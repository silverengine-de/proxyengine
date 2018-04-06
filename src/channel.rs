use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{ATOMIC_U64_INIT, AtomicU64, Ordering};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PipelineId {
    pub core: u16,
    pub port_id: u16,
    pub rxq: u16,
}

impl fmt::Display for PipelineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<c{}, p{}, rx{}>", self.core, self.port_id, self.rxq)
    }
}

pub enum MessageFrom {
    Statistics(PipelineId, Arc<ConnectionStatistics>),
    Channel(PipelineId, Sender<MessageTo>),
    Exit, // exit recv thread
}

pub enum MessageTo {
    Hello,
    Exit, // exit recv thread
}

#[derive(Debug)]
pub struct ConnectionStatistics {
    seized: AtomicU64,
    released: AtomicU64,
}

impl ConnectionStatistics {
    pub fn new() -> ConnectionStatistics {
        ConnectionStatistics {
            seized: ATOMIC_U64_INIT,
            released: ATOMIC_U64_INIT,
        }
    }

    pub fn get(&self) -> (u64, u64) {
        (self.seized.load(Ordering::Relaxed), self.released.load(Ordering::Relaxed))
    }

    #[inline]
    pub fn c_seized(&self) -> u64 {
        self.seized.fetch_add(1u64, Ordering::Relaxed)
    }
    pub fn c_released(&self) -> u64 {
        self.released.fetch_add(1u64, Ordering::Relaxed)
    }
}

impl fmt::Display for ConnectionStatistics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<seizures= {}, releases= {}>", self.get().0, self.get().1 )
    }
}


pub struct ProxyStatistics {
    full: u64,
    requests: u64,
    rxq: u16,
}

impl ProxyStatistics {
    fn new(rxq: u16) -> ProxyStatistics {
        ProxyStatistics { full: 0, requests: 0, rxq }
    }

    #[inline]
    fn full_connect(&mut self) {
        self.full += 1
    }
}

pub fn spawn_recv_thread(pipeline_id: PipelineId, c_statistics: Arc<ConnectionStatistics>, tx: Sender<MessageFrom>) {
    let handle = thread::spawn(move || {
        debug!("setting up reverse channel from pipeline {}", pipeline_id);
        let (remote_tx, rx) = channel::<MessageTo>();
        tx.send(MessageFrom::Channel(pipeline_id.clone(), remote_tx)).unwrap();
        loop {
            match rx.recv() {
                Ok(MessageTo::Hello) => {
                    debug!("{}: got a Hello", pipeline_id);
                    tx.send(MessageFrom::Statistics(pipeline_id.clone(), c_statistics.clone())).unwrap();
                }
                Ok(MessageTo::Exit) => {
                    debug!("{}: exiting recv thread", pipeline_id);
                    break;
                }
                Err(e) => {
                    error!("{}: error receiving from message channel: {}", pipeline_id, e);
                    break;
                }
                _ => warn!("illegal message"),
            }
        }
    });
}
