use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{ATOMIC_U64_INIT, AtomicU64, Ordering};
use cmanager::ConRecord;
use cmanager::ReleaseCause;

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
    CRecord(PipelineId, ConRecord),
    Exit, // exit recv thread
}

pub enum MessageTo {
    Hello,
    Exit, // exit recv thread
}

#[derive(Debug)]
pub struct ConnectionStatistics {
    seized: AtomicU64,
    released: Vec<AtomicU64>,
}

impl ConnectionStatistics {
    pub fn new() -> ConnectionStatistics {
        let mut c = ConnectionStatistics {
            seized: ATOMIC_U64_INIT,
            released: Vec::with_capacity(ReleaseCause::MaxCauses as usize),
        };
        for cause in 0..ReleaseCause::MaxCauses as usize {
            c.released.push(ATOMIC_U64_INIT);
            c.released[cause].store(0u64, Ordering::Relaxed);
        }
        c
    }

    pub fn get_seized(&self) -> u64 {
        self.seized.load(Ordering::Relaxed)
    }

    pub fn get_released(&self, release_cause: ReleaseCause) -> u64 {
        self.released[release_cause as usize].load(Ordering::Relaxed)
    }

    #[inline]
    pub fn c_seized(&self) -> u64 {
        self.seized.fetch_add(1u64, Ordering::Relaxed)
    }
    pub fn c_released(&self, release_cause: ReleaseCause) -> u64 {
        self.released[release_cause as usize].fetch_add(1u64, Ordering::Relaxed)
    }
}

impl fmt::Display for ConnectionStatistics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<seizures= {}, timeouts= {}, FIN by client= {}, FIN by server= {}>",
            self.get_seized(),
            self.get_released(ReleaseCause::Timeout),
            self.get_released(ReleaseCause::FinClient),
            self.get_released(ReleaseCause::FinServer),
        )
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
            }
        }
    });
}
