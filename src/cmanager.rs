use std::time::{Duration, Instant};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::hash::BuildHasherDefault;
use std::fmt;

use e2d2::headers::MacHeader;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue};

use eui48::MacAddress;
use channel::{ConnectionStatistics, MessageFrom, PipelineId};
use timer_wheel::TimerWheel;

use fnv::FnvHasher;

type FnvHash = BuildHasherDefault<FnvHasher>;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum TcpState {
    Listen,
    SynReceived,
    SynSent,
    Established,
    CloseWait,
    FinWait,
    LastAck,
    Closed,
}

#[derive(Debug, Clone, Copy)]
pub struct L234Data {
    pub mac: MacAddress,
    pub ip: u32,
    pub port: u16,
}

pub trait UserData: Send + Sync + 'static {
    fn ref_userdata(&self) -> &Any;
    fn mut_userdata(&mut self) -> &mut Any;
    fn init(&mut self);
}

#[derive(Debug, Clone, Copy, Eq, Hash)]
pub enum CKey {
    Port(u16),
    Socket(SocketAddrV4),
}

impl PartialEq for CKey {
    fn eq(&self, other: &CKey) -> bool {
        match *other {
            CKey::Port(p) => {
                if let CKey::Port(x) = *self {
                    p == x
                } else {
                    false
                }
            }
            CKey::Socket(s) => {
                if let CKey::Socket(x) = *self {
                    s == x
                } else {
                    false
                }
            }
        }
    }
}

struct Timeouts {
    established: Duration,    // max. time from SYN to server connection established
}

impl Timeouts {
    fn new() -> Timeouts {
        Timeouts {
            established: Duration::from_millis(200),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ReleaseCause {
    Unknown = 0,
    Timeout = 1,
    FinClient = 2,
    FinServer = 3,
    MaxCauses = 4,
}

#[derive(Clone, Copy)]
pub struct ConRecord {
    /// timestamp of SYN
    pub con_syn_recv: Instant,
    /// holding time
    pub con_hold: Duration,
    release_cause: ReleaseCause,
}

impl ConRecord {
    fn init(&mut self) {
        self.con_syn_recv = Instant::now();
    }
    #[inline]
    fn c_released(&mut self, cause: ReleaseCause) {
        self.con_hold = self.con_syn_recv.elapsed();
        self.release_cause = cause;
    }
    #[inline]
    pub fn get_release_cause(&self) -> ReleaseCause {
        self.release_cause
    }
}

impl Default for ConRecord {
    fn default() -> ConRecord {
        ConRecord {
            con_syn_recv: Instant::now(),
            con_hold: Duration::default(),
            release_cause: ReleaseCause::Unknown,
        }
    }
}

pub struct Connection {
    pub payload: Box<Vec<u8>>,
    pub client_sock: SocketAddrV4,
    pub server: Option<L234Data>,
    pub userdata: Option<Box<UserData>>,
    //Box makes the trait object sizeable
    pub client_mac: MacHeader,
    con_record: ConRecord,
    pub proxy_sport: u16,
    pub c_state: TcpState,
    pub s_state: TcpState,
    /// c_seqn is seqn for connection to client,
    /// after the SYN-ACK from the target server it is the delta to be added to server seqn
    /// see 'server_synack_received'
    pub c_seqn: u32,
    /// number of bytes inserted by proxy in connection from client to server
    pub c2s_inserted_bytes: usize,
    pub f_seqn: u32, // seqn for connection from client
}

impl Connection {
    fn initialize(&mut self, client_sock: SocketAddrV4, proxy_sport: u16) {
        self.payload.clear();
        self.proxy_sport = proxy_sport;
        self.client_sock = client_sock;
        self.server = None;
        self.userdata = None;
        self.client_mac = MacHeader::default();
        self.c_state = TcpState::Listen;
        self.s_state = TcpState::Closed;
        self.c_seqn = 0;
        self.f_seqn = 0;
        self.c2s_inserted_bytes = 0;
        self.con_record.init();
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Connection(s-port={}, {:?}/{:?})", self.proxy_sport, self.c_state, self.s_state)
    }
}

impl Default for Connection {
    fn default() -> Connection {
        Connection {
            payload: Box::new(Vec::with_capacity(1500)),
            client_sock: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0),
            server: None,
            userdata: None,
            client_mac: MacHeader::default(),
            proxy_sport: 0u16,
            c_state: TcpState::Listen,
            s_state: TcpState::Closed,
            c_seqn: 0,
            c2s_inserted_bytes: 0,
            f_seqn: 0,
            con_record: ConRecord::default(),
        }
    }
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

pub struct ConnectionManager {
    sock2port: HashMap<SocketAddrV4, u16, FnvHash>,
    free_ports: VecDeque<u16>,
    port2con: HashMap<u16, Connection, FnvHash>,
    timeouts: Timeouts,
    pci: CacheAligned<PortQueue>, // the PortQueue for which connections are managed
    pipeline_id: PipelineId,
    c_statistics: Arc<ConnectionStatistics>,
    tcp_port_base: u16,
    tx: Sender<MessageFrom>,
}

fn get_tcp_port_base_by_manager_count(pci: &CacheAligned<PortQueue>, count: u16) -> u16 {
    let port_mask = pci.port.get_tcp_dst_port_mask();
    debug!("port_mask= {}", port_mask);
    port_mask - count * (!port_mask + 1)
}

impl ConnectionManager {
    pub fn new(pipeline_id: PipelineId, pci: CacheAligned<PortQueue>, proxy_data: L234Data, tx: Sender<MessageFrom>) -> ConnectionManager {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let tcp_port_base: u16 = get_tcp_port_base_by_manager_count(&pci, old_manager_count);
        let max_tcp_port: u16 = tcp_port_base + !port_mask;
        // program the NIC to send all flows for our owned ports to our rx queue
        pci.port.add_fdir_filter(pci.rxq() as u16, proxy_data.ip, tcp_port_base).unwrap();
        let mut cm = ConnectionManager {
            sock2port: HashMap::<SocketAddrV4, u16, FnvHash>::with_hasher(Default::default()),
            port2con: HashMap::<u16, Connection, FnvHash>::with_hasher(Default::default()),
            free_ports: (tcp_port_base..max_tcp_port).collect(),
            timeouts: Timeouts::new(),
            pci,
            pipeline_id,
            c_statistics: Arc::new(ConnectionStatistics::new()),
            tcp_port_base,
            tx,
        };
        // need to add last port this way to avoid overflow with slice, when max_tcp_port == 65535
        cm.free_ports.push_back(max_tcp_port);
        //        cm.spawn_maintenance_thread();
        debug!(
            "created ConnectionManager {} for port {}, rxq {} and tcp ports {} - {}",
            old_manager_count,
            PacketRx::port_id(&cm.pci),
            cm.pci.rxq(),
            cm.free_ports.front().unwrap(),
            cm.free_ports.back().unwrap(),
        );
        cm
    }

    pub fn get_statistics(&self) -> Arc<ConnectionStatistics> {
        self.c_statistics.clone()
    }

    fn owns_tcp_port(&self, tcp_port: u16) -> bool {
        tcp_port & self.pci.port.get_tcp_dst_port_mask() == self.tcp_port_base
    }

    #[inline]
    pub fn tcp_port_base(&self) -> u16 {
        self.tcp_port_base
    }
    //fn tcp_port_mask(&self) -> u16 { self.tcp_port_mask }

    /*fn get(&self, key: &CKey) -> Option<&Connection> {
        match *key {
            CKey::Port(p) => {
                if self.owns_tcp_port(p) {
                    self.port2con.get(&p)
                } else {
                    None
                }
            }
            CKey::Socket(s) => {
                let port = self.sock2port.get(&s);
                if port.is_some() {
                    self.port2con.get(&port.unwrap())
                } else {
                    None
                }
            }
        }
    }
    */

    pub fn get_mut(&mut self, key: CKey) -> Option<&mut Connection> {
        match key {
            CKey::Port(p) => {
                if self.owns_tcp_port(p) {
                    if let Some(c) = self.port2con.get_mut(&p) {
                        // check if c has a port != 0 assigned
                        // otherwise it is released, as we keep released connections
                        // and just mark them as unused by assigning port 0
                        if c.proxy_sport != 0 {
                            Some(c)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            CKey::Socket(s) => {
                let port = self.sock2port.get(&s);
                if port.is_some() {
                    self.port2con.get_mut(&port.unwrap())
                } else {
                    None
                }
            }
        }
    }

    fn get_timeouts(&mut self, now: &Instant, wheel: &mut TimerWheel<u16>) -> Vec<u16> {
        let mut con_timeouts: Vec<u16> = Vec::new();
        let resolution=wheel.get_resolution();
        loop {
            match wheel.tick(now) {
                (Some(mut drain), more) => {
                    let mut port = drain.next();
                    while port.is_some() {
                        //self.check_timeout(&port.unwrap());
                        let p = port.unwrap();
                        let timeout = self.timeouts.established;
                        let c = self.port2con.get_mut(&p);
                        if c.is_some() {
                            let c = c.unwrap();
                            if *now - c.con_record.con_syn_recv >= timeout - resolution && c.s_state < TcpState::Established {
                                c.con_record.c_released(ReleaseCause::Timeout);
                                con_timeouts.push(p);
                            } else {
                                warn!(
                                    "incomplete timeout: s_state = {:?}, syn_received = {:?}, now ={:?}",
                                    c.s_state, c.con_record.con_syn_recv, now
                                );
                            }
                        }
                        port = drain.next();
                    }
                    if !more {
                        break;
                    }
                }
                (None, more) => if !more {
                    break;
                },
            }
        }
        con_timeouts
    }

    pub fn get_mut_or_insert(&mut self, key: CKey, wheel: &mut TimerWheel<u16>) -> Option<&mut Connection> {
        match key {
            CKey::Port(p) => {
                if self.owns_tcp_port(p) {
                    self.port2con.get_mut(&p)
                } else {
                    None
                }
            }
            CKey::Socket(s) => {
                {
                    // we borrow sock2port here !
                    let port = self.sock2port.get(&s);
                    if port.is_some() {
                        return self.port2con.get_mut(&port.unwrap());
                    }
                }
                // now we are free to borrow sock2port mutably
                let opt_port = self.free_ports.pop_front();
                if opt_port.is_some() {
                    let port = opt_port.unwrap();
                    let mut c = None;
                    // reuse a released connection ?
                    match self.port2con.get_mut(&port) {
                        Some(c) => {
                            assert_eq!(c.proxy_sport, 0);
                            c.initialize(s, port);
                            self.sock2port.insert(c.client_sock, port);
                        }
                        _ => {
                            // we never used this port before
                            let mut cc = Connection::default();
                            cc.client_sock = s;
                            c = Some(cc);
                        }
                    };
                    if c.is_some() {
                        let mut c = c.unwrap();
                        c.initialize(s, port);
                        let port_vec = self.get_timeouts(&c.con_record.con_syn_recv, wheel);
                        self.release_ports(port_vec);
                        wheel.schedule(&(c.con_record.con_syn_recv + self.timeouts.established), port);
                        self.sock2port.insert(c.client_sock, port);
                        self.port2con.insert(port, c);
                        debug!("tcp flow for {} created on port {:?}", s, port);
                        self.c_statistics.c_seized();
                    }
                    self.port2con.get_mut(&port)
                } else {
                    None
                }
            }
        }
    }

    pub fn release_port(&mut self, proxy_port: u16) -> Option<&mut Connection> {
        match self.port2con.get_mut(&proxy_port) {
            Some(c) => {
                // only if it is in use, i.e. it has been not released already
                if c.proxy_sport != 0 {
                    self.free_ports.push_back(proxy_port);
                    assert_eq!(proxy_port, c.proxy_sport);
                    let port = self.sock2port.remove(&c.client_sock);
                    assert_eq!(port.unwrap(), c.proxy_sport);
                    c.proxy_sport = 0u16; // this indicates an unused connection,
                                          // we keep unused connection in port2con table
                    Some(c)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn release_port_with_cause(&mut self, proxy_port: u16, release_cause: ReleaseCause) -> bool {
        let con_record;
        match self.release_port(proxy_port) {
            Some(ref mut c) => {
                c.con_record.c_released(release_cause);
                con_record = c.con_record.clone();
            }
            _ => {
                return false;
            }
        }
        self.c_statistics.c_released(release_cause);
        self.tx.send(MessageFrom::CRecord(self.pipeline_id.clone(), con_record)).unwrap();
        return true;
    }

    pub fn release_ports(&mut self, ports: Vec<u16>) {
        ports.iter().for_each(|p| {
            let con_record;
            match self.release_port(*p) {
                Some(ref mut c) => {
                    con_record = Some(c.con_record.clone());
                }
                _ => con_record = None,
            }
            if con_record.is_some() {
                let con_record = con_record.unwrap();
                self.tx.send(MessageFrom::CRecord(self.pipeline_id.clone(), con_record)).unwrap();
                self.c_statistics.c_released(con_record.get_release_cause());
            }
        });
    }
}
