use std::net::{Ipv4Addr, SocketAddrV4};
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::hash::BuildHasherDefault;
use std::fmt;

use e2d2::headers::MacHeader;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow};
use e2d2::utils;

use eui48::MacAddress;
use {MessageFrom, PipelineId};
use timer_wheel::{TimerWheel, MILLIS_TO_CYCLES};
use {Configuration, Timeouts, FlowSteeringMode};

use fnv::FnvHasher;

type FnvHash = BuildHasherDefault<FnvHasher>;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum TcpState {
    Listen,
    SynReceived,
    SynSent,
    Established,
    CloseWait,
    FinWait1,
    FinWait2,
    LastAck,
    Closed,
}

#[derive(Debug, Clone)]
pub struct L234Data {
    pub mac: MacAddress,
    pub ip: u32,
    pub port: u16,
    pub server_id: String,
    pub index: usize,   // index of this struct in a Vec
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReleaseCause {
    Unknown = 0,
    Timeout = 1,
    FinClient = 2,
    FinServer = 3,
    MaxCauses = 4,
}

#[derive(Clone)]
pub struct ConRecord {
    pub p_port: u16,
    pub client_sock: SocketAddrV4,
    /// timestamp of SYN
    pub c_syn_recv: u64,
    /// timestamp of client Ack in 3way handshake
    pub c_ack_recv: u64,
    /// timestamp of SYN towards server in 3way handshake
    pub s_syn_sent: u64,
    /// timestamp of Ack towards server in 3way handshake
    pub s_ack_sent: u64,
    /// holding time
    pub con_hold: u64,
    pub c_state: Vec<TcpState>,
    pub s_state: Vec<TcpState>,
    pub server_index: usize,
    release_cause: ReleaseCause,
}

impl ConRecord {
    fn init(&mut self, proxy_sport: u16, client_sock: SocketAddrV4) {
        self.c_syn_recv = utils::rdtsc_unsafe();
        self.c_ack_recv = self.c_syn_recv;
        self.s_syn_sent = self.c_syn_recv;
        self.s_ack_sent = self.c_syn_recv;
        self.p_port = proxy_sport;
        self.client_sock = client_sock;
        self.c_state.clear();
        self.c_state.push(TcpState::Closed);
        self.s_state.clear();
        self.s_state.push(TcpState::Listen); // server starts with Listen
        self.server_index =0;
    }
    #[inline]
    pub fn released(&mut self, cause: ReleaseCause) {
        self.con_hold = utils::rdtsc_unsafe() - self.c_syn_recv;
        self.release_cause = cause;
    }
    #[inline]
    pub fn get_release_cause(&self) -> ReleaseCause {
        self.release_cause
    }

    fn new() -> ConRecord {
        ConRecord {
            client_sock: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0),
            c_syn_recv: utils::rdtsc_unsafe(),
            c_ack_recv: utils::rdtsc_unsafe(),
            s_syn_sent: utils::rdtsc_unsafe(),
            s_ack_sent: utils::rdtsc_unsafe(),
            con_hold: 0u64,
            c_state: Vec::with_capacity(8),
            s_state: Vec::with_capacity(8),
            server_index: 0,
            release_cause: ReleaseCause::Unknown,
            p_port: 0u16,
        }
    }
}

pub struct Connection {
    pub payload: Box<Vec<u8>>,
    pub server: Option<L234Data>,
    pub userdata: Option<Box<UserData>>,
    //Box makes the trait object sizeable
    pub client_mac: MacHeader,
    pub con_rec: ConRecord,
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
        self.server = None;
        self.userdata = None;
        self.client_mac = MacHeader::default();
        self.c_seqn = 0;
        self.f_seqn = 0;
        self.c2s_inserted_bytes = 0;
        self.con_rec.init(proxy_sport, client_sock);
    }

    fn new() -> Connection {
        Connection {
            payload: Box::new(Vec::with_capacity(1500)),
            server: None,
            userdata: None,
            client_mac: MacHeader::default(),
            c_seqn: 0,
            c2s_inserted_bytes: 0,
            f_seqn: 0,
            con_rec: ConRecord::new(),
        }
    }

    #[inline]
    pub fn client_con_established(&mut self) {
        self.con_rec.c_state.push(TcpState::Established);
        self.con_rec.c_ack_recv = utils::rdtsc_unsafe();
    }

    #[inline]
    pub fn server_syn_sent(&mut self) {
        self.con_rec.s_state.push(TcpState::SynReceived);
        self.con_rec.s_syn_sent = utils::rdtsc_unsafe();
    }

    #[inline]
    pub fn server_con_established(&mut self) {
        self.con_rec.s_state.push(TcpState::Established);
        self.con_rec.s_ack_sent = utils::rdtsc_unsafe();
    }

    #[inline]
    pub fn p_port(&self) -> u16 {
        self.con_rec.p_port
    }

    #[inline]
    pub fn set_p_port(&mut self, port: u16) {
        self.con_rec.p_port = port;
    }

    #[inline]
    pub fn get_client_sock(&self) -> &SocketAddrV4 {
        &self.con_rec.client_sock
    }

    #[inline]
    pub fn set_client_sock(&mut self, client_sock: SocketAddrV4) {
        self.con_rec.client_sock = client_sock;
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(s-port={}, {:?}/{:?})",
            self.p_port(),
            self.con_rec.c_state,
            self.con_rec.s_state
        )
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Connection::new()
    }
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

pub struct ConnectionManager {
    sock2port: HashMap<SocketAddrV4, u16, FnvHash>,
    free_ports: VecDeque<u16>,
    port2con: Vec<Connection>,
    timeouts: Timeouts,
    pci: CacheAligned<PortQueue>, // the PortQueue for which connections are managed
    pipeline_id: PipelineId,
    tx: Sender<MessageFrom>,
    tcp_port_base: u16,
    ip: u32,    // ip address to use for connections of this manager
}


impl ConnectionManager {
    pub fn new(
        pipeline_id: PipelineId,
        pci: CacheAligned<PortQueue>,
        proxy_data: L234Data,
        proxy_config: Configuration,
        l4flow: &L4Flow,
        tx: Sender<MessageFrom>,
    ) -> ConnectionManager {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base)=(l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port = tcp_port_base + !port_mask;
        let mut cm = ConnectionManager {
            sock2port: HashMap::<SocketAddrV4, u16, FnvHash>::with_hasher(Default::default()),
            port2con: vec![Connection::new(); (!port_mask + 1) as usize],
            free_ports: (tcp_port_base..max_tcp_port).collect(),
            timeouts: Timeouts::default_or_some(&proxy_config.engine.timeouts),
            pci,
            pipeline_id,
            tx,
            tcp_port_base,
            ip,
        };
        // need to add last port this way to avoid overflow with slice, when max_tcp_port == 65535
        cm.free_ports.push_back(max_tcp_port);
        //        cm.spawn_maintenance_thread();
        debug!(
            "created ConnectionManager {} for port {}, rxq {}, ip= {}, tcp ports {} - {}",
            old_manager_count,
            PacketRx::port_id(&cm.pci),
            cm.pci.rxq(),
            Ipv4Addr::from(ip),
            cm.free_ports.front().unwrap(),
            cm.free_ports.back().unwrap(),
        );
        cm
    }

    #[inline]
    fn get_mut_con(&mut self, p: &u16) -> &mut Connection {
        &mut self.port2con[(p - self.tcp_port_base) as usize]
    }

    fn owns_tcp_port(&self, tcp_port: u16) -> bool {
        tcp_port & self.pci.port.get_tcp_dst_port_mask() == self.tcp_port_base
    }

    #[inline]
    pub fn tcp_port_base(&self) -> u16 {
        self.tcp_port_base
    }

    #[inline]
    pub fn ip(&self) -> u32 {
        self.ip
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
                    let c = self.get_mut_con(&p);
                    // check if c has a port != 0 assigned
                    // otherwise it is released, as we keep released connections
                    // and just mark them as unused by assigning port 0
                    if c.p_port() != 0 {
                        Some(c)
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
                    Some(&mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize])
                } else {
                    None
                }
            }
        }
    }

    fn get_timeouts(&mut self, now: &u64, wheel: &mut TimerWheel<u16>) -> Vec<u16> {
        let mut con_timeouts: Vec<u16> = Vec::new();
        let resolution = wheel.get_resolution();
        loop {
            match wheel.tick(now) {
                (Some(mut drain), more) => {
                    let mut port = drain.next();
                    while port.is_some() {
                        let p = port.unwrap();
                        // TODO convert ms to cycles more precisely
                        let timeout = self.timeouts.established.unwrap_or(200)*MILLIS_TO_CYCLES;
                        let c = self.get_mut_con(&p);
                        if *now - c.con_rec.c_syn_recv >= timeout - resolution {
                            if c.con_rec.s_state.last().unwrap() < &TcpState::Established {
                                c.con_rec.released(ReleaseCause::Timeout);
                                con_timeouts.push(p);
                            }
                        } else {
                            warn!(
                                "incomplete timeout: s_state = {:?}, syn_received = {:?}, now ={:?}",
                                c.con_rec.s_state, c.con_rec.c_syn_recv, now,
                            );
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
                    Some(&mut self.port2con[(p - self.tcp_port_base) as usize])
                } else {
                    None
                }
            }
            CKey::Socket(s) => {
                {
                    // we borrow sock2port here !
                    let port = self.sock2port.get(&s);
                    if port.is_some() {
                        return Some(&mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize]);
                    }
                }
                // now we are free to borrow sock2port mutably
                let opt_port = self.free_ports.pop_front();
                if opt_port.is_some() {
                    let port = opt_port.unwrap();
                    let now;
                    {
                        let cc = &mut self.port2con[(port - self.tcp_port_base) as usize];
                        assert_eq!(cc.p_port(), 0);
                        cc.initialize(s, port);
                        now = cc.con_rec.c_syn_recv;
                        debug!("tcp flow for {} created on {}:{:?}", s, Ipv4Addr::from(self.ip), port);
                    }
                    let port_vec = self.get_timeouts(&now, wheel);
                    if self.timeouts.established.unwrap() < wheel.get_max_timeout_cycles() {
                        wheel.schedule(&(now + self.timeouts.established.unwrap()*MILLIS_TO_CYCLES), port);
                    }
                    self.release_ports(port_vec);
                    self.sock2port.insert(s, port);
                    Some(self.get_mut_con(&port))
                } else {
                    warn!("out of ports");
                    None
                }
            }
        }
    }

    pub fn release_port(&mut self, proxy_port: u16) -> Option<ConRecord> {
        let c = &mut self.port2con[(proxy_port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.p_port() != 0 {
            let con_rec = c.con_rec.clone();
            self.free_ports.push_back(proxy_port);
            assert_eq!(proxy_port, c.p_port());
            let port = self.sock2port.remove(&c.get_client_sock());
            assert_eq!(port.unwrap(), c.p_port());
            c.set_p_port(0u16); // this indicates an unused connection,
                                // we keep unused connection in port2con table
            Some(con_rec)
        } else {
            None
        }
    }

    pub fn release_ports(&mut self, ports: Vec<u16>) {
        ports.iter().for_each(|p| {
            let con_record = self.release_port(*p);
            if con_record.is_some() {
                let con_record = con_record.unwrap();
                self.tx
                    .send(MessageFrom::CRecord(self.pipeline_id.clone(), con_record.clone()))
                    .unwrap();
            }
        })
    }
}

/*

impl Drop for ConnectionManager {
    fn drop(&mut self) { self.send_all_c_records(); }
}
*/
