use std::net::{Ipv4Addr, SocketAddrV4};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::hash::BuildHasherDefault;
use std::fmt;
use std::mem;

use e2d2::headers::MacHeader;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow};

use uuid::Uuid;
use netfcts::timer_wheel::{TimerWheel};
use netfcts::tcp_common::*;
use netfcts::ConRecord;


use fnv::FnvHasher;

type FnvHash = BuildHasherDefault<FnvHasher>;


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

pub struct Connection {
    pub payload: Box<Vec<u8>>,
    pub server: Option<L234Data>,
    pub userdata: Option<Box<UserData>>,
    //Box makes the trait object sizeable
    pub client_mac: MacHeader,
    pub con_rec_c: ConRecord,
    pub con_rec_s: ConRecord,
    /// c_seqn is seqn for connection to client,
    /// after the SYN-ACK from the target server it is the delta to be added to server seqn
    /// see 'server_synack_received'
    pub c_seqn: u32,
    /// number of bytes inserted by proxy in connection from client to server
    pub c2s_inserted_bytes: usize,
    pub f_seqn: u32, // seqn for connection from client
}

impl Connection {
    fn initialize(&mut self, client_sock: &SocketAddrV4, proxy_sport: u16) {
        self.payload.clear();
        self.server = None;
        self.userdata = None;
        self.client_mac = MacHeader::default();
        self.c_seqn = 0;
        self.f_seqn = 0;
        self.c2s_inserted_bytes = 0;
        self.con_rec_c.init(TcpRole::Client, proxy_sport, Some(client_sock));
        self.con_rec_s.init(TcpRole::Server, proxy_sport, Some(client_sock));
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
            con_rec_c: ConRecord::new(),
            con_rec_s: ConRecord::new(),
        }
    }

    #[inline]
    pub fn client_con_established(&mut self) {
        self.con_rec_c.push_state(TcpState::Established);
    }

    #[inline]
    pub fn server_syn_sent(&mut self) {
        self.con_rec_s.push_state(TcpState::SynReceived);
    }

    #[inline]
    pub fn server_con_established(&mut self) {
        self.con_rec_s.push_state(TcpState::Established);
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.con_rec_c.port
    }

    #[inline]
    pub fn in_use(&self) -> bool {
        self.con_rec_c.port != 0
    }

    #[inline]
    pub fn set_port(&mut self, port: u16) {
        self.con_rec_c.port = port;
    }

    #[inline]
    pub fn get_client_sock(&self) -> &Option<SocketAddrV4> {
        &self.con_rec_c.sock
    }

    #[inline]
    pub fn set_client_sock(&mut self, client_sock: SocketAddrV4) {
        self.con_rec_c.sock = Some(client_sock);
    }

    #[inline]
    pub fn set_uuid(&mut self, uuid: Option<Uuid>)-> Option<Uuid> { mem::replace(&mut self.con_rec_c.uuid, uuid) }

    #[inline]
    pub fn get_uuid(&self)-> &Option<Uuid> { &self.con_rec_c.uuid }

    #[inline]
    pub fn make_uuid(&mut self) -> &Uuid {
        self.con_rec_c.uuid = Some(Uuid::new_v4());
        self.con_rec_s.uuid = self.con_rec_c.uuid.clone();
        self.con_rec_c.uuid.as_ref().unwrap()
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(port={}, {:?}/{:?})",
            self.port(),
            self.con_rec_c.states(),
            self.con_rec_s.states()
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
    con_records_c: HashMap<Uuid, ConRecord>,
    con_records_s: HashMap<Uuid, ConRecord>,
    sock2port: HashMap<SocketAddrV4, u16, FnvHash>,
    free_ports: VecDeque<u16>,
    port2con: Vec<Connection>,
    pci: CacheAligned<PortQueue>, // the PortQueue for which connections are managed
    tcp_port_base: u16,
    ip: u32,    // ip address to use for connections of this manager
}

const MAX_CONNECTIONS:usize = 0xFFFF as usize;

impl ConnectionManager {
    pub fn new(
        pci: CacheAligned<PortQueue>,
        l4flow: &L4Flow,
    ) -> ConnectionManager {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base)=(l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port = tcp_port_base + !port_mask;
        let mut cm = ConnectionManager {
            con_records_c: HashMap::with_capacity(MAX_CONNECTIONS),
            con_records_s: HashMap::with_capacity(MAX_CONNECTIONS),
            sock2port: HashMap::<SocketAddrV4, u16, FnvHash>::with_hasher(Default::default()),
            port2con: vec![Connection::new(); (!port_mask + 1) as usize],
            free_ports: (tcp_port_base..max_tcp_port).collect(),
            pci,
            tcp_port_base,
            ip,
        };
        // need to add last port this way to avoid overflow with slice, when max_tcp_port == 65535
        cm.free_ports.push_back(max_tcp_port);
        //        cm.spawn_maintenance_thread();
        info!(
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

    pub fn get_mut(&mut self, key: CKey) -> Option<&mut Connection> {
        match key {
            CKey::Port(p) => {
                if self.owns_tcp_port(p) {
                    let c = self.get_mut_con(&p);
                    // check if c has a port != 0 assigned
                    // otherwise it is released, as we keep released connections
                    // and just mark them as unused by assigning port 0
                    if c.port() != 0 {
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


    pub fn get_mut_or_insert(&mut self, key: CKey) -> Option<&mut Connection> {
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
                    {
                        let cc = &mut self.port2con[(port - self.tcp_port_base) as usize];
                        assert_eq!(cc.port(), 0);
                        cc.initialize(&s, port);
                        debug!("rxq={}: tcp flow for {} created on {}:{:?}", self.pci.rxq(), s, Ipv4Addr::from(self.ip), port);
                    }
                    self.sock2port.insert(s, port);
                    Some(self.get_mut_con(&port))
                } else {
                    warn!("out of ports");
                    None
                }
            }
        }
    }

    pub fn release_port(&mut self, port: u16) {
        let c = &mut self.port2con[(port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.in_use() {
            self.con_records_c.insert(c.get_uuid().unwrap(), c.con_rec_c.clone());
            self.con_records_s.insert(c.get_uuid().unwrap(), c.con_rec_s.clone());
            self.free_ports.push_back(port);
            assert_eq!(port, c.port());
            {
                let sock = c.get_client_sock();
                if sock.is_some() {
                    let port = self.sock2port.remove(&sock.unwrap());
                    assert_eq!(port.unwrap(), c.port());
                }
            }
            c.set_port(0u16); // this indicates an unused connection,
                                // we keep unused connection in port2con table
        }
    }

    //TODO allow for more precise time out conditions, currently whole TCP connections are timed out, also we should send a RST
    pub fn release_timeouts(&mut self, now: &u64, wheel: &mut TimerWheel<u16>) {
        loop {
            match wheel.tick(now) {
                (Some(mut drain), more) => {
                    let mut port = drain.next();
                    while port.is_some() {
                        self.timeout(port.unwrap());
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
    }

    #[inline]
    fn timeout(&mut self, port: u16) {
        debug!("timing out port {}", port);
        {
            let mut c = self.get_mut(CKey::Port(port));
            if c.is_some() {
                c.as_mut().unwrap().con_rec_c.released(ReleaseCause::Timeout);
                c.unwrap().con_rec_c.push_state(TcpState::Closed);
            }
        }
        self.release_port(port);
    }


    // pushes all uncompleted connections to the connection record store
    pub fn record_uncompleted(&mut self) {
        let c_records = &mut self.con_records_c;
        self.port2con.iter().for_each(|c| {
            if c.port() != 0 {
                c_records.insert(c.get_uuid().unwrap(), c.con_rec_c.clone());
            }
        });
    }

    pub fn fetch_c_records(&mut self) -> (HashMap<Uuid, ConRecord>, HashMap<Uuid, ConRecord>) {
        (mem::replace(&mut self.con_records_c, HashMap::with_capacity(MAX_CONNECTIONS)), // we are "moving" the con_records out, and replace it with a new one
         mem::replace(&mut self.con_records_s, HashMap::with_capacity(MAX_CONNECTIONS)))
    }

    #[allow(dead_code)]
    pub fn release_ports(&mut self, ports: Vec<u16>) {
        ports.iter().for_each(|p| {
            self.release_port(*p);
        })
    }
}

/*

impl Drop for ConnectionManager {
    fn drop(&mut self) { self.send_all_c_records(); }
}
*/
