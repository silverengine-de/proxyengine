use std::net::{Ipv4Addr, SocketAddrV4};
use std::collections::{VecDeque, BTreeMap};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::fmt;
use std::mem;

use e2d2::headers::{MacHeader, TcpHeader};
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow, Packet};
use e2d2::common::EmptyMetadata;

use uuid::Uuid;
use netfcts::timer_wheel::TimerWheel;
use netfcts::tcp_common::*;
use netfcts::ConRecord;

pub struct Connection{
    //pub payload: Vec<u8>,
    pub payload_packet: Option<Packet<TcpHeader, EmptyMetadata>>,
    //Box makes the trait object sizeable
    ///can be used by applications to store application specific connection state
    pub userdata: Option<Box<UserData>>,
    pub client_mac: MacHeader,
    pub con_rec_c: ConRecord,
    pub con_rec_s: ConRecord,
    /// seqn for connection to client,
    /// after the SYN-ACK from the target server it is the delta to be added to server seqn
    /// see 'server_synack_received'
    pub c_seqn: u32,
    /// current ack no towards server (=expected seqn)
    pub ackn_p2s: u32,
    /// current ack no towards client (=expected seqn)
    pub ackn_p2c: u32,
    /// seqn_nxt for connection from client to server, only used during connection setup
    pub f_seqn: u32,
    /// number of bytes inserted by proxy in connection from client to server
    pub c2s_inserted_bytes: isize,
    /// latest seqn of FIN seen for proxy to client
    pub seqn_fin_p2c: u32,
    /// latest seqn of FIN seen for proxy to server
    pub seqn_fin_p2s: u32,

}

impl  Connection {
    fn initialize(&mut self, client_sock: &SocketAddrV4, proxy_sport: u16) {
        //self.payload.clear();
        self.userdata = None;
        self.client_mac = MacHeader::default();
        self.c_seqn = 0;
        self.f_seqn = 0;
        self.ackn_p2s = 0;
        self.ackn_p2c = 0;
        self.c2s_inserted_bytes = 0;
        self.seqn_fin_p2c = 0;
        self.seqn_fin_p2s = 0;
        self.con_rec_c.init(TcpRole::Client, proxy_sport, Some(client_sock));
        self.con_rec_s.init(TcpRole::Server, proxy_sport, Some(client_sock));
        self.con_rec_s.uuid = self.con_rec_c.uuid.clone();
    }

    fn new() -> Connection {
        Connection {
            //payload: Vec::with_capacity(1500),
            payload_packet: None,
            userdata: None,
            client_mac: MacHeader::default(),
            c_seqn: 0,
            ackn_p2s: 0,
            ackn_p2c: 0,
            c2s_inserted_bytes: 0,
            f_seqn: 0,
            seqn_fin_p2c: 0,
            seqn_fin_p2s: 0,
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
    pub fn set_uuid(&mut self, uuid: Option<Uuid>) -> Option<Uuid> {
        mem::replace(&mut self.con_rec_c.uuid, uuid)
    }

    #[inline]
    pub fn get_uuid(&self) -> &Option<Uuid> {
        &self.con_rec_c.uuid
    }

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
    con_records_c: Vec<ConRecord>,
    con_records_s: Vec<ConRecord>,
    //sockport: Box<[Box<[(u32, u16);8]>; 0xFFFF]>,
    sock2port: BTreeMap<(u32,u16), u16>,
    free_ports: VecDeque<u16>,
    port2con: Vec<Connection>,
    pci: CacheAligned<PortQueue>,
    // the PortQueue for which connections are managed
    tcp_port_base: u16,
    ip: u32, // ip address to use for connections of this manager/pipeline  towards the servers
}

const MAX_CONNECTIONS: usize = 0xFFFF as usize;

impl ConnectionManager {
    pub fn new(pci: CacheAligned<PortQueue>, l4flow: &L4Flow) -> ConnectionManager {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base) = (l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port = tcp_port_base + !port_mask;
        let mut cm = ConnectionManager {
            con_records_c: Vec::with_capacity(MAX_CONNECTIONS),
            con_records_s: Vec::with_capacity(MAX_CONNECTIONS),
            //sock2port: HashMap::with_capacity(256),
            sock2port: BTreeMap::new(),
            port2con: vec![Connection::new(); (!port_mask + 1) as usize],
            free_ports: ((if tcp_port_base == 0 { 1 } else { tcp_port_base })..max_tcp_port).collect(), // port 0 is reserved and not usable for us
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

    pub fn get_mut_by_port(&mut self, port: u16) -> Option<&mut Connection> {
        if self.owns_tcp_port(port) {
            let c = self.get_mut_con(&port);
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

    pub fn get_mut_by_sock(&mut self, sock: &SocketAddrV4) -> Option<&mut Connection> {
        let s = (u32::from(*sock.ip()), sock.port());
        let port = self.sock2port.get(&s);
        if port.is_some() {
            Some(&mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize])
        } else {
            None
        }
    }

    pub fn get_mut_or_insert(&mut self, sock: &SocketAddrV4) -> Option<&mut Connection> {
        let s = (u32::from(*sock.ip()), sock.port());
        {
            // we borrow sock2port here !
            let port = self.sock2port.get(&s);
            if port.is_some() {
                let cc= &mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize];
                assert_ne!(cc.port(), 0);
                return Some(cc);
            }
        }
        // now we are free to borrow sock2port mutably
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.unwrap();
            let cc = &mut self.port2con[(port - self.tcp_port_base) as usize];
            assert_eq!(cc.port(), 0);
            cc.initialize(sock, port);
            debug!(
                "rxq={}: tcp flow for {} created on {}:{:?}",
                self.pci.rxq(),
                sock,
                Ipv4Addr::from(self.ip),
                port
            );
            self.sock2port.insert(s, port);
            Some(cc)
        } else {
            warn!("out of ports");
            None
        }
    }

    pub fn release_port(&mut self, port: u16) {
        let c = &mut self.port2con[(port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.in_use() {
            self.con_records_c.push(c.con_rec_c.clone());
            self.con_records_s.push(c.con_rec_s.clone());
            self.free_ports.push_back(port);
            assert_eq!(port, c.port());
            {
                let sock = c.get_client_sock();
                if sock.is_some() {
                    let s = (u32::from(*sock.unwrap().ip()), sock.unwrap().port());
                    let port = self.sock2port.remove(&s);
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
            let mut c = self.get_mut_by_port(port);
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
                c_records.push(c.con_rec_c.clone());
            }
        });
    }

    pub fn fetch_c_records(&mut self) -> (Vec<ConRecord>, Vec<ConRecord>) {
        (
            mem::replace(&mut self.con_records_c, Vec::with_capacity(MAX_CONNECTIONS)), // we are "moving" the con_records out, and replace it with a new one
            mem::replace(&mut self.con_records_s, Vec::with_capacity(MAX_CONNECTIONS)),
        )
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
