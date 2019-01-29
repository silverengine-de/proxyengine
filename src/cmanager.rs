use std::net::Ipv4Addr;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::fmt;
use std::mem;
use std::cell::RefCell;
use std::rc::Rc;

use e2d2::headers::TcpHeader;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow, Packet};
use e2d2::common::EmptyMetadata;
use e2d2::utils;

//use uuid::Uuid;
use netfcts::timer_wheel::TimerWheel;
use netfcts::tcp_common::*;
use netfcts::Store64;
use netfcts::{ConRecordOperations, Storable};
use netfcts::TIME_STAMP_REDUCTION_FACTOR;
use netfcts::utils::shuffle_ports;
use netfcts::utils::Sock2Index;
#[cfg(feature = "profiling")]
use netfcts::utils::TimeAdder;

use eui48::MacAddress;

pub type ProxyRecStore = Store64<Extension>;

#[derive(Clone, Copy, Debug)]
#[repr(align(32))]
pub struct Extension {
    s_stamps: [u32; 5],
    s_state: [u8; 8],
    s_state_count: u8,
    s_release_cause: u8,
}

impl Extension {
    #[inline]
    pub fn states(&self) -> Vec<TcpState> {
        let mut result = vec![TcpState::Listen; self.s_state_count as usize];
        for i in 0..self.s_state_count as usize {
            result[i] = TcpState::from(self.s_state[i]);
        }
        result
    }

    #[inline]
    fn push_state(&mut self, state: TcpState, base_stamp: u64) {
        self.s_state[self.s_state_count as usize] = state as u8;
        self.s_stamps[self.s_state_count as usize - 1] =
            ((utils::rdtsc_unsafe() - base_stamp) / TIME_STAMP_REDUCTION_FACTOR) as u32;
        self.s_state_count += 1;
    }

    #[inline]
    pub fn release_cause(&self) -> ReleaseCause {
        ReleaseCause::from(self.s_release_cause)
    }

    #[inline]
    fn set_release_cause(&mut self, cause: ReleaseCause) {
        self.s_release_cause = cause as u8;
    }

    fn init(&mut self) {
        self.s_state[0] = TcpState::Listen as u8;
        self.s_state_count = 1;
    }

    pub fn last_state(&self) -> TcpState {
        TcpState::from(self.s_state[self.s_state_count as usize - 1])
    }
}

impl Storable for Extension {
    fn new() -> Extension {
        Extension {
            s_state: [TcpState::Closed as u8; 8],
            s_stamps: [0u32; 5],
            s_release_cause: ReleaseCause::Unknown as u8,
            s_state_count: 0,
        }
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:?}, {:?})", self.states(), self.release_cause(),)
    }
}

pub struct Connection {
    pub payload_packet: Option<Box<Packet<TcpHeader, EmptyMetadata>>>,
    //Box makes the trait object sizeable
    ///can be used by applications to store application specific connection state
    pub userdata: Option<Box<UserData>>,
    pub client_mac: MacAddress,
    pub wheel_slot_and_index: (u16, u16),
    con_rec: Option<usize>,
    store: Option<Rc<RefCell<ProxyRecStore>>>,
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

const ERR_NO_CON_RECORD: &str = "connection has no ConRecord";

impl ConRecordOperations<ProxyRecStore> for Connection {
    #[inline]
    fn store(&self) -> &Rc<RefCell<ProxyRecStore>> {
        self.store.as_ref().unwrap()
    }

    #[inline]
    fn con_rec(&self) -> usize {
        self.con_rec.expect(ERR_NO_CON_RECORD)
    }

    #[inline]
    fn release_conrec(&mut self) {
        //trace!("releasing con record on port {}", self.port());
        self.con_rec = None;
        self.store = None;
    }

    #[inline]
    fn in_use(&self) -> bool {
        self.store.is_some()
    }
}

impl Connection {
    #[inline]
    fn initialize(&mut self, client_sock: &(u32, u16), proxy_sport: u16, store: Rc<RefCell<ProxyRecStore>>) {
        self.userdata = None;
        self.client_mac = MacAddress::default();
        self.c_seqn = 0;
        self.f_seqn = 0;
        self.ackn_p2s = 0;
        self.ackn_p2c = 0;
        self.c2s_inserted_bytes = 0;
        self.seqn_fin_p2c = 0;
        self.seqn_fin_p2s = 0;
        self.wheel_slot_and_index = (0, 0);
        self.con_rec = Some(store.borrow_mut().get_unused_slot());
        self.store = Some(store);
        self.store
            .as_ref()
            .unwrap()
            .borrow_mut()
            .get_mut(self.con_rec())
            .unwrap()
            .init(TcpRole::Proxy, proxy_sport, Some(*client_sock));
        self.store
            .as_ref()
            .unwrap()
            .borrow_mut()
            .get_mut_1(self.con_rec())
            .unwrap()
            .init();
    }

    fn new() -> Connection {
        Connection {
            payload_packet: None,
            userdata: None,
            client_mac: MacAddress::default(),
            c_seqn: 0,
            ackn_p2s: 0,
            ackn_p2c: 0,
            c2s_inserted_bytes: 0,
            wheel_slot_and_index: (0, 0),
            f_seqn: 0,
            seqn_fin_p2c: 0,
            seqn_fin_p2s: 0,
            con_rec: None,
            store: None,
        }
    }

    #[inline]
    pub fn server_syn_sent(&mut self) {
        self.s_push_state(TcpState::SynReceived);
    }

    #[inline]
    pub fn server_con_established(&mut self) {
        self.s_push_state(TcpState::Established);
    }

    #[inline]
    pub fn make_uid(&mut self) -> u64 {
        let uid = utils::rdtsc_unsafe();
        self.set_uid(uid);
        uid
    }

    #[inline]
    pub fn s_last_state(&self) -> TcpState {
        self.store().borrow().get_1(self.con_rec()).unwrap().last_state()
    }

    #[inline]
    pub fn s_states(&self) -> Vec<TcpState> {
        self.store().borrow().get_1(self.con_rec()).unwrap().states()
    }

    #[inline]
    pub fn s_push_state(&mut self, state: TcpState) {
        let base_stamp = self.store().borrow().get(self.con_rec()).unwrap().base_stamp();
        self.store()
            .borrow_mut()
            .get_mut_1(self.con_rec())
            .unwrap()
            .push_state(state, base_stamp)
    }

    #[inline]
    pub fn s_set_release_cause(&mut self, cause: ReleaseCause) {
        self.store()
            .borrow_mut()
            .get_mut_1(self.con_rec())
            .unwrap()
            .set_release_cause(cause)
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(port={}, {:?}/{:?})",
            self.port(),
            self.states(),
            self.s_states()
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
    record_store: Rc<RefCell<ProxyRecStore>>,
    sock2port: Sock2Index,
    #[cfg(feature = "profiling")]
    time_adder: TimeAdder,
    //sock2port: HashMap<(u32, u16), u16>,
    free_ports: VecDeque<u16>,
    port2con: Vec<Connection>,
    pci: CacheAligned<PortQueue>,
    // the PortQueue for which connections are managed
    tcp_port_base: u16,
    ip: u32, // ip address to use for connections of this manager/pipeline  towards the servers
}

const MAX_RECORDS: usize = 0x3FFFF as usize;

impl ConnectionManager {
    pub fn new(pci: CacheAligned<PortQueue>, l4flow: &L4Flow) -> ConnectionManager {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base) = (l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port = tcp_port_base + !port_mask;
        // one store for client and server side
        let store = Rc::new(RefCell::new(Store64::with_capacity(MAX_RECORDS)));
        let mut cm = ConnectionManager {
            record_store: store.clone(),
            sock2port: Sock2Index::new(),
            #[cfg(feature = "profiling")]
            time_adder: TimeAdder::new_with_warm_up("connection initialize", 4000, 100),
            free_ports: {
                let vec = shuffle_ports(if tcp_port_base == 0 { 1 } else { tcp_port_base }, max_tcp_port - 1);
                VecDeque::<u16>::from(vec)
            }, // port 0 is reserved and not usable for us
            port2con: Vec::with_capacity(!port_mask as usize + 1),
            pci,
            tcp_port_base,
            ip,
        };
        cm.port2con = vec![Connection::new(); !port_mask as usize + 1];
        // need to add last port this way to avoid overflow with slice, when max_tcp_port == 65535
        cm.free_ports.push_back(max_tcp_port);
        info!(
            "created ConnectionManager {} for port {}, rxq {}, ip= {}, tcp ports {} - {}",
            old_manager_count,
            PacketRx::port_id(&cm.pci),
            cm.pci.rxq(),
            Ipv4Addr::from(ip),
            if tcp_port_base == 0 { 1 } else { tcp_port_base },
            max_tcp_port,
        );
        cm
    }

    #[inline]
    fn get_mut_con(&mut self, p: &u16) -> &mut Connection {
        &mut self.port2con[(p - self.tcp_port_base) as usize]
    }

    #[inline]
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
            // check if c is in use
            if c.in_use() {
                Some(c)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_mut_by_sock(&mut self, sock: &(u32, u16)) -> Option<&mut Connection> {
        let port = self.sock2port.get(sock);
        if port.is_some() {
            Some(&mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize])
        } else {
            None
        }
    }

    pub fn get_mut_or_insert(&mut self, sock: &(u32, u16)) -> Option<&mut Connection> {
        {
            // we borrow sock2port here !
            let port = self.sock2port.get(sock);
            if port.is_some() {
                let cc = &mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize];
                assert_ne!(cc.port(), 0);
                return Some(cc);
            }
        }
        // now we are free to borrow sock2port mutably
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.unwrap();
            let cc = &mut self.port2con[(port - self.tcp_port_base) as usize];

            #[cfg(feature = "profiling")]
            let timestamp_entry = utils::rdtscp_unsafe();

            cc.initialize(sock, port, Rc::clone(&self.record_store));

            #[cfg(feature = "profiling")]
            self.time_adder.add_diff(utils::rdtscp_unsafe() - timestamp_entry);

            debug!(
                "rxq={}: tcp flow for socket ({},{}) created on {}:{:?}",
                self.pci.rxq(),
                sock.0,
                sock.1,
                Ipv4Addr::from(self.ip),
                port
            );
            self.sock2port.insert(*sock, port);

            Some(cc)
        } else {
            warn!("out of ports");
            None
        }
    }

    pub fn release_port(&mut self, port: u16, wheel: &mut TimerWheel<u16>) {
        let c = &mut self.port2con[(port - self.tcp_port_base) as usize];
        // only if it is in use, i.e. it has been not released already
        if c.in_use() {
            self.free_ports.push_back(port);
            assert_eq!(port, c.port());
            //remove port from timer wheel by overwriting it
            let old = wheel.replace(c.wheel_slot_and_index, 0);
            assert_eq!(old.unwrap(), port);
            {
                let sock = c.sock();
                if sock.is_some() {
                    let port = self.sock2port.remove(&sock.unwrap());
                    assert_eq!(port.unwrap(), c.port());
                }
            }
            c.release_conrec();
        }
    }

    //TODO allow for more precise time out conditions, currently whole TCP connections are timed out, also we should send a RST
    pub fn release_timeouts(&mut self, now: &u64, wheel: &mut TimerWheel<u16>) {
        loop {
            match wheel.tick(now) {
                (Some(mut drain), more) => {
                    let mut port = drain.next();
                    while port.is_some() {
                        let p = port.unwrap();
                        if p != 0 {
                            self.timeout(p);
                        }
                        port = drain.next();
                    }
                    if !more {
                        break;
                    }
                }
                (None, more) => {
                    if !more {
                        break;
                    }
                }
            }
        }
    }

    #[inline]
    fn timeout(&mut self, port: u16) {
        let mut release = false;
        let mut sock = None;
        {
            let c = self.get_mut_by_port(port);
            if c.is_some() {
                let c = c.unwrap();
                c.set_release_cause(ReleaseCause::Timeout);
                c.push_state(TcpState::Closed);
                debug!("timing out port {} at {:?}", port, c.wheel_slot_and_index);
                sock = c.sock();
                c.release_conrec();
                release = true;
            }
        }
        if release {
            self.free_ports.push_back(port);
            if sock.is_some() {
                self.sock2port.remove(&sock.unwrap());
            }
        }
    }

    pub fn fetch_c_records(&mut self) -> Option<ProxyRecStore> {
        // we are "moving" the record_store out, and replace it with a new one
        let new_store = Rc::new(RefCell::new(ProxyRecStore::with_capacity(MAX_RECORDS)));
        let old_store = mem::replace(&mut self.record_store, new_store);
        let strong_count_c = Rc::strong_count(&old_store);
        debug!("fetch_c_records: strong_count= {}", strong_count_c);
        // we should have only one reference per store, if every connection was released
        if strong_count_c > 1 {
            for c in &mut self.port2con {
                c.release_conrec();
            }
        }
        let unwrapped_c = Rc::try_unwrap(old_store);
        if unwrapped_c.is_ok() {
            Some(unwrapped_c.unwrap().into_inner())
        } else {
            None
        }
    }
}
