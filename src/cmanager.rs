use std::net::Ipv4Addr;
use std::collections::{VecDeque, BTreeMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::fmt;
use std::mem;
use std::cell::RefCell;
use std::rc::Rc;

use e2d2::interface::{PortQueue, L4Flow, Pdu};
use e2d2::utils;

//use uuid::Uuid;
use netfcts::timer_wheel::TimerWheel;
use netfcts::tcp_common::*;
use netfcts::Store64;
use netfcts::{Storable, SimpleStore, HasTcpState};
use netfcts::TIME_STAMP_REDUCTION_FACTOR;
use netfcts::utils::shuffle_ports;
//use netfcts::utils::Sock2Index;
#[cfg(feature = "profiling")]
use netfcts::utils::TimeAdder;

use eui48::MacAddress;
use separator::Separatable;

pub type ProxyRecStore = Store64<Extension>;

#[derive(Clone, Copy, Debug)]
#[repr(align(32))]
pub struct Extension {
    s_stamps: [u32; 7],
    s_state: [u8; 7],
    s_state_count: u8,
    s_release_cause: u8,
}

impl Extension {
    #[inline]
    pub fn states(&self) -> Vec<TcpState> {
        let mut result = vec![TcpState::Listen; self.s_state_count as usize + 1];
        for i in 0..self.s_state_count as usize {
            result[i + 1] = TcpState::from(self.s_state[i]);
        }
        result
    }

    #[inline]
    fn push_state(&mut self, state: TcpState, base_stamp: u64) {
        self.s_state[self.s_state_count as usize] = state as u8;
        self.s_stamps[self.s_state_count as usize] =
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

    #[inline]
    fn init(&mut self) {
        self.s_state_count = 0;
    }

    #[inline]
    pub fn last_state(&self) -> TcpState {
        if self.s_state_count == 0 {
            TcpState::Listen
        } else {
            TcpState::from(self.s_state[self.s_state_count as usize - 1])
        }
    }

    #[inline]
    pub fn get_last_stamp(&self) -> Option<u64> {
        match self.s_state_count {
            0 => None,
            _ => Some(self.s_stamps[self.s_state_count as usize - 1] as u64 * TIME_STAMP_REDUCTION_FACTOR),
        }
    }

    #[inline]
    pub fn get_first_stamp(&self) -> Option<u64> {
        if self.s_state_count > 0 {
            Some(self.s_stamps[0] as u64 * TIME_STAMP_REDUCTION_FACTOR)
        } else {
            None
        }
    }

    fn deltas_to_base_stamp(&self) -> Vec<u32> {
        if self.s_state_count >= 1 {
            self.s_stamps[0..(self.s_state_count as usize)].iter().map(|s| *s).collect()
        } else {
            vec![]
        }
    }
}

impl Storable for Extension {
    fn new() -> Extension {
        Extension {
            s_state: [TcpState::Listen as u8; 7],
            s_stamps: [0u32; 7],
            s_release_cause: ReleaseCause::Unknown as u8,
            s_state_count: 0,
        }
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(Server, {:?}, {:?}, {:?})",
            self.states(),
            self.release_cause(),
            self.deltas_to_base_stamp()
                .iter()
                .map(|u| u.separated_string())
                .collect::<Vec<_>>(),
        )
    }
}

pub union Seqn {
    /// seqn_nxt for connection from client to server, only used during connection setup
    pub f_seqn: u32,
    /// latest seqn of FIN seen for proxy to client, only used during connection release
    pub ack_for_fin_p2c: u32,
}

pub struct ProxyConnection<'a> {
    pub payload_packet: Option<Box<Pdu<'a>>>,
    //pub payload: Box<Vec<u8>>,
    detailed_c: Option<Box<DetailedConnection>>,
    pub client_mac: MacAddress,
    client_port: u16,
    client_ip: u32,
    /// seqn for connection to client,
    /// after the SYN-ACK from the target server it is the delta to be added to server seqn
    /// see 'server_synack_received'
    pub c_seqn: u32,
    /// current ack no towards server (=expected seqn)
    pub ackn_p2s: u32,
    /// current ack no towards client (=expected seqn)
    pub ackn_p2c: u32,
    pub seqn: Seqn,
    /// number of bytes inserted/removed by proxy in connection from client to server
    pub c2s_inserted_bytes: i32,
    /// latest seqn of FIN seen for proxy to server
    pub seqn_fin_p2s: u32,
    /// egress proxy port assigned to this connection
    proxy_port: u16,
    pub wheel_slot_and_index: (u16, u16),
    /// current client and server state, we keep a copy here for performance reasons
    pub client_state: u8,
    pub server_state: u8,
    /// server assigned to this connection
    server_index: u8,
}

impl<'a> ProxyConnection<'a> {
    fn new() -> ProxyConnection<'a> {
        ProxyConnection {
            payload_packet: None,
            //payload: Box::new(Vec::with_capacity(1500)),
            detailed_c: None,
            //userdata: None,
            client_mac: MacAddress::default(),
            c_seqn: 0,
            ackn_p2s: 0,
            ackn_p2c: 0,
            c2s_inserted_bytes: 0,
            wheel_slot_and_index: (0, 0),
            seqn: Seqn { f_seqn: 0 },
            seqn_fin_p2s: 0,
            client_ip: 0,
            client_port: 0,
            proxy_port: 0,
            server_index: 0,
            client_state: TcpState::Closed as u8,
            server_state: TcpState::Listen as u8,
        }
    }

    #[inline]
    fn initialize(&mut self, client_sock: &(u32, u16), proxy_port: u16) {
        //self.userdata = None;
        self.payload_packet = None;
        //self.payload.clear();
        self.client_mac = MacAddress::default();
        self.c_seqn = 0;
        self.seqn.f_seqn = 0;
        self.ackn_p2s = 0;
        self.ackn_p2c = 0;
        self.c2s_inserted_bytes = 0;
        self.seqn_fin_p2s = 0;
        self.wheel_slot_and_index = (0, 0);
        self.client_ip = client_sock.0;
        self.client_port = client_sock.1;
        self.proxy_port = proxy_port;
        self.server_index = 0;
        self.client_state = TcpState::Closed as u8;
        self.server_state = TcpState::Listen as u8;
    }

    #[inline]
    fn initialize_with_details(&mut self, client_sock: &(u32, u16), proxy_port: u16, store: &Rc<RefCell<ProxyRecStore>>) {
        self.initialize(client_sock, proxy_port);
        if self.detailed_c.is_none() {
            self.detailed_c = Some(Box::new(DetailedConnection::new(store)));
        } else {
            self.detailed_c.as_mut().unwrap().re_new(store)
        }
        self.detailed_c.as_mut().unwrap().initialize(client_sock, proxy_port)
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.proxy_port
    }

    #[inline]
    fn in_use(&self) -> bool {
        self.proxy_port != 0
    }

    #[inline]
    fn release(&mut self) {
        self.proxy_port = 0;
        if self.detailed_c.is_some() {
            self.detailed_c.as_mut().unwrap().release();
        }
    }

    #[inline]
    pub fn server_index(&self) -> usize {
        self.server_index as usize
    }

    #[inline]
    pub fn set_server_index(&mut self, index: u8) {
        self.server_index = index;
    }

    #[inline]
    pub fn sock(&self) -> Option<(u32, u16)> {
        let s = (self.client_ip, self.client_port);
        if s.0 != 0 {
            Some(s)
        } else {
            None
        }
    }

    #[inline]
    pub fn set_sock(&mut self, s: (u32, u16)) {
        self.client_ip = s.0;
        self.client_port = s.1;
    }

    #[inline]
    pub fn client_state(&self) -> TcpState {
        TcpState::from(self.client_state)
    }

    #[inline]
    pub fn server_state(&self) -> TcpState {
        TcpState::from(self.server_state)
    }

    #[inline]
    pub fn c_push_state(&mut self, state: TcpState) {
        if self.detailed_c.is_some() {
            self.detailed_c.as_mut().unwrap().c_push_state(state)
        }
        self.client_state = state as u8;
    }

    #[inline]
    pub fn s_push_state(&mut self, state: TcpState) {
        if self.detailed_c.is_some() {
            self.detailed_c.as_mut().unwrap().s_push_state(state)
        }
        self.server_state = state as u8;
    }

    #[inline]
    pub fn s_set_release_cause(&mut self, cause: ReleaseCause) {
        if self.detailed_c.is_some() {
            self.detailed_c.as_mut().unwrap().s_set_release_cause(cause)
        }
    }

    #[inline]
    pub fn s_init(&mut self) {
        if self.detailed_c.is_some() {
            self.detailed_c.as_mut().unwrap().s_init()
        }
    }

    #[inline]
    pub fn set_release_cause(&mut self, cause: ReleaseCause) {
        if self.detailed_c.is_some() {
            self.detailed_c.as_mut().unwrap().set_release_cause(cause)
        }
    }

    #[inline]
    pub fn s_states(&self) -> Vec<TcpState> {
        if self.detailed_c.is_some() {
            self.detailed_c.as_ref().unwrap().s_states()
        } else {
            Vec::new()
        }
    }

    #[inline]
    pub fn c_states(&self) -> Vec<TcpState> {
        if self.detailed_c.is_some() {
            self.detailed_c.as_ref().unwrap().c_states()
        } else {
            Vec::new()
        }
    }
}

pub struct DetailedConnection {
    con_rec: Option<usize>,
    store: Option<Rc<RefCell<ProxyRecStore>>>,
}

const ERR_NO_CON_RECORD: &str = "connection has no ConRecord";

impl DetailedConnection {
    #[inline]
    fn initialize(&mut self, client_sock: &(u32, u16), proxy_sport: u16) {
        self.store()
            .borrow_mut()
            .get_mut(self.con_rec())
            .init(TcpRole::Client, proxy_sport, Some(*client_sock));
        // the server side record is initialized when SYN is sent to server
    }

    fn new(store: &Rc<RefCell<ProxyRecStore>>) -> DetailedConnection {
        let con_rec = store.borrow_mut().get_next_slot();
        DetailedConnection {
            con_rec: Some(con_rec),
            store: Some(Rc::clone(store)),
        }
    }

    fn re_new(&mut self, store: &Rc<RefCell<ProxyRecStore>>) {
        let con_rec = store.borrow_mut().get_next_slot();
        self.con_rec = Some(con_rec);
        self.store = Some(Rc::clone(store));
    }

    #[inline]
    fn store(&self) -> &Rc<RefCell<ProxyRecStore>> {
        self.store.as_ref().unwrap()
    }

    #[inline]
    fn con_rec(&self) -> usize {
        self.con_rec.expect(ERR_NO_CON_RECORD)
    }

    #[inline]
    pub fn set_release_cause(&mut self, cause: ReleaseCause) {
        self.store().borrow_mut().get_mut(self.con_rec()).set_release_cause(cause)
    }
    /*
        #[inline]
        pub fn s_last_state(&self) -> TcpState {
            self.store().borrow().get_1(self.con_rec()).last_state()
        }
    */

    #[inline]
    pub fn c_states(&self) -> Vec<TcpState> {
        self.store().borrow().get(self.con_rec()).states()
    }

    #[inline]
    pub fn s_states(&self) -> Vec<TcpState> {
        self.store().borrow().get_1(self.con_rec()).states()
    }

    #[inline]
    pub fn s_push_state(&mut self, state: TcpState) {
        let base_stamp = self.store().borrow().get(self.con_rec()).base_stamp();
        self.store()
            .borrow_mut()
            .get_mut_1(self.con_rec())
            .push_state(state, base_stamp);
    }

    #[inline]
    pub fn c_push_state(&mut self, state: TcpState) {
        self.store().borrow_mut().get_mut(self.con_rec()).push_state(state);
    }

    #[inline]
    pub fn s_init(&mut self) {
        self.store().borrow_mut().get_mut_1(self.con_rec()).init()
    }

    #[inline]
    pub fn s_set_release_cause(&mut self, cause: ReleaseCause) {
        self.store().borrow_mut().get_mut_1(self.con_rec()).set_release_cause(cause)
    }

    #[inline]
    fn release(&mut self) {
        //trace!("releasing con record on port {}", self.port());
        self.con_rec = None;
        self.store = None;
    }
}

impl<'a> Clone for ProxyConnection<'a> {
    fn clone(&self) -> Self {
        ProxyConnection::new()
    }
}

pub trait Connection {
    #[inline]
    fn s_push_state(&mut self, state: TcpState);

    #[inline]
    fn c_push_state(&mut self, state: TcpState);
}

pub static GLOBAL_MANAGER_COUNT: AtomicUsize = AtomicUsize::new(0);

pub struct ConnectionManager<'a> {
    record_store: Rc<RefCell<ProxyRecStore>>,
    //    sock2port: Sock2Index,
    sock2port: BTreeMap<(u32, u16), u16>,
    #[cfg(feature = "profiling")]
    time_adder: TimeAdder,
    //sock2port: HashMap<(u32, u16), u16>,
    free_ports: VecDeque<u16>,
    port2con: Vec<ProxyConnection<'a>>,
    pci: PortQueue,
    // the PortQueue for which connections are managed
    tcp_port_base: u16,
    ip: u32,
    // ip address to use for connections of this manager/pipeline  towards the servers
    detailed_records: bool,
}

const MAX_RECORDS: usize = 0x3FFFF as usize;

impl<'a> ConnectionManager<'a> {
    pub fn new(pci: PortQueue, l4flow: L4Flow, detailed_records: bool) -> ConnectionManager<'a> {
        let old_manager_count: u16 = GLOBAL_MANAGER_COUNT.fetch_add(1, Ordering::SeqCst) as u16;
        let (ip, tcp_port_base) = (l4flow.ip, l4flow.port);
        let port_mask = pci.port.get_tcp_dst_port_mask();
        let max_tcp_port = tcp_port_base + !port_mask;
        // one store for client and server side
        let store = Rc::new(RefCell::new(Store64::with_capacity(MAX_RECORDS)));
        let mut cm = ConnectionManager {
            record_store: store.clone(),
            //            sock2port: Sock2Index::new(),
            sock2port: BTreeMap::new(),
            #[cfg(feature = "profiling")]
            time_adder: TimeAdder::new_with_warm_up("connection initialize", 100000, 100),
            free_ports: {
                let vec = shuffle_ports(if tcp_port_base == 0 { 1 } else { tcp_port_base }, max_tcp_port - 1);
                VecDeque::<u16>::from(vec)
            }, // port 0 is reserved and not usable for us
            port2con: Vec::with_capacity(!port_mask as usize + 1),
            pci,
            tcp_port_base,
            ip,
            detailed_records,
        };
        cm.port2con = vec![ProxyConnection::new(); !port_mask as usize + 1];
        // need to add last port this way to avoid overflow with slice, when max_tcp_port == 65535
        cm.free_ports.push_back(max_tcp_port);
        info!(
            "created ConnectionManager {} (detailed_records = {:?}) for port {}, rxq {}, ip= {}, tcp ports {} - {}",
            old_manager_count,
            detailed_records,
            cm.pci.port_id(),
            cm.pci.rxq(),
            Ipv4Addr::from(ip),
            if tcp_port_base == 0 { 1 } else { tcp_port_base },
            max_tcp_port,
        );
        cm
    }

    #[inline]
    fn get_mut_con(&mut self, p: &u16) -> &mut ProxyConnection<'a> {
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

    #[inline]
    pub fn get_mut_by_port(&mut self, port: u16) -> Option<&mut ProxyConnection<'a>> {
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

    pub fn get_mut_by_sock(&mut self, sock: &(u32, u16)) -> Option<&mut ProxyConnection<'a>> {
        let port = self.sock2port.get(sock);
        if port.is_some() {
            Some(&mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize])
        } else {
            None
        }
    }

    pub fn get_mut_or_insert(&mut self, sock: &(u32, u16)) -> Option<&mut ProxyConnection<'a>> {
        {
            // we borrow sock2port here !
            let port = self.sock2port.get(sock);
            if port.is_some() {
                let cc = &mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize];
                assert!(cc.in_use());
                return Some(cc);
            }
        }
        // now we are free to borrow sock2port mutably
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.expect("something really weird has happened!");
            let cc = &mut self.port2con[(port - self.tcp_port_base) as usize];
            assert!(!cc.in_use());

            #[cfg(feature = "profiling")]
            let timestamp_entry = utils::rdtscp_unsafe();

            if self.detailed_records {
                cc.initialize_with_details(sock, port, &self.record_store);
            } else {
                cc.initialize(sock, port);
            }

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
            if old.is_some() {
                assert_eq!(old.unwrap(), port);
            }
            {
                let sock = c.sock();
                if sock.is_some() {
                    let port = self.sock2port.remove(&sock.unwrap());
                    if port.is_some() {
                        assert_eq!(port.unwrap(), c.port());
                    }
                }
            }
            c.release();
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
                c.c_push_state(TcpState::Closed);
                warn!(
                    "timing out port {}, sock {:?} at {:?}",
                    port,
                    c.sock().unwrap_or((0, 0)),
                    c.wheel_slot_and_index
                );
                sock = c.sock();
                c.release();
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
        debug!("records in record_store = {}", self.record_store.borrow().len());
        let new_store = Rc::new(RefCell::new(ProxyRecStore::with_capacity(MAX_RECORDS)));
        let old_store = mem::replace(&mut self.record_store, new_store);
        let strong_count_c = Rc::strong_count(&old_store);
        debug!("fetch_c_records: strong_count= {}", strong_count_c);
        // we should have only one reference per store, if every connection was released
        if strong_count_c > 1 {
            for c in &mut self.port2con {
                c.release();
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
