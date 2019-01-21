use std::net::Ipv4Addr;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::fmt;
use std::mem;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use e2d2::headers::{MacHeader, TcpHeader};
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PacketRx, PortQueue, L4Flow, Packet};
use e2d2::common::EmptyMetadata;
use e2d2::utils;

//use uuid::Uuid;
use netfcts::timer_wheel::TimerWheel;
use netfcts::tcp_common::*;
use netfcts::RecordStore;
use netfcts::ConRecordOperations;
use netfcts::utils::shuffle_ports;
use netfcts::utils::Sock2Index;
#[cfg(feature = "profiling")]
use netfcts::utils::TimeAdder;

pub struct Connection {
    pub payload_packet: Option<Packet<TcpHeader, EmptyMetadata>>,
    //Box makes the trait object sizeable
    ///can be used by applications to store application specific connection state
    pub userdata: Option<Box<UserData>>,
    pub client_mac: MacHeader,
    pub wheel_slot_and_index: (u16, u16),
    /// a helper construct to access either connection record for client or server side, see also c() and s() below
    selector: Selector,
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

pub struct Selector {
    selected_con_rec: Cell<usize>,
    selected_store: Cell<usize>,
    con_rec: [Option<usize>; 2],
    record_stores: [Option<Rc<RefCell<RecordStore>>>; 2],
}

impl Selector {
    fn allocate_conrecs(&mut self) {
        self.con_rec = [
            Some(self.record_stores[0].as_ref().unwrap().borrow_mut().get_unused_slot()),
            Some(self.record_stores[1].as_ref().unwrap().borrow_mut().get_unused_slot()),
        ]
    }
}

impl ConRecordOperations for Selector {
    #[inline]
    fn store(&self) -> &Rc<RefCell<RecordStore>> {
        self.record_stores[self.selected_store.get()].as_ref().unwrap()
    }

    #[inline]
    fn con_rec(&self) -> usize {
        self.selected_con_rec.get()
    }

    #[inline]
    fn release_conrec(&mut self) {
        self.con_rec = [None; 2];
        self.record_stores = [None, None];
    }

    #[inline]
    fn in_use(&self) -> bool {
        self.record_stores[0].is_some() && self.record_stores[1].is_some()
    }
}

impl Connection {
    #[inline]
    fn initialize(&mut self, client_sock: &(u32, u16), proxy_sport: u16, stores: [Option<Rc<RefCell<RecordStore>>>; 2]) {
        self.userdata = None;
        self.client_mac = MacHeader::default();
        self.c_seqn = 0;
        self.f_seqn = 0;
        self.ackn_p2s = 0;
        self.ackn_p2c = 0;
        self.c2s_inserted_bytes = 0;
        self.seqn_fin_p2c = 0;
        self.seqn_fin_p2s = 0;
        self.wheel_slot_and_index = (0, 0);
        self.selector.record_stores = stores;
        self.selector.allocate_conrecs();
        self.c().store().borrow_mut().get_mut(self.c().con_rec()).unwrap().init(
            TcpRole::Client,
            proxy_sport,
            Some(*client_sock),
        );
        self.s().store().borrow_mut().get_mut(self.s().con_rec()).unwrap().init(
            TcpRole::Server,
            proxy_sport,
            Some(*client_sock),
        );
        let uid = self.c().get_uid();
        self.s_mut().set_uid(uid);
    }

    fn new() -> Connection {
        Connection {
            payload_packet: None,
            userdata: None,
            client_mac: MacHeader::default(),
            c_seqn: 0,
            ackn_p2s: 0,
            ackn_p2c: 0,
            c2s_inserted_bytes: 0,
            wheel_slot_and_index: (0, 0),
            f_seqn: 0,
            seqn_fin_p2c: 0,
            seqn_fin_p2s: 0,
            selector: Selector {
                selected_con_rec: Cell::new(0),
                selected_store: Cell::new(2),
                con_rec: [None, None],
                record_stores: [None, None],
            },
        }
    }

    #[inline]
    pub fn release_conrec(&mut self) {
        self.selector.release_conrec()
    }

    #[inline]
    pub fn c(&self) -> &Selector {
        self.selector.selected_con_rec.set(self.selector.con_rec[0].unwrap());
        self.selector.selected_store.set(0);
        &self.selector
    }

    #[inline]
    pub fn s(&self) -> &Selector {
        self.selector.selected_con_rec.set(self.selector.con_rec[1].unwrap());
        self.selector.selected_store.set(1);
        &self.selector
    }

    #[inline]
    pub fn c_mut(&mut self) -> &mut Selector {
        self.selector.selected_con_rec.set(self.selector.con_rec[0].unwrap());
        self.selector.selected_store.set(0);
        &mut self.selector
    }

    #[inline]
    pub fn s_mut(&mut self) -> &mut Selector {
        self.selector.selected_con_rec.set(self.selector.con_rec[1].unwrap());
        self.selector.selected_store.set(1);
        &mut self.selector
    }

    #[inline]
    pub fn in_use(&self) -> bool {
        self.selector.record_stores[0].is_some() && self.selector.record_stores[1].is_some()
    }

    #[inline]
    pub fn client_con_established(&mut self) {
        self.c().push_state(TcpState::Established);
    }

    #[inline]
    pub fn server_syn_sent(&mut self) {
        self.s().push_state(TcpState::SynReceived);
    }

    #[inline]
    pub fn server_con_established(&mut self) {
        self.s().push_state(TcpState::Established);
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.c().port()
    }

    #[inline]
    pub fn set_port(&mut self, port: u16) {
        self.c_mut().set_port(port);
    }

    #[inline]
    pub fn get_client_sock(&self) -> Option<(u32, u16)> {
        self.c().get_dut_sock()
    }

    #[inline]
    pub fn set_client_sock(&mut self, client_sock: (u32, u16)) {
        self.c_mut().set_dut_sock(client_sock);
    }

    #[inline]
    pub fn set_uid(&mut self, uid: u64) {
        self.c_mut().set_uid(uid);
    }

    #[inline]
    pub fn get_uid(&self) -> u64 {
        self.c().get_uid()
    }

    #[inline]
    pub fn make_uid(&mut self) -> u64 {
        let uid = utils::rdtsc_unsafe();
        self.c_mut().set_uid(uid);
        self.s_mut().set_uid(uid);
        uid
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(port={}, {:?}/{:?})",
            self.port(),
            self.c().states(),
            self.s().states()
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
    record_store: [Rc<RefCell<RecordStore>>; 2],
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
        let store_c = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let store_s = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let mut cm = ConnectionManager {
            record_store: [store_c.clone(), store_s.clone()],
            sock2port: Sock2Index::new(),
            #[cfg(feature = "profiling")]
            time_adder: TimeAdder::new("cm_get_mut_or_insert", 4000),
            port2con: vec![Connection::new(); !port_mask as usize + 1],
            free_ports: {
                let vec = shuffle_ports(if tcp_port_base == 0 { 1 } else { tcp_port_base }, max_tcp_port - 1);
                VecDeque::<u16>::from(vec)
            }, // port 0 is reserved and not usable for us
            pci,
            tcp_port_base,
            ip,
        };
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
        #[cfg(feature = "profiling")]
        let timestamp_entry = utils::rdtscp_unsafe();
        {
            // we borrow sock2port here !
            let port = self.sock2port.get(sock);
            if port.is_some() {
                let cc = &mut self.port2con[(port.unwrap() - self.tcp_port_base) as usize];
                assert_ne!(cc.port(), 0);
                #[cfg(feature = "profiling")]
                self.time_adder.add_diff(utils::rdtscp_unsafe() - timestamp_entry);
                return Some(cc);
            }
        }
        // now we are free to borrow sock2port mutably
        let opt_port = self.free_ports.pop_front();
        if opt_port.is_some() {
            let port = opt_port.unwrap();
            let cc = &mut self.port2con[(port - self.tcp_port_base) as usize];

            cc.initialize(
                sock,
                port,
                [Some(Rc::clone(&self.record_store[0])), Some(Rc::clone(&self.record_store[1]))],
            );

            debug!(
                "rxq={}: tcp flow for socket ({},{}) created on {}:{:?}",
                self.pci.rxq(),
                sock.0,
                sock.1,
                Ipv4Addr::from(self.ip),
                port
            );
            self.sock2port.insert(*sock, port);
            #[cfg(feature = "profiling")]
            self.time_adder.add_diff(utils::rdtscp_unsafe() - timestamp_entry);
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
                let sock = c.get_client_sock();
                if sock.is_some() {
                    let port = self.sock2port.remove(&sock.unwrap());
                    assert_eq!(port.unwrap(), c.port());
                }
            }
            // this releases client and server side con_recs and stores
            c.c_mut().release_conrec();
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
                c.c().released(ReleaseCause::Timeout);
                c.c().push_state(TcpState::Closed);
                debug!("timing out port {} at {:?}", port, c.wheel_slot_and_index);
                sock = c.get_client_sock();
                c.c_mut().release_conrec();
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

    pub fn fetch_c_records(&mut self) -> (Option<RecordStore>, Option<RecordStore>) {
        // we are "moving" the record_store out, and replace it with a new one
        let new_store_c = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let new_store_s = Rc::new(RefCell::new(RecordStore::with_capacity(MAX_RECORDS)));
        let [old_store_c, old_store_s] = mem::replace(&mut self.record_store, [new_store_c, new_store_s]);
        let strong_count_c = Rc::strong_count(&old_store_c);
        let strong_count_s = Rc::strong_count(&old_store_s);
        debug!("fetch_c_records: strong_counts= {}, {}", strong_count_c, strong_count_s);
        // we should have only one reference per store, if every connection was released
        if strong_count_c > 1 || strong_count_s > 1 {
            for c in &mut self.port2con {
                c.release_conrec();
            }
        }
        let unwrapped_c = Rc::try_unwrap(old_store_c);
        let unwrapped_s = Rc::try_unwrap(old_store_s);
        (
            if unwrapped_c.is_ok() {
                Some(unwrapped_c.unwrap().into_inner())
            } else {
                None
            },
            if unwrapped_s.is_ok() {
                Some(unwrapped_s.unwrap().into_inner())
            } else {
                None
            },
        )
    }
}

/*

impl Drop for ConnectionManager {
    fn drop(&mut self) { self.send_all_c_records(); }
}
*/
