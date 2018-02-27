use e2d2::operators::*;
use e2d2::scheduler::*;
use e2d2::allocators::CacheAligned;
use e2d2::native::zcsi::rte_kni_handle_request;
use e2d2::headers::{MacHeader, IpHeader, TcpHeader, MacAddress};
use e2d2::interface::*;
use e2d2::utils::{ipv4_extract_flow, finalize_checksum};
use e2d2::queues::{new_mpsc_queue_pair, MpscProducer};
use e2d2::headers::EndOffset;

use std::sync::Arc;
use std::cmp::min;
use std::hash::BuildHasherDefault;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::collections::{HashMap, VecDeque};
use std::any::Any;
use std::process::Command;

use rand;

const PROXY_PORT_MIN: u16 = 65526;
const MIN_FRAME_SIZE: usize = 60; // without fcs

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

pub struct Connection {
    pub payload: Box<Vec<u8>>,
    client_sock: SocketAddrV4,
    pub server: Option<L234Data>,
    pub userdata: Option<Box<UserData>>, //Box makes the trait object sizeable
    client_mac: MacHeader,
    proxy_sport: u16,
    c_state: TcpState,
    s_state: TcpState,
    /// c_seqn is seqn for connection to client,
    /// after the SYN-ACK from the target server it is the delta to be added to server seqn
    /// see 'server_synack_received'
    c_seqn: u32,
    /// number of bytes inserted by proxy in connection from client to server
    c2s_inserted_bytes: usize,
    f_seqn: u32, // seqn for connection from client
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
        }
    }
}

struct ConnectionManager {
    sock2port: HashMap<SocketAddrV4, u16, FnvHash>,
    freeports: VecDeque<u16>,
    port2con: HashMap<u16, Connection, FnvHash>, //port2con: Box<[Option(Arc<Connection>); (65535 - PROXY_PORT_MIN + 1) as usize]>
}

impl ConnectionManager {
    fn new() -> ConnectionManager {
        ConnectionManager {
            sock2port: HashMap::<SocketAddrV4, u16, FnvHash>::with_hasher(Default::default()),
            port2con: HashMap::<u16, Connection, FnvHash>::with_hasher(Default::default()),
            freeports: (PROXY_PORT_MIN..65535).collect(),
        }
    }

    fn get(&self, key: &CKey) -> Option<&Connection> {
        match *key {
            CKey::Port(p) => {
                if p >= PROXY_PORT_MIN {
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

    fn get_mut(&mut self, key: CKey) -> Option<&mut Connection> {
        match key {
            CKey::Port(p) => {
                if p >= PROXY_PORT_MIN {
                    if let Some(c) = self.port2con.get_mut(&p) {
                        // need to check if c has a port != 0 assigned
                        // otherwise it is released, as we keep released connections
                        // and just mark them as unused by assigning port 0
                        if c.proxy_sport != 0 { Some(c) } else { None }
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

    fn get_mut_or_insert(&mut self, key: CKey) -> Option<&mut Connection> {
        match key {
            CKey::Port(p) => {
                if p >= PROXY_PORT_MIN {
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
                let opt_port = self.freeports.pop_front();
                if opt_port.is_some() {
                    let port = opt_port.unwrap();
                    let mut c = None;
                    // reuse a released connection ?
                    if let Some(c) = self.port2con.get_mut(&port) {
                        assert!(c.proxy_sport == 0);
                        c.initialize(s, port);
                        debug!("tcp flow for {} created on port {:?}", s, port);
                        self.sock2port.insert(c.client_sock, port);

                    } else {
                        let mut cc = Connection::default();
                        cc.client_sock = s;
                        c = Some(cc);
                    };
                    if c.is_some() {
                        let mut c = c.unwrap();
                        c.initialize(s, port);
                        self.sock2port.insert(c.client_sock, port);
                        self.port2con.insert(port, c);
                        debug!("tcp flow for {} created on port {:?}", s, port);
                    }
                    self.port2con.get_mut(&port)
                } else {
                    None
                }
            }
        }
    }

    fn release(&mut self, c: &mut Connection) {
        self.freeports.push_back(c.proxy_sport);
        let port = self.sock2port.remove(&c.client_sock);
        assert!(port.unwrap() == c.proxy_sport);
        c.proxy_sport = 0;
    }

    fn release_port(&mut self, proxy_port: u16) {
        if let Some(c) = self.port2con.get_mut(&proxy_port) {
            self.freeports.push_back(proxy_port);
            assert!(proxy_port == c.proxy_sport);
            let port = self.sock2port.remove(&c.client_sock);
            assert!(port.unwrap() == c.proxy_sport);
            c.proxy_sport = 0u16; // this indicates an unused connection,
            // we keep unused connection in port2con table
        }
    }
}


pub struct KniHandleRequest {
    pub kni_port: Arc<PmdPort>,
}

impl Executable for KniHandleRequest {
    fn execute(&mut self) {
        unsafe {
            rte_kni_handle_request(self.kni_port.get_kni());
        }
    }
    fn dependencies(&mut self) -> Vec<usize> {
        vec![]
    }
}

pub fn is_kni_core(pci: &CacheAligned<PortQueue>) -> bool {
    pci.rxq() == 0
}

pub fn setup_kni(kni_name: &str, ip_address: &str, mac_address: &str, kni_netns: &str) {

    debug!("setup_kni");
    //# ip link set dev vEth1 address XX:XX:XX:XX:XX:XX
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "address", mac_address])
        .output()
        .expect("failed to assign MAC address to kni i/f");
    let reply = output.stderr;

    debug!(
        "assigning MAC addr {} to {}: {}, {}",
        mac_address,
        kni_name,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    //# ip netns add nskni
    let output = Command::new("ip")
        .args(&["netns", "add", kni_netns])
        .output()
        .expect("failed to create namespace for kni i/f");
    let reply = output.stderr;

    debug!(
        "creating network namespace {}: {}, {}",
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    // ip link set dev vEth1 netns nskni
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "netns", kni_netns])
        .output()
        .expect("failed to move kni i/f to namespace");
    let reply = output.stderr;

    debug!(
        "moving kni i/f {} to namesapce {}: {}, {}",
        kni_name,
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    // e.g. ip netns exec nskni ip addr add w.x.y.z/24 dev vEth1
    let output = Command::new("ip")
        .args(
            &[
                "netns",
                "exec",
                kni_netns,
                "ip",
                "addr",
                "add",
                ip_address,
                "dev",
                kni_name,
            ],
        )
        .output()
        .expect("failed to assign IP address to kni i/f");
    let reply = output.stderr;
    debug!(
        "assigning IP addr {} to {}: {}, {}",
        ip_address,
        kni_name,
        output.status,
        String::from_utf8_lossy(&reply)
    );
    // e.g. ip netns exec nskni ip link set dev vEth1 up
    let output1 = Command::new("ip")
        .args(
            &[
                "netns",
                "exec",
                kni_netns,
                "ip",
                "link",
                "set",
                "dev",
                kni_name,
                "up",
            ],
        )
        .output()
        .expect("failed to set kni i/f up");
    let reply1 = output1.stderr;
    debug!(
        "ip netns exec {} ip link set dev {} up: {}, {}",
        kni_netns,
        kni_name,
        output1.status,
        String::from_utf8_lossy(&reply1)
    );
    // e.g. ip netns exec nskni ip addr show dev vEth1
    let output2 = Command::new("ip")
        .args(
            &[
                "netns",
                "exec",
                kni_netns,
                "ip",
                "addr",
                "show",
                "dev",
                kni_name,
            ],
        )
        .output()
        .expect("failed to show IP address of kni i/f");
    let reply2 = output2.stdout;
    info!(
        "show IP addr: {}\n {}",
        output.status,
        String::from_utf8_lossy(&reply2)
    );
}


pub fn setup_forwarder<S, F1, F2>(
    pci: &CacheAligned<PortQueue>,
    kni: &CacheAligned<PortQueue>,
    sched: &mut S,
    pd: L234Data,
    f_select_server: F1,
    f_process_payload_c_s: F2,
) where
    S: Scheduler + Sized,
    F1: Fn(&mut Connection) + Sized + Send + 'static,
    F2: Fn(&mut Connection, &mut [u8], usize) + Sized + Send + 'static,
{
    debug!("enter setup_forwarder");
    debug!("proxy_mac = {}", pd.mac);

    let mut sm = ConnectionManager::new();
    debug!("StateManager created");

    // we need this queue for the delayed bindrequest
    let (producer, consumer) = new_mpsc_queue_pair();

    // forwarding frames coming from KNI to PCI, if we are the kni core
    if is_kni_core(pci) {
        let forward2pci = ReceiveBatch::new(kni.clone())
            .parse::<MacHeader>()
            .transform(box move |p| {
                let ethhead = p.get_mut_header();
                debug!("sending KNI frame to PCI: Eth header = { }", &ethhead);
            })
            .send(pci.clone());
        sched.add_task(forward2pci).unwrap();
    }

    // only accept traffic from PCI with matching L2 address
    let l2filter_from_pci = ReceiveBatch::new(pci.clone()).parse::<MacHeader>().filter(
        box move |p| {
            let header = p.get_header();
            if header.dst == pd.mac {
                debug!("from pci: found mac: {} ", &header);
                true
            } else if header.dst.is_multicast() || header.dst.is_broadcast() {
                debug!("from pci: multicast mac: {} ", &header);
                true
            } else {
                debug!("from pci: discarding because mac unknown: {} ", &header);
                false
            }
        },
    );

    // group the traffic into TCP traffic addressed to Proxy (group 1),
    // and send all other traffic to KNI (group 0)
    let mut l2groups = l2filter_from_pci.group_by(
        2,
        box move |p| {
            let payload = p.get_payload();
            let ipflow = ipv4_extract_flow(payload);
            if ipflow.is_none() {
                debug!("not ip_flow");
                0
            } else {
                let ipflow = ipflow.unwrap();
                if ipflow.dst_ip == pd.ip && ipflow.proto == 6 {
                    if ipflow.dst_port == pd.port || ipflow.dst_port >= PROXY_PORT_MIN {
                        debug!("proxy tcp flow: {:?}", ipflow);
                        1
                    } else {
                        debug!("no proxy tcp flow: {:?}", ipflow);
                        0
                    }
                } else {
                    debug!("ignored by proxy: not a tcp flow or not addressed to proxy");
                    0
                }
            }
        },
        sched,
    );

    // group 0 -> dump packets
    // group 1 -> send to PCI
    // group 2 -> send to KNI

    // process TCP traffic addressed to Proxy
    let mut l4groups = l2groups
        .get_group(1)
        .unwrap()
        .parse::<IpHeader>()
        .parse::<TcpHeader>()
        .group_by(3, 
            box move |p| {

            struct HeaderState<'a> {
                mac: &'a mut MacHeader,
                ip: &'a mut IpHeader,
                tcp: &'a mut TcpHeader,
                //flow: Flow,
            }
            
            impl<'a> HeaderState<'a> {
                fn set_server_socket(&mut self, ip: u32, port: u16) {
                    self.ip.set_dst(ip);
                    self.tcp.set_dst_port(port);
                }
            }
            
            fn do_ttl(h: &mut HeaderState) {
                let ttl = h.ip.ttl();
                if ttl >= 1 {
                    h.ip.set_ttl(ttl - 1);
                }
                h.ip.update_checksum();
            }
            
            fn make_reply_packet(h: &mut HeaderState,) {
                let smac = h.mac.src;
                let dmac = h.mac.dst;
                let sip = h.ip.src();
                let dip = h.ip.dst();
                let sport = h.tcp.src_port();
                let dport = h.tcp.dst_port();
                h.mac.set_smac(&dmac);
                h.mac.set_dmac(&smac);
                h.ip.set_dst(sip);
                h.ip.set_src(dip);
                h.tcp.set_src_port(dport);
                h.tcp.set_dst_port(sport);
                h.tcp.set_ack_flag();
                let ack_num=h.tcp.seq_num().wrapping_add(1);
                h.tcp.set_ack_num(ack_num);
            }

            // remove tcp options for SYN and SYN-ACK, 
            // pre-requisite: no payload exists, because any payload is not shifted up            
            fn remove_tcp_options<M: Sized+ Send>(
                p: &mut Packet<TcpHeader,M>, 
                h: &mut HeaderState, 
            ) {
                let old_offset = h.tcp.offset() as u16;
                if old_offset > 20 {
                    debug!("trimming tcp-options by { } bytes", old_offset-20);
                    h.tcp.set_data_offset(5u8);
                    h.ip.trim_length_by(old_offset-20u16);    // minimum mbuf data length is 60 bytes
                    let trim_by= min(p.data_len()- 60usize, (old_offset - 20u16) as usize);            
                    p.trim_payload_size(trim_by);
                    h.ip.update_checksum();
                }
            }

            fn client_syn_received<M: Sized+ Send> (
                p: &mut Packet<TcpHeader,M>, 
                c: &mut Connection, 
                h: &mut HeaderState, ) 
            {
                c.client_mac = h.mac.clone();
                c.client_sock=SocketAddrV4::new(Ipv4Addr::from(h.ip.src()), h.tcp.src_port());
                // debug!("checksum in = {:X}",p.get_header().checksum());
                remove_tcp_options(p, h);
                make_reply_packet(h);     
                //generate seq number:
                c.c_seqn=rand::random::<u32>();
                h.tcp.set_seq_num(c.c_seqn);
                update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                // debug!("checksum recalc = {:X}",p.get_header().checksum());
                debug!("reply with (SYN-)ACK, L3: { }, L4: { }", h.ip, h.tcp);    
            }
            
            fn set_proxy2server_headers(
                c: &mut Connection, 
                h: &mut HeaderState,
                pd: &L234Data, 
            ){
                h.mac.set_dmac(&c.server.as_ref().unwrap().mac);
                h.mac.set_smac(&pd.mac);
                let l2l3=&c.server.as_ref().unwrap();
                h.set_server_socket(l2l3.ip, l2l3.port);
                h.ip.set_src(pd.ip);
                h.tcp.set_src_port(c.proxy_sport);            
            }

            fn client_to_server<M: Sized+ Send, F>(
                p: &mut Packet<TcpHeader,M>, 
                c: &mut Connection, 
                h: &mut HeaderState, 
                pd: &L234Data,
                f_process_payload: F,         
            )
            where F: Fn(&mut Connection, &mut [u8], usize)
            {
                let tailroom=p.get_tailroom();
                f_process_payload(c, p.get_mut_payload(), tailroom);
                let ip_client=h.ip.src();    
                let port_client = h.tcp.src_port();
                set_proxy2server_headers(c,h,pd);
                h.tcp.update_checksum_incremental(port_client, c.proxy_sport);
                h.tcp.update_checksum_incremental(pd.port, c.server.as_ref().unwrap().port);
                h.tcp.update_checksum_incremental(
                    !finalize_checksum(ip_client),
                    !finalize_checksum(c.server.as_ref().unwrap().ip),
                );
                // adapt ackn of client packet
                let oldackn=h.tcp.ack_num();
                let newackn=oldackn.wrapping_sub(c.c_seqn);
                let oldseqn=h.tcp.seq_num();
                let newseqn=oldseqn.wrapping_add(c.c2s_inserted_bytes as u32);
                if c.c2s_inserted_bytes!=0 {
                    h.tcp.set_seq_num(newseqn);
                    h.tcp.update_checksum_incremental(
                        !finalize_checksum(oldseqn),
                        !finalize_checksum(newseqn),
                    );
                }
                h.tcp.set_ack_num(newackn);
                h.tcp.update_checksum_incremental(
                    !finalize_checksum(oldackn),
                    !finalize_checksum(newackn),
                );
                //debug!("translated c->s: { }, L4: { }", p, p.get_header());                
            }
            
            fn server_to_client<M: Sized+ Send>(
                p: &mut Packet<TcpHeader,M>, // we will need this once s->c payload inspection is required
                c: &mut Connection, 
                h: &mut HeaderState, 
                pd: &L234Data,            
            ) {
                // this is the s->c part of the stable two-way connection state
                // translate packets and forward to client
                h.mac.set_dmac(&c.client_mac.src);
                h.mac.set_smac(&pd.mac);
                let ip_server=h.ip.src();     
                h.ip.set_dst(u32::from(*c.client_sock.ip()));
                h.ip.set_src(pd.ip);
                let server_src_port = h.tcp.src_port();
                h.tcp.set_src_port(pd.port);
                h.tcp.set_dst_port(c.client_sock.port());
                h.tcp.update_checksum_incremental(server_src_port, pd.port);
                h.tcp.update_checksum_incremental(c.proxy_sport, c.client_sock.port());
                h.tcp.update_checksum_incremental(
                    !finalize_checksum(ip_server),
                    !finalize_checksum(u32::from(*c.client_sock.ip())),
                );
                // adapt seqn and ackn from server packet
                let oldseqn=h.tcp.seq_num();
                let newseqn=oldseqn.wrapping_add(c.c_seqn);
                let oldackn=h.tcp.ack_num();
                let newackn=oldackn.wrapping_sub(c.c2s_inserted_bytes as u32);
                if c.c2s_inserted_bytes!=0 {
                    h.tcp.set_ack_num(newackn);
                    h.tcp.update_checksum_incremental(
                        !finalize_checksum(oldackn),
                        !finalize_checksum(newackn),
                    );
                }
                h.tcp.set_seq_num(newseqn);
                h.tcp.update_checksum_incremental(
                    !finalize_checksum(oldseqn),
                    !finalize_checksum(newseqn),
                );
                //debug!("translated s->c: {}", p);                
            }
            
            #[inline]
            pub fn tcpip_payload_size<M: Sized+ Send>(p:&Packet<TcpHeader,M>) -> u16 {
                let iph = p.get_pre_header().unwrap();
                // payload size = ip total length - ip header length -tcp header length
                iph.length() - (iph.ihl() as u16) * 4u16 - (p.get_header().data_offset() as u16) * 4u16
            }
            
            fn select_server<M: Sized+ Send, F>(
                p: &mut Packet<TcpHeader,M>, 
                c: &mut Connection, 
                h: &mut HeaderState, 
                pd: &L234Data,
                f_select_server: &F,
            )
            where F: Fn(&mut Connection),
            {
                let payload_sz=tcpip_payload_size(p);
                {
                    // safe the payload for later
                    p.copy_payload_to_bytearray(&mut c.payload, payload_sz);
                    let old_payload_size=c.payload.len();
                    f_select_server(c);
                    c.c2s_inserted_bytes=c.payload.len()-old_payload_size;
                }
                // create a SYN Packet from the current packet
                // remove payload

                debug!("select_server:  payload_sz= {}", payload_sz);
                h.ip.trim_length_by(payload_sz as u16);
                
                // 60 is the minimum data length (4 bytes FCS not included)
                let trim_by= min(p.data_len()- 60usize, payload_sz as usize);
                p.trim_payload_size(trim_by);
                c.f_seqn=h.tcp.seq_num().wrapping_sub(1);
                set_proxy2server_headers(c, h, pd);
                h.tcp.set_seq_num(c.f_seqn);
                h.tcp.set_syn_flag();
                h.tcp.set_ack_num(0u32);
                h.tcp.unset_ack_flag();
                h.tcp.unset_psh_flag();
                update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                debug!("new SYN packet L2: {}, L3: {}, L4: {}", h.mac, h.ip, p.get_header());
            }
            
   
            fn server_synack_received<M: Sized+ Send>(
                p: &mut Packet<TcpHeader,M>,
                c: &mut Connection, 
                h: &mut HeaderState, 
                producer: &mut MpscProducer,       
            ){
                let delta=c.c_seqn.wrapping_sub(h.tcp.seq_num()); // correction for server side seq numbers
                c.c_seqn=delta;
                make_reply_packet(h);
                h.tcp.unset_syn_flag();
                c.f_seqn=c.f_seqn.wrapping_add(1);
                h.tcp.set_seq_num(c.f_seqn);
                //debug!("data_len= { }, p= { }",p.data_len(), p);
                update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                // we clone the packet and send it via the extra queue 
                // before the delayed request
                // to keep them in sequence
                let p_clone=p.clone();
                //debug!("new ACK packet L2: {}, L3: {}, L4: {}", h.mac, h.ip, p_clone.get_header());
                producer.enqueue_one(p_clone);

                if c.payload.len() > 0 {
                    let mut delayed_ip=new_packet().unwrap() //TODO handle None == out of memory
                        .push_header(h.mac)
                        .unwrap()
                        .push_header(h.ip)
                        .unwrap();
                    delayed_ip.get_mut_header().set_length(
                        h.ip.length() +c.payload.len() as u16);
                    delayed_ip.get_mut_header().update_checksum();
                    //debug!("stored payload.len()= {}, h.ip.length= {}", c.payload.len(), h.ip.length()); 
                    
                    let ip_payload_size= delayed_ip.get_header().payload_size(0);
                    //debug!("ip_payload_size= {}", ip_payload_size);
                    let mut delayed_p=delayed_ip
                        .push_header(h.tcp)
                        .unwrap();
                    delayed_p.copy_payload_from_bytearray(&c.payload);    
                    { 
                        let h_tcp=delayed_p.get_mut_header();
                        h_tcp.set_psh_flag();        
                    }
                    let n_padding_bytes=MIN_FRAME_SIZE-delayed_p.data_len();
                    if n_padding_bytes > 0 {
                        debug!("padding with {} 0x0 bytes", n_padding_bytes);
                        delayed_p.add_padding(n_padding_bytes);
                    }
                    // let sz=delayed_p.payload_size() as u32;
                    // delayed_p.get_mut_header().set_seq_num(c.f_seqn+sz);
                    update_tcp_checksum(
                        &mut delayed_p,
                        ip_payload_size,
                        h.ip.src(),
                        h.ip.dst(),
                    );
                    //debug!("delayed packet: { }", delayed_p);
                    producer.enqueue_one(delayed_p);
                }                            
            }

            let mut group_index=0usize;  // the index of the group to be returned
            let mut producer=producer.clone(); // need to clone here, as this closure is an FnMut

            assert!(p.get_pre_header().is_some()); // we must have parsed the headers
            
            let hs_ip;
            let hs_flow;
            let hs_mac;
            let hs_tcp;

            unsafe {
                // converting to raw pointer avoids to borrow mutably from p
                let ptr = p.get_mut_pre_header().unwrap() as *mut IpHeader;
                hs_ip = &mut *ptr; 
                hs_flow = hs_ip.flow().unwrap();
                let ptr = p.get_mut_pre_pre_header().unwrap() as *mut MacHeader;               
                hs_mac=&mut *ptr;
                let ptr=p.get_mut_header() as *mut TcpHeader;
                hs_tcp = &mut *ptr;
            };
            
            let mut hs = HeaderState {
                mac: hs_mac,
                ip: hs_ip,
                tcp: hs_tcp,
            };
            // if this port is set by the following tcp state machine, the port/connection becomes released afterwards
            let mut release_proxy_sport = None;
            
          
            if hs_flow.dst_port == pd.port {
                //debug!("client to server");
                let key= CKey::Socket(hs_flow.src_socket_addr());
                let mut c= sm.get_mut_or_insert(key).unwrap();
                // we only handle active open on client side:
                // we reset server and client state 
                //TODO revisit this approach
 
                let old_s_state = c.s_state;
                let old_c_state = c.c_state; 
        
                if hs.tcp.syn_flag() {
                    if c.c_state == TcpState::Listen { 
                        c.c_state=TcpState::SynSent;
                        c.s_state=TcpState::Listen;
                        client_syn_received(p, &mut c, &mut hs); // replies with a SYN-ACK to client
                        group_index=1;
                    }
                    else { warn!("received client SYN in state {:?}/{:?}", c.c_state, c.s_state); }                                          
                } 
                else if hs.tcp.ack_flag() && c.c_state == TcpState::SynSent {
                    c.c_state=TcpState::Established;
                    debug!("client side connection established for {:?}", hs_flow.src_socket_addr());
                }
                else if hs.tcp.ack_flag() && c.s_state == TcpState::FinWait {
                    c.c_state = TcpState::CloseWait;
                    c.s_state = TcpState::Closed; 
                    if hs.tcp.fin_flag() { c.c_state = TcpState::LastAck }
                    debug!("transition to client/server state {:?}/{:?}", c.c_state, c.s_state);                                       
                }
                else if c.s_state==TcpState::LastAck && hs.tcp.ack_flag() {
                    // received final ack from client for client initiated close
                    debug!("received final ACK for client initiated close on port {}/{}",
                        hs.tcp.src_port(), c.proxy_sport,
                    );
                    c.s_state= TcpState::Listen;
                    c.c_state= TcpState::Listen;
                    // release connection in the next block after the state machine
                    release_proxy_sport=Some(c.proxy_sport);
                    debug!("releasing connection state for {}/{}", hs.tcp.src_port(), c.proxy_sport);
                }
                else if hs.tcp.fin_flag() {
                    if c.s_state >= TcpState::FinWait {
                        // we got a FIN as a receipt to a sent FIN (server closed connection)
                        debug!("received FIN-reply from client {:?}", hs_flow.src_socket_addr());
                        c.c_state = TcpState::LastAck;
                        c.s_state = TcpState::Closed;                               
                    } else {
                        // client wants to close connection
                        debug!("client sends FIN on port {}/{} in state {:?}/{:?}",
                            hs.tcp.src_port(), c.proxy_sport, c.c_state, c.s_state
                        );
                        if c.s_state >= TcpState::Established {
                            c.c_state = TcpState::FinWait;
                        }
                        // in case the server connection is still not stable, we can only ignore the FIN
                        else { debug!("ignoring FIN request"); group_index=0; }
                    }
                }
                else if c.c_state == TcpState::Established && c.s_state == TcpState::Listen {
                    // should be the first payload packet from client
                    debug!("selecting server after 3 way handshake");
                    select_server(p, &mut c, &mut hs, &pd, &f_select_server);
                    c.s_state= TcpState::SynReceived;
                    group_index= 1; 
                }  
                else if c.s_state < TcpState::Established || c.c_state < TcpState::Established {
                    warn!("unexpected client-side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                        hs.tcp.src_port(), c.proxy_sport, c.c_state, c.s_state,
                    );
                    group_index= 2;
                }           
                
                // once we established a two-way e2e-connection, we always forward the packets
                if old_s_state >= TcpState::Established && old_c_state >= TcpState::Established {                        
                    client_to_server(p, &mut c, &mut hs, &pd, &f_process_payload_c_s);
                    group_index= 1;
                }
            } else {
                // should be server to client
                { 
                    // debug!("looking up state for server side port { }", hs.tcp.dst_port());
                    let mut c = sm.get_mut(CKey::Port(hs.tcp.dst_port()));
                    if c.is_some() {
                        let mut c = c.as_mut().unwrap();
                        let mut b_unexpected=false;
                        let old_s_state = c.s_state;
                        let old_c_state = c.c_state; 
                        
                        if c.s_state == TcpState::SynReceived && hs.tcp.ack_flag() && hs.tcp.syn_flag() {
                            c.s_state= TcpState::Established;
                            debug!("established two-way client server connection");
                            server_synack_received(p, &mut c, &mut hs, &mut producer);
                            group_index=0;  // packets are sent via extra queue
                        }
                        else if hs.tcp.fin_flag() {
                            if c.c_state >= TcpState::FinWait  {
                                // got FIN receipt to a client initiated FIN 
                                debug!("received FIN-reply from server on port {}", hs.tcp.dst_port());
                                c.s_state = TcpState::LastAck;
                                c.c_state = TcpState::Closed;
                            }
                            else { // server initiated TCP close
                                debug!("server closes connection on port {}/{} in state {:?}",
                                    hs.tcp.dst_port(), c.client_sock.port(), c.s_state,
                                ); 
                                c.s_state = TcpState::FinWait;
                            }                           
                        }
                        else if c.c_state==TcpState::LastAck && hs.tcp.ack_flag() {
                            // received final ack from server for server initiated close
                            debug!("received final ACK for server initiated close on port { }", hs.tcp.dst_port());
                            c.s_state= TcpState::Listen;
                            c.c_state= TcpState::Listen;
                            // release connection in the next block
                            release_proxy_sport=Some(c.proxy_sport);
                        }
                        else {
                            // debug!("received from server { } in c/s state {:?}/{:?} ", hs.tcp, c.c_state, c.s_state);
                            b_unexpected=true; //  except we revise it, see below
                        } 

                         // once we established a two-way e2e-connection, we always forward the packets
                        if old_s_state >= TcpState::Established && old_c_state >= TcpState::Established {                        
                            // this is the s->c part of the stable two-way connection state
                            // translate packets and forward to client
                            server_to_client(p, &mut c, &mut hs, &pd);
                            group_index=1;
                            b_unexpected=false; 
                        }
                         
                        if b_unexpected {
                            warn!("unexpected server side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                                hs.tcp.dst_port(), c.client_sock.port(), c.c_state, c.s_state,
                            );
                            group_index= 2;
                        }
                        
                    } else {
                        warn!("proxy port has no state, sending to KNI i/f");
                        // we send this to KNI which handles out-of-order TCP, e.g. by sending RST
                        group_index=2;
                    }
                    
                }
            }
            // here we check if we shall release the connection state,
            // required because of borrow checker for the state manager sm
            if let Some(release_proxy_sport) = release_proxy_sport {
                 debug!("releasing port {}", release_proxy_sport);
                sm.release_port(release_proxy_sport);                            
            }
            do_ttl(&mut hs);           
            group_index
        }, sched);


    let l2kniflow = l2groups.get_group(0).unwrap().compose();
    let l4kniflow = l4groups.get_group(2).unwrap().compose();
    let pipe2kni = merge(vec![l2kniflow, l4kniflow]).send(kni.clone());
    let l4pciflow = l4groups.get_group(1).unwrap().compose();
    let l4dumpflow = l4groups
        .get_group(0)
        .unwrap()
        .filter(box move |_| false)
        .compose();
    let pipe2pci = merge(vec![l4pciflow, l4dumpflow]).send(pci.clone());
    sched.add_task(pipe2kni).unwrap();
    sched.add_task(pipe2pci).unwrap();
    sched.add_task(consumer.send(pci.clone())).unwrap();

}
