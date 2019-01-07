use e2d2::operators::{ReceiveBatch, Batch, merge_auto, SchedulingPolicy};
use e2d2::scheduler::{Runnable, Scheduler, StandaloneScheduler};
use e2d2::allocators::CacheAligned;
use e2d2::headers::{IpHeader, MacHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::utils::finalize_checksum;
use e2d2::queues::{new_mpsc_queue_pair, MpscProducer};
use e2d2::headers::EndOffset;
use e2d2::utils;
use e2d2::common::EmptyMetadata;

use std::sync::Arc;
#[cfg(feature = "profiling")]
use std::sync::atomic::Ordering;
use std::cmp::min;
use std::sync::mpsc::{Sender, channel};
use std::collections::HashMap;

//use eui48::MacAddress;
//use ipnet::Ipv4Net;
use uuid::Uuid;
use rand;
//use separator::Separatable;

use cmanager::{Connection, ConnectionManager};
use netfcts::timer_wheel::TimerWheel;
use netfcts::system::SystemData;
use netfcts::tcp_common::*;
use netfcts::tasks;
use netfcts::tasks::private_etype;
#[cfg(feature = "profiling")]
use netfcts::TimeAdder;

use EngineConfig;
use {PipelineId, MessageFrom, MessageTo, TaskType};
use Timeouts;
use is_kni_core;

const MIN_FRAME_SIZE: usize = 60; // without fcs

pub fn setup_forwarder<F1, F2>(
    core: i32,
    pci: &CacheAligned<PortQueue>,
    kni: &CacheAligned<PortQueue>,
    sched: &mut StandaloneScheduler,
    engine_config: &EngineConfig,
    servers: Vec<L234Data>,
    flowdirector_map: HashMap<i32, Arc<FlowDirector>>,
    tx: Sender<MessageFrom>,
    system_data: SystemData,
    f_select_server: F1,
    f_process_payload_c_s: F2,
) where
    F1: Fn(&mut Connection) + Sized + Send + Sync + 'static,
    F2: Fn(&mut Connection, &mut [u8], usize) + Sized + Send + Sync + 'static,
{
    let l4flow_for_this_core = flowdirector_map.get(&pci.port.port_id()).unwrap().get_flow(pci.rxq());

    #[derive(Clone)]
    struct Me {
        // contains the client side ip address
        l234: L234Data,
        // server side ip address to use in this pipeline
        ip_s: u32,
    }

    let me = Me { l234: engine_config.get_l234data(), ip_s: l4flow_for_this_core.ip };

    let pipeline_id = PipelineId {
        core: core as u16,
        port_id: pci.port.port_id() as u16,
        rxq: pci.rxq(),
    };
    debug!("enter setup_forwarder {}", pipeline_id);

    let mut cm: ConnectionManager = ConnectionManager::new(
        pci.clone(),
        l4flow_for_this_core,
    );

    let timeouts = Timeouts::default_or_some(&engine_config.timeouts);
    let mut wheel = TimerWheel::new(128, system_data.cpu_clock / 10, 128);

    // we need this queue for the delayed bindrequest
    let (producer, consumer) = new_mpsc_queue_pair();

    // setting up a a reverse message channel between this pipeline and the main program thread
    debug!("{} setting up reverse channel", pipeline_id);
    let (remote_tx, rx) = channel::<MessageTo>();
    // we send the transmitter to the remote receiver of our messages
    tx.send(MessageFrom::Channel(pipeline_id.clone(), remote_tx)).unwrap();

    // forwarding frames coming from KNI to PCI, if we are the kni core
    if is_kni_core(pci) {
        let forward2pci = ReceiveBatch::new(kni.clone())
            .parse::<MacHeader>()
            .send(pci.clone());
        let uuid = Uuid::new_v4();
        let name = String::from("Kni2Pci");
        sched.add_runnable(Runnable::from_task(uuid, name, forward2pci).move_ready());
    }

    let thread_id = format!("<c{}, rx{}>: ", core, pci.rxq());
    let tcp_min_port = cm.tcp_port_base();
    let me_clone = me.clone();
    let tx_clone = tx.clone();
    let pipeline_ip = cm.ip();
    let pipeline_id_clone = pipeline_id.clone();
    let mut counter_c = TcpCounter::new();
    let mut counter_s = TcpCounter::new();
    #[cfg(feature = "profiling")]
        let mut rx_tx_stats = Vec::with_capacity(1000);

    // set up the generator producing timer tick packets with our private EtherType
    let (producer_timerticks, consumer_timerticks) = new_mpsc_queue_pair();
    let tick_generator = tasks::TickGenerator::new(producer_timerticks, &me.l234, system_data.cpu_clock / 100); // 10 ms
    assert!(wheel.resolution() > tick_generator.tick_length());
    let wheel_tick_reduction_factor = wheel.resolution() / tick_generator.tick_length();
    let mut ticks = 0;
    let uuid_tick_generator = tasks::install_task(sched, "TickGenerator", tick_generator);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_tick_generator, TaskType::TickGenerator))
        .unwrap();

    let receive_pci = ReceiveBatch::new(pci.clone());
    let l2_input_stream = merge_auto(
        vec![consumer_timerticks.set_urgent().compose(), receive_pci.compose()],
        SchedulingPolicy::LongestQueue,
    );

    // group 0 -> dump packets
    // group 1 -> send to PCI
    // group 2 -> send to KNI
    let csum_offload = pci.port.csum_offload();
    let uuid_l4groupby = Uuid::new_v4();
    #[cfg(feature = "profiling")]
        let tx_stats = pci.tx_stats();
    #[cfg(feature = "profiling")]
        let rx_stats = pci.rx_stats();
    // process TCP traffic addressed to Proxy
    #[cfg(feature = "profiling")]
        let mut time_adders = [
        TimeAdder::new("select_server", 9000),
        TimeAdder::new("SYN - SYN-ACK", 9000),
        TimeAdder::new("connection lookup", 9000),
    ];
    let mut l4groups = l2_input_stream
        .parse::<MacHeader>()
        .group_by(
            3,
            box move |p_closure| {
                // this is the major closure for TCP processing
                struct HeaderState<'a> {
                    mac: &'a mut MacHeader,
                    ip: &'a mut IpHeader,
                    tcp: &'a mut TcpHeader,
                }

                impl<'a> HeaderState<'a> {
                    #[inline]
                    fn set_dst_socket(&mut self, ip: u32, port: u16) {
                        self.ip.set_dst(ip);
                        self.tcp.set_dst_port(port);
                    }
                }

                #[inline]
                fn do_ttl(h: &mut HeaderState) {
                    let ttl = h.ip.ttl();
                    if ttl >= 1 {
                        h.ip.set_ttl(ttl - 1);
                    }
                    h.ip.update_checksum();
                }

                #[inline]
                fn make_reply_packet(h: &mut HeaderState) {
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
                    let ack_num = h.tcp.seq_num().wrapping_add(1);
                    h.tcp.set_ack_num(ack_num);
                }

                // remove tcp options for SYN and SYN-ACK,
                // pre-requisite: no payload exists, because any payload is not shifted up
                #[inline]
                fn remove_tcp_options<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, h: &mut HeaderState) {
                    let old_offset = h.tcp.offset() as u16;
                    if old_offset > 20 {
                        trace!("trimming tcp-options by { } bytes", old_offset - 20);
                        h.tcp.set_data_offset(5u8);
                        // minimum mbuf data length is 60 bytes
                        h.ip.trim_length_by(old_offset - 20u16);
                        let trim_by = min(p.data_len() - 60usize, (old_offset - 20u16) as usize);
                        p.trim_payload_size(trim_by);
                        h.ip.update_checksum();
                    }
                }


                #[inline]
                fn client_syn_received(p: &mut Packet<TcpHeader, EmptyMetadata>, c: &mut Connection, h: &mut HeaderState) {
                    c.con_rec_c.push_state(TcpState::SynSent);
                    c.client_mac = h.mac.clone();
                    c.set_client_sock((h.ip.src(), h.tcp.src_port()));
                    // debug!("checksum in = {:X}",p.get_header().checksum());
                    remove_tcp_options(p, h);
                    make_reply_packet(h);
                    //generate seq number:
                    c.c_seqn = rand::random::<u32>();
                    h.tcp.set_seq_num(c.c_seqn);
                    c.ackn_p2c = h.tcp.ack_num();
                    update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                }

                #[inline]
                fn set_header(server: &L234Data, port: u16, h: &mut HeaderState, me: &Me) {
                    h.mac.set_dmac(&server.mac);
                    h.mac.set_smac(&me.l234.mac);
                    h.set_dst_socket(server.ip, server.port);
                    h.ip.set_src(me.ip_s);
                    h.tcp.set_src_port(port);
                    h.ip.update_checksum();
                }
                /*
                            #[inline]
                            fn set_proxy2server_headers(c: &mut Connection, h: &mut HeaderState, pd: &L234Data, ip_src: u32) {
                                if c.server.is_none() {
                                    error!("no server set: {}", c);
                                }
                                h.mac.set_dmac(&c.server.as_ref().unwrap().mac);
                                h.mac.set_smac(&pd.mac);
                                let l2l3 = &c.server.as_ref().unwrap();
                                h.set_dst_socket(l2l3.ip, l2l3.port);
                                h.ip.set_src(ip_src);
                                h.tcp.set_src_port(c.port());
                            }
                */
                fn client_to_server<M: Sized + Send, F>(
                    p: &mut Packet<TcpHeader, M>,
                    c: &mut Connection,
                    h: &mut HeaderState,
                    me: &Me,
                    servers: &Vec<L234Data>,
                    f_process_payload: F,
                ) where
                    F: Fn(&mut Connection, &mut [u8], usize),
                {
                    let ip_client = h.ip.src();
                    let old_ip_dst = h.ip.dst();
                    let port_client = h.tcp.src_port();
                    let server = &servers[c.con_rec_s.server_index];

                    if tcp_payload_size(p) > 0 {
                        let tailroom = p.get_tailroom();
                        f_process_payload(c, p.get_mut_payload(), tailroom);
                        //if port_client == OBSERVE_PORT { info!("client_to_server: payload size {}", p.payload_size()) };
                    }

                    set_header(&servers[c.con_rec_s.server_index], c.port(), h, me);
                    h.tcp.update_checksum_incremental(port_client, c.port());
                    h.tcp.update_checksum_incremental(me.l234.port, server.port);
                    h.tcp.update_checksum_incremental(
                        !finalize_checksum(ip_client),
                        !finalize_checksum(me.ip_s),
                    );
                    h.tcp.update_checksum_incremental(
                        !finalize_checksum(old_ip_dst),
                        !finalize_checksum(server.ip),
                    );
                    // adapt ackn of client packet
                    let oldackn = h.tcp.ack_num();
                    let newackn = oldackn.wrapping_sub(c.c_seqn);
                    let oldseqn = h.tcp.seq_num();
                    let newseqn = oldseqn.wrapping_add(c.c2s_inserted_bytes as u32);
                    if c.c2s_inserted_bytes != 0 {
                        h.tcp.set_seq_num(newseqn);
                        h.tcp.update_checksum_incremental(!finalize_checksum(oldseqn), !finalize_checksum(newseqn));
                    }
                    h.tcp.set_ack_num(newackn);
                    c.ackn_p2s = newackn;
                    if h.tcp.fin_flag() { c.seqn_fin_p2s = newseqn; }
                    h.tcp.update_checksum_incremental(!finalize_checksum(oldackn), !finalize_checksum(newackn));
                    //if port_client == OBSERVE_PORT { info!("client_to_server: {}", utils::rdtsc_unsafe().separated_string()) }
                    //debug!("translated c->s: { }, L4: { }", p, p.get_header());
                }

                fn server_to_client<M: Sized + Send>(
                    // we will need p once s->c payload inspection is required
                    _p: &mut Packet<TcpHeader, M>,
                    c: &mut Connection,
                    h: &mut HeaderState,
                    me: &Me,
                ) {
                    //if c.get_client_sock().unwrap().port() == OBSERVE_PORT { info!("server_to_client pos 0: {}", utils::rdtsc_unsafe().separated_string()) }
                    // this is the s->c part of the stable two-way connection state
                    // translate packets and forward to client
                    h.mac.set_dmac(&c.client_mac.src);
                    h.mac.set_smac(&me.l234.mac);
                    let ip_server = h.ip.src();
                    let old_dest_ip = h.ip.dst();
                    h.ip.set_dst(c.get_client_sock().unwrap().0);
                    h.ip.set_src(me.l234.ip);
                    let server_src_port = h.tcp.src_port();
                    h.tcp.set_src_port(me.l234.port);
                    h.tcp.set_dst_port(c.get_client_sock().unwrap().1);
                    h.tcp.update_checksum_incremental(server_src_port, me.l234.port);
                    h.tcp.update_checksum_incremental(c.port(), c.get_client_sock().unwrap().1);
                    h.tcp.update_checksum_incremental(
                        !finalize_checksum(ip_server),
                        !finalize_checksum(me.l234.ip),
                    );
                    //if c.get_client_sock().unwrap().port() == OBSERVE_PORT { info!("server_to_client pos 1: {}", utils::rdtsc_unsafe().separated_string()) }
                    h.tcp.update_checksum_incremental(
                        !finalize_checksum(old_dest_ip),
                        !finalize_checksum(c.get_client_sock().unwrap().0),
                    );
                    // adapt seqn and ackn from server packet
                    let oldseqn = h.tcp.seq_num();
                    let newseqn = oldseqn.wrapping_add(c.c_seqn);
                    let oldackn = h.tcp.ack_num();
                    let newackn = oldackn.wrapping_sub(c.c2s_inserted_bytes as u32);
                    if c.c2s_inserted_bytes != 0 {
                        h.tcp.set_ack_num(newackn);
                        h.tcp.update_checksum_incremental(!finalize_checksum(oldackn), !finalize_checksum(newackn));
                    }
                    h.tcp.set_seq_num(newseqn);
                    if h.tcp.fin_flag() { c.seqn_fin_p2c = newseqn; }
                    c.ackn_p2c = newackn;
                    h.tcp.update_checksum_incremental(!finalize_checksum(oldseqn), !finalize_checksum(newseqn));
                    //if c.get_client_sock().unwrap().port() == OBSERVE_PORT { info!("server_to_client pos 2: {}", utils::rdtsc_unsafe().separated_string()) }
                    //debug!("translated s->c: {}", p);
                }

                #[inline]
                fn read_headers(p: &mut Packet<TcpHeader, EmptyMetadata>) -> HeaderState {
                    HeaderState {
                        ip: unsafe { &mut *(p.get_mut_pre_header().unwrap() as *mut IpHeader) },
                        mac: unsafe { &mut *(p.get_mut_pre_pre_header().unwrap() as *mut MacHeader) },
                        tcp: unsafe { &mut *(p.get_mut_header() as *mut TcpHeader) },
                    }
                }

                // attention: after calling select_server, p_closure points to a different mbuf, while p and h refer to the original mbuf
                fn select_server<F>(
                    p: &mut Packet<TcpHeader, EmptyMetadata>,
                    c: &mut Connection,
                    h: &mut HeaderState,
                    p_closure: &mut Packet<MacHeader, EmptyMetadata>,
                    me: &Me,
                    servers: &Vec<L234Data>,
                    f_select_server: &F,
                ) where
                    F: Fn(&mut Connection),
                {
                    // save clone of payload packet to connection state
                    let p_clone = p.clone(); // creates reference to the mbuf in p
                    let payload_sz = tcp_payload_size(&p_clone);
                    c.payload_packet = Some(p_clone);
                    f_select_server(c);
                    c.c2s_inserted_bytes = tcp_payload_size(c.payload_packet.as_ref().unwrap()) as isize - payload_sz as isize;

                    // set the header for the selected server in the payload packet p and its clone p_clone
                    set_header(&servers[c.con_rec_s.server_index], c.port(), h, me);
                    // create a brand new mac frame with a new mbuf, using the adapted MAC header. It later becomes our SYN packet
                    let syn = new_packet().unwrap().push_header(h.mac).unwrap();
                    // this is a little bit tricky: we replace the borrowed packet of the closure, with the new mac frame
                    let mut old_p = unsafe { p_closure.replace(syn) };
                    old_p.dereference_mbuf(); // as p_closure no longer references the original mbuf

                    // the new syn packet is the parsed proxy for p_closure (as we cannot push headers on the borrowed p_closure itself)
                    let mut syn = p_closure.clone_without_ref_counting().push_header(h.ip).unwrap().push_header(h.tcp).unwrap();
                    let ip_payload_size;
                    let ip_src;
                    let ip_dst;
                    { // need this block as we borrow syn mutably
                        // recreate the header state for the new p_closure
                        let h = read_headers(&mut syn);

                        h.ip.trim_length_by(payload_sz as u16);
                        h.ip.update_checksum();

                        c.f_seqn = h.tcp.seq_num().wrapping_sub(1);
                        h.tcp.set_seq_num(c.f_seqn);
                        h.tcp.set_syn_flag();
                        h.tcp.set_ack_num(0u32);
                        h.tcp.unset_ack_flag();
                        h.tcp.unset_psh_flag();
                        ip_payload_size = h.ip.payload_size(0);
                        ip_src = h.ip.src();
                        ip_dst = h.ip.dst();
                    }
                    update_tcp_checksum(&mut syn, ip_payload_size, ip_src, ip_dst);
                }

                fn server_synack_received(
                    p: &mut Packet<TcpHeader, EmptyMetadata>,
                    c: &mut Connection,
                    h: &mut HeaderState,
                    producer: &mut MpscProducer,
                ) {
                    // correction for server side seq numbers
                    let delta = c.c_seqn.wrapping_sub(h.tcp.seq_num());
                    c.c_seqn = delta;
                    remove_tcp_options(p, h);
                    make_reply_packet(h);
                    h.tcp.unset_syn_flag();
                    c.f_seqn = c.f_seqn.wrapping_add(1);
                    h.tcp.set_seq_num(c.f_seqn);
                    //debug!("data_len= { }, p= { }",p.data_len(), p);
                    update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
                    // we clone the packet and send it via the extra queue, the original p gets discarded
                    let p_clone = p.clone();
                    trace!("last ACK of three way handshake towards server: L4: {}", p_clone.get_header());
                    producer.enqueue_one(p_clone);

                    if c.payload_packet.is_some() {
                        let mut payload_packet = c.payload_packet.take().unwrap();
                        payload_packet.replace_header(h.tcp);  // same tcp header as in Ack packet
                        /*
                        let mut delayed_ip = new_packet().unwrap().push_header(h.mac).unwrap().push_header(h.ip).unwrap();
                        delayed_ip.get_mut_header().set_length(h.ip.length() + c.payload.len() as u16);
                        delayed_ip.get_mut_header().update_checksum();
                        //debug!("stored payload.len()= {}, h.ip.length= {}",
                        // c.payload.len(), h.ip.length());

                        let ip_payload_size = delayed_ip.get_header().payload_size(0);
                        //debug!("ip_payload_size= {}", ip_payload_size);
                        let mut delayed_p = delayed_ip.push_header(h.tcp).unwrap();
                        delayed_p.copy_payload_from_u8_slice(&c.payload);
                        */
                        {
                            let h_tcp = payload_packet.get_mut_header();
                            h_tcp.set_psh_flag();
                        }

                        if payload_packet.data_len() < MIN_FRAME_SIZE {
                            let n_padding_bytes = MIN_FRAME_SIZE - payload_packet.data_len();
                            debug!("padding with {} 0x0 bytes", n_padding_bytes);
                            payload_packet.add_padding(n_padding_bytes);
                        }
                        // let sz=delayed_p.payload_size() as u32;
                        // delayed_p.get_mut_header().set_seq_num(c.f_seqn+sz);
                        let ip_payload_size = payload_packet.get_pre_header().unwrap().payload_size(0);
                        update_tcp_checksum(&mut payload_packet, ip_payload_size, h.ip.src(), h.ip.dst());
                        c.ackn_p2s = h.tcp.ack_num();
                        trace!("delayed packet: { }", payload_packet.get_header());
                        assert_eq!(payload_packet.refcnt(), 1);
                        producer.enqueue_one(payload_packet);
                    }
                }

// *****  the closure starts here with processing

                #[cfg(feature = "profiling")]
                    let timestamp_entry = utils::rdtsc_unsafe();

                // need to clone here, as this closure must be an FnMut, not only FnOnce:
                let mut producer = producer.clone();

                // we must do the parsing on a clone of the borrowed packet, as we need to move it for this
                // we release the clone within this closure, so we do not care about mbuf refcount
                let p_mac = p_closure.clone_without_ref_counting();
                let b_private_etype = private_etype(&p_closure.get_header().etype());
                if !b_private_etype {
                    let header = p_mac.get_header();
                    if header.dst != me.l234.mac && !header.dst.is_multicast() && !header.dst.is_broadcast() {
                        debug!("{} from pci: discarding because mac unknown: {} ", thread_id, &header);
                        return 0;
                    }
                    if header.etype() != 0x0800 && !b_private_etype {
                        // everything other than Ipv4 or our own packets we send to KNI, i.e. group 2
                        return 2;
                    }
                }
                let p_ip = p_mac.parse_header::<IpHeader>();
                if !b_private_etype {
                    let iph = p_ip.get_header();
                    // everything other than TCP, and everything not addressed to us we send to KNI, i.e. group 2
                    if iph.protocol() != 6 || iph.dst() != pipeline_ip && iph.dst() != me.l234.ip {
                        return 2;
                    }
                }
                let p = &mut p_ip.parse_header::<TcpHeader>();

                let mut group_index = 0usize; // the index of the group to be returned, default 0: dump packet
                if csum_offload {
                    p.set_tcp_ipv4_checksum_tx_offload();
                }

                // converting to raw pointer avoids to borrow mutably from p
                // therefore we also cannot use read_headers here
                // this is bad Rust code and we should re-visit this, once we re-design the header parsing in packet.rs of NetBricks
                let mut hs = HeaderState {
                    ip: unsafe { &mut *(p.get_mut_pre_header().unwrap() as *mut IpHeader) },
                    mac: unsafe { &mut *(p.get_mut_pre_pre_header().unwrap() as *mut MacHeader) },
                    tcp: unsafe { &mut *(p.get_mut_header() as *mut TcpHeader) },
                };

                if !b_private_etype && hs.tcp.dst_port() != me_clone.l234.port && hs.tcp.dst_port() < tcp_min_port {
                    return 2;
                }

                let src_sock = (hs.ip.src(), hs.tcp.src_port());

                // if set by the following tcp state machine,
                // the port/connection becomes released afterwards
                // this is cumbersome, but we must make the  borrow checker happy
                let mut release_connection = None;
                // check if we got a packet from generator
                match hs.mac.etype() {
                    tasks::PRIVATE_ETYPE_PACKET => {}
                    tasks::PRIVATE_ETYPE_TIMER => {
                        ticks += 1;
                        match rx.try_recv() {
                            Ok(MessageTo::FetchCounter) => {
                                debug!("{}: received FetchCounter", pipeline_id_clone);
                                #[cfg(feature = "profiling")]
                                    tx_clone
                                        .send(MessageFrom::Counter(
                                            pipeline_id_clone.clone(),
                                            counter_c.clone(),
                                            counter_s.clone(),
                                            Some(rx_tx_stats.clone()),
                                        )).unwrap();
                                #[cfg(not (feature = "profiling"))]
                                    tx_clone
                                        .send(MessageFrom::Counter(
                                            pipeline_id_clone.clone(),
                                            counter_c.clone(),
                                            counter_s.clone(),
                                            None,
                                        )).unwrap();
                            }
                            Ok(MessageTo::FetchCRecords) => {
                                debug!("{}: received FetchCRecords", pipeline_id_clone);
                                cm.record_uncompleted();
                                let c_recs = cm.fetch_c_records();
                                tx_clone
                                    .send(MessageFrom::CRecords(pipeline_id_clone.clone(), c_recs.0, c_recs.1))
                                    .unwrap();
                            }
                            _ => {}
                        }
                        // check for timeouts
                        // debug!("ticks = {}", ticks);
                        if ticks % wheel_tick_reduction_factor == 0 {
                            trace!("checking timeouts");
                            cm.release_timeouts(&utils::rdtsc_unsafe(), &mut wheel);
                        }
                        #[cfg(feature = "profiling")]
                            {   //save stats
                                let tx_stats_now = tx_stats.stats.load(Ordering::Relaxed);
                                let rx_stats_now = rx_stats.stats.load(Ordering::Relaxed);
                                // only save changes
                                if rx_tx_stats.last().is_none() || tx_stats_now != rx_tx_stats.last().unwrap().1 {
                                    rx_tx_stats.push((utils::rdtsc_unsafe(), rx_stats_now, tx_stats_now));
                                }
                            }
                    }
                    _ => {
                        if hs.tcp.dst_port() == me.l234.port {
                            //trace!("client to server");
                            let opt_c = if hs.tcp.syn_flag() {
                                cm.get_mut_or_insert(&src_sock)
                            } else {
                                cm.get_mut_by_sock(&src_sock)
                            };

                            if hs.tcp.syn_flag() {
                                #[cfg(feature = "profiling")]
                                    time_adders[1].add(utils::rdtsc_unsafe() - timestamp_entry);
                            } else {
                                #[cfg(feature = "profiling")]
                                    time_adders[2].add(utils::rdtsc_unsafe() - timestamp_entry)
                            }

                            if opt_c.is_none() {
                                warn!("{} unexpected client side packet (seq={}): no state for socket ({}, {}), sending to KNI i/f", thread_id, hs.tcp.seq_num(), src_sock.0, src_sock.1);
                            } else {
                                let mut c = opt_c.unwrap();
                                // we only handle active open on client side:
                                // we reset server and client state
                                //TODO revisit this approach
                                let old_s_state = c.con_rec_s.last_state().clone();
                                let old_c_state = c.con_rec_c.last_state().clone();

                                //check seqn
                                if old_c_state != TcpState::Closed && hs.tcp.seq_num() < c.ackn_p2c {
                                    let diff = hs.tcp.seq_num() as i64 - c.ackn_p2c as i64;
                                    //  a re-sent packet ?
                                    debug!("{} state= {:?}, diff= {}, tcp= {}", thread_id, old_s_state, diff, hs.tcp);
                                } else if hs.tcp.syn_flag() {
                                    if old_c_state == TcpState::Closed {
                                        // replies with a SYN-ACK to client:
                                        client_syn_received(p, &mut c, &mut hs);
                                        trace!("{} (SYN-)ACK to client, L3: { }, L4: { }", thread_id, hs.ip, hs.tcp);
                                        counter_c[TcpStatistics::RecvSyn] += 1;
                                        counter_c[TcpStatistics::SentSynAck] += 1;

                                        wheel.schedule(&(timeouts.established.unwrap() * system_data.cpu_clock / 1000), c.port());
                                        group_index = 1;
                                    } else {
                                        warn!("received client SYN in state {:?}/{:?}", c.con_rec_c.states(), c.con_rec_s.states());
                                    }
                                } else if hs.tcp.ack_flag() && old_c_state == TcpState::SynSent {
                                    c.client_con_established();
                                    counter_c[TcpStatistics::RecvSynAck2] += 1;
                                } else if hs.tcp.fin_flag() {
                                    if old_s_state >= TcpState::FinWait1 { // server in active close, client in passive or also active close

                                        if hs.tcp.ack_flag() && hs.tcp.ack_num() == c.seqn_fin_p2c.wrapping_add(1) {
                                            counter_c[TcpStatistics::RecvFinAck] += 1;
                                            counter_s[TcpStatistics::SentFinAck] += 1;
                                            c.con_rec_c.released(ReleaseCause::PassiveClose);
                                            c.con_rec_c.push_state(TcpState::LastAck);
                                        } else { // no ACK
                                            counter_c[TcpStatistics::RecvFin] += 1;
                                            counter_s[TcpStatistics::SentFin] += 1;
                                            c.con_rec_c.released(ReleaseCause::ActiveClose);
                                            c.con_rec_c.push_state(TcpState::Closing); //will still receive FIN of server
                                            if old_s_state == TcpState::FinWait1 {
                                                c.con_rec_s.push_state(TcpState::Closing);
                                            } else if old_s_state == TcpState::FinWait2 {
                                                c.con_rec_s.push_state(TcpState::Closed)
                                            }
                                        }
                                        group_index = 1;
                                    } else { // client in active close
                                        c.con_rec_c.released(ReleaseCause::ActiveClose);
                                        counter_c[TcpStatistics::RecvFin] += 1;
                                        c.con_rec_c.push_state(TcpState::FinWait1);
                                        if old_s_state < TcpState::Established {
                                            // in case the server connection is still not established
                                            // proxy must close connection and sends Fin-Ack to client
                                            make_reply_packet(&mut hs);
                                            hs.tcp.set_ack_flag();
                                            c.c_seqn = c.c_seqn.wrapping_add(1);
                                            hs.tcp.set_seq_num(c.c_seqn);
                                            //debug!("data_len= { }, p= { }",p.data_len(), p);
                                            update_tcp_checksum(p, hs.ip.payload_size(0), hs.ip.src(), hs.ip.dst());
                                            c.con_rec_s.push_state(TcpState::LastAck); // pretend that server received the FIN
                                            c.con_rec_s.released(ReleaseCause::PassiveClose);
                                            counter_c[TcpStatistics::SentFinAck] += 1;
                                            c.seqn_fin_p2c = hs.tcp.seq_num();
                                            //TODO send restart to server?
                                            trace!("FIN-ACK to client, L3: { }, L4: { }", hs.ip, hs.tcp);
                                        } else {
                                            counter_s[TcpStatistics::SentFin] += 1;
                                        }
                                        group_index = 1;
                                    }
                                } else if hs.tcp.rst_flag() {
                                    trace!("received RST");
                                    counter_c[TcpStatistics::RecvRst] += 1;
                                    c.con_rec_c.push_state(TcpState::Closed);
                                    c.con_rec_c.released(ReleaseCause::ActiveRst);
                                    release_connection = Some(c.port());
                                } else if hs.tcp.ack_flag() && hs.tcp.ack_num() == c.seqn_fin_p2c.wrapping_add(1) && old_s_state >= TcpState::FinWait1 {
                                    // ACK from client for FIN of Server
                                    match old_s_state {
                                        TcpState::FinWait1 => { c.con_rec_s.push_state(TcpState::FinWait2); }
                                        TcpState::Closing => { c.con_rec_s.push_state(TcpState::Closed); }
                                        _ => {}
                                    }
                                    match old_c_state {
                                        TcpState::Established => { c.con_rec_c.push_state(TcpState::CloseWait) }
                                        TcpState::FinWait1 => { c.con_rec_c.push_state(TcpState::Closing) }
                                        TcpState::FinWait2 => { c.con_rec_c.push_state(TcpState::Closed) }
                                        _ => {}
                                    }
                                    counter_c[TcpStatistics::RecvFinAck2] += 1;
                                    counter_s[TcpStatistics::SentFinAck2] += 1;
                                } else if old_s_state == TcpState::LastAck && hs.tcp.ack_flag() && hs.tcp.ack_num() == c.seqn_fin_p2c.wrapping_add(1) {
                                    // received final ack from client for client initiated close
                                    trace!(
                                        "{} received final ACK for client initiated close on port {}/{}",
                                        thread_id,
                                        hs.tcp.src_port(),
                                        c.port(),
                                    );
                                    c.con_rec_s.push_state(TcpState::Closed);
                                    c.con_rec_c.push_state(TcpState::Closed);
                                    counter_c[TcpStatistics::RecvFinAck2] += 1;
                                    counter_s[TcpStatistics::SentFinAck2] += 1;
                                } else if old_c_state == TcpState::Established
                                    && old_s_state == TcpState::Listen {
                                    // should be the first payload packet from client
                                    select_server(p, &mut c, &mut hs, p_closure, &me, &servers, &f_select_server);
                                    #[cfg(feature = "profiling")]
                                        time_adders[1].add(utils::rdtsc_unsafe() - timestamp_entry);
                                    debug!("{} SYN packet to server - L3: {}, L4: {}", thread_id, hs.ip, p.get_header());
                                    c.con_rec_s.push_state(TcpState::SynReceived);
                                    counter_c[TcpStatistics::Payload] += 1;
                                    counter_s[TcpStatistics::SentSyn] += 1;
                                    group_index = 1;
                                } else if old_s_state < TcpState::SynReceived || old_c_state < TcpState::Established {
                                    warn!(
                                        "{} unexpected client-side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                                        thread_id,
                                        hs.tcp.src_port(),
                                        c.port(),
                                        c.con_rec_c.states(),
                                        c.con_rec_s.states(),
                                    );
                                    counter_c[TcpStatistics::Unexpected] += 1;
                                    group_index = 2;
                                }

                                if *c.con_rec_c.last_state() == TcpState::Closed && *c.con_rec_s.last_state() == TcpState::Closed {
                                    release_connection = Some(c.port());
                                }

                                // once we established a two-way e2e-connection, we always forward the packets
                                if old_s_state >= TcpState::Established && old_s_state < TcpState::Closed
                                    && old_c_state >= TcpState::Established {
                                    client_to_server(p, &mut c, &mut hs, &me, &servers, &f_process_payload_c_s);
                                    group_index = 1;
                                }
                            }
                        } else {
                            // server to client
                            {
                                //debug!("looking up state for server side port { }", hs.tcp.dst_port());
                                let mut c = cm.get_mut_by_port(hs.tcp.dst_port());
                                if c.is_some() {
                                    let mut c = c.as_mut().unwrap();
                                    let mut b_unexpected = false;
                                    let old_s_state = c.con_rec_s.last_state().clone();
                                    let old_c_state = c.con_rec_c.last_state().clone();

                                    if hs.tcp.ack_flag() && hs.tcp.syn_flag() {
                                        counter_s[TcpStatistics::RecvSynAck] += 1;
                                        if old_s_state == TcpState::SynReceived {
                                            c.server_con_established();
                                            debug!("{} established two-way client server connection, SYN-ACK received: L3: {}, L4: {}", thread_id, hs.ip, hs.tcp);
                                            server_synack_received(p, &mut c, &mut hs, &mut producer);
                                            counter_s[TcpStatistics::SentSynAck2] += 1;
                                            counter_s[TcpStatistics::Payload] += 1;
                                            group_index = 0; // delayed payload packets are sent via extra queue
                                        } else {
                                            warn!("{} received SYN-ACK in wrong state: {:?}", thread_id, old_s_state);
                                            group_index = 0;
                                        }
                                    } else if hs.tcp.fin_flag() {
                                        if old_c_state >= TcpState::FinWait1 {
                                            if hs.tcp.ack_flag() && hs.tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) {
                                                counter_s[TcpStatistics::RecvFinAck] += 1;
                                                counter_c[TcpStatistics::SentFinAck] += 1;
                                                trace!("{} received FIN-reply from server on proxy port {}", thread_id, hs.tcp.dst_port());
                                                c.con_rec_s.released(ReleaseCause::PassiveClose);
                                                c.con_rec_s.push_state(TcpState::LastAck);
                                            } else {
                                                trace!("simultaneous active close from server on port {}", hs.tcp.dst_port());
                                                counter_s[TcpStatistics::RecvFin] += 1;
                                                counter_c[TcpStatistics::SentFin] += 1;
                                                c.con_rec_s.released(ReleaseCause::ActiveClose);
                                                c.con_rec_s.push_state(TcpState::Closing);
                                                if old_c_state == TcpState::FinWait1 {
                                                    c.con_rec_c.push_state(TcpState::Closing);
                                                } else if old_c_state == TcpState::FinWait2 {
                                                    c.con_rec_c.push_state(TcpState::Closed)
                                                }
                                            }
                                        } else {
                                            // server initiated TCP close
                                            trace!(
                                                "{} server closes connection on port {}/{} in state {:?}",
                                                thread_id,
                                                hs.tcp.dst_port(),
                                                c.get_client_sock().unwrap().1,
                                                c.con_rec_s.states(),
                                            );
                                            c.con_rec_s.push_state(TcpState::FinWait1);
                                            c.con_rec_s.released(ReleaseCause::ActiveClose);
                                            counter_s[TcpStatistics::RecvFin] += 1;
                                            counter_c[TcpStatistics::SentFin] += 1;
                                        }
                                    } else if old_c_state >= TcpState::LastAck && hs.tcp.ack_flag() {
                                        if hs.tcp.ack_num() == c.seqn_fin_p2s.wrapping_add(1) {
                                            // received  Ack from server for a FIN
                                            match old_c_state {
                                                TcpState::LastAck => {
                                                    c.con_rec_c.push_state(TcpState::Closed);
                                                    c.con_rec_s.push_state(TcpState::Closed);
                                                }
                                                TcpState::FinWait1 => { c.con_rec_c.push_state(TcpState::FinWait2) }
                                                TcpState::Closing => {
                                                    c.con_rec_c.push_state(TcpState::Closed);
                                                }
                                                _ => {}
                                            }
                                            match old_s_state {
                                                TcpState::FinWait1 => {}
                                                _ => {}
                                            }
                                            counter_s[TcpStatistics::RecvFinAck2] += 1;
                                            counter_c[TcpStatistics::SentFinAck2] += 1;
                                            trace!("{} on proxy port {} transition to client/server state {:?}/{:?}", thread_id, c.port(), c.con_rec_c.states(), c.con_rec_s.states());
                                        }
                                    } else {
                                        // debug!("received from server { } in c/s state {:?}/{:?} ", hs.tcp, c.con_rec.c_state, c.con_rec.s_state);
                                        b_unexpected = true; //  may still be revised, see below
                                    }

                                    if *c.con_rec_c.last_state() == TcpState::Closed && *c.con_rec_s.last_state() == TcpState::Closed {
                                        release_connection = Some(c.port());
                                    }

                                    // once we established a two-way e-2-e connection, we always forward server side packets
                                    if old_s_state >= TcpState::Established
                                        && old_c_state >= TcpState::Established
                                        && old_c_state < TcpState::Closed {
                                        // translate packets and forward to client
                                        server_to_client(p, &mut c, &mut hs, &me);
                                        group_index = 1;
                                        b_unexpected = false;
                                    }

                                    if b_unexpected {
                                        warn!(
                                            "{} unexpected server side TCP packet on port {}/{} in client/server state {:?}/{:?}, sending to KNI i/f",
                                            thread_id,
                                            hs.tcp.dst_port(),
                                            c.get_client_sock().unwrap().1,
                                            c.con_rec_c.states(),
                                            c.con_rec_s.states(),
                                        );
                                        group_index = 2;
                                    }
                                } else {
                                    warn!("{} unexpected server side packet: no state on port {}, sending to KNI i/f", thread_id, hs.tcp.dst_port());
                                    // we send this to KNI which handles out-of-order TCP, e.g. by sending RST
                                    group_index = 2;
                                }
                            }
                        }
                    }
                }
                // here we check if we shall release the connection state,
                // required because of borrow checker for the state manager sm
                if let Some(sport) = release_connection {
                    trace!("releasing connection on port {}", sport);
                    cm.release_port(sport);
                }
                do_ttl(&mut hs);
                group_index
            },
            sched,
            "L4-Groups".to_string(),
            uuid_l4groupby,
        );

    let pipe2kni = l4groups.get_group(2).unwrap().send(kni.clone());
    let l4pciflow = l4groups.get_group(1).unwrap().compose();
    let l4dumpflow = l4groups.get_group(0).unwrap().filter(box move |_| false).compose();
    let pipe2pci = merge_auto(vec![l4pciflow, l4dumpflow], SchedulingPolicy::LongestQueue).send(pci.clone());


    let uuid_pipe2kni = tasks::install_task(sched, "Pipe2Kni", pipe2kni);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2kni, TaskType::Pipe2Kni))
        .unwrap();

    let uuid_pipe2pic = tasks::install_task(sched, "Pipe2Pci", pipe2pci);
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_pipe2pic, TaskType::Pipe2Pci))
        .unwrap();

    let uuid_consumer = tasks::install_task(sched, "BypassPipe", consumer.send(pci.clone()));
    tx.send(MessageFrom::Task(pipeline_id.clone(), uuid_consumer, TaskType::BypassPipe))
        .unwrap();
}
