extern crate ctrlc;
extern crate e2d2;
extern crate tcp_proxy;
extern crate time;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ipnet;
extern crate netfcts;
extern crate separator;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::env;
use std::time::Duration;
use std::thread;
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::channel;
use std::fs::File;
use std::collections::{HashSet, HashMap};
use std::str::FromStr;
use std::sync::mpsc::RecvTimeoutError;

use ipnet::Ipv4Net;
use separator::Separatable;

use e2d2::config::{basic_opts, read_matches};
use e2d2::native::zcsi::*;
use e2d2::interface::PortQueue;
use e2d2::scheduler::initialize_system;
use e2d2::scheduler::StandaloneScheduler;
use e2d2::allocators::CacheAligned;

use netfcts::initialize_flowdirector;
use netfcts::tcp_common::ReleaseCause;
use netfcts::system::{SystemData, get_mac_from_ifname};
use netfcts::io::{ print_tcp_counters, print_rx_tx_counters};
use netfcts::ConRecordOperations;

use tcp_proxy::Connection;
use tcp_proxy::{read_config};
use tcp_proxy::L234Data;
use netfcts::comm::{MessageFrom, MessageTo};
use tcp_proxy::spawn_recv_thread;
use tcp_proxy::setup_pipelines;
use tcp_proxy::TcpState;

#[test]
fn delayed_binding_proxy() {
    env_logger::init();
    info!("Testing client side tcp connection setup and release ..");
    // cannot directly read toml file from command line, as cargo test owns it. Thus we take a detour and read it from a file.
    let mut f = File::open("./tests/toml_file.txt").expect("file not found");
    let mut toml_file = String::new();
    f.read_to_string(&mut toml_file)
        .expect("something went wrong reading toml_file.txt");

    let log_level_rte = if log_enabled!(log::Level::Debug) {
        RteLogLevel::RteLogDebug
    } else {
        RteLogLevel::RteLogInfo
    };
    unsafe {
        rte_log_set_global_level(log_level_rte);
        rte_log_set_level(RteLogtype::RteLogtypePmd, log_level_rte);
        info!("dpdk log global level: {}", rte_log_get_global_level());
        info!("dpdk log level for PMD: {}", rte_log_get_level(RteLogtype::RteLogtypePmd));
    }

    let system_data = SystemData::detect();

    let configuration = read_config(toml_file.trim()).expect("cannot read config from toml file");
    if configuration.test_size.is_none() {
        error!("missing parameter 'test_size' in configuration file");
        std::process::exit(1);
    };

    fn am_root() -> bool {
        match env::var("USER") {
            Ok(val) => val == "root",
            Err(_e) => false,
        }
    }

    if !am_root() {
        error!(" ... must run as root, e.g.: sudo -E env \"PATH=$PATH\" $executable, see also test.sh\nDo not run 'cargo test' as root.");
        std::process::exit(1);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    }).expect("error setting Ctrl-C handler");

    let opts = basic_opts();

    let args: Vec<String> = vec!["proxyengine", "-f", toml_file.trim()]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut netbricks_configuration = read_matches(&matches, &opts);

    let l234data: Vec<L234Data> = configuration
        .targets
        .iter()
        .enumerate()
        .map(|(i,srv_cfg)| L234Data {
            mac: srv_cfg
                .mac
                .unwrap_or_else(|| get_mac_from_ifname(srv_cfg.linux_if.as_ref().unwrap()).unwrap()),
            ip: u32::from(srv_cfg.ip),
            port: srv_cfg.port,
            server_id: srv_cfg.id.clone(),
            index: i,
        }).collect();

    let proxy_config_cloned = configuration.clone();
    let l234data_clone=l234data.clone();
    // this is the closure, which selects the target server to use for a new TCP connection
    let f_select_server = move |c: &mut Connection| {
        let s = String::from_utf8(c.payload_packet.as_ref().unwrap().get_payload().to_vec()).unwrap();
        // read first item in string and convert to usize:
        let stars: usize = s.split(" ").next().unwrap().parse().unwrap();
        let remainder = stars % l234data_clone.len();
        c.s_mut().set_server_index(remainder);
        debug!("selecting {}", proxy_config_cloned.targets[remainder].id);
    };

    // this is the closure, which may modify the payload of client to server packets in a TCP connection
    let f_process_payload_c_s = |_c: &mut Connection, _payload: &mut [u8], _tailroom: usize| {};

    match initialize_system(&mut netbricks_configuration) {
        Ok(mut context) => {
            let flowdirector_map = initialize_flowdirector(&context, configuration.flow_steering_mode(), &Ipv4Net::from_str(&configuration.engine.ipnet).unwrap());
            context.start_schedulers();
            let (mtx, mrx) = channel::<MessageFrom>();
            let (reply_mtx, reply_mrx) = channel::<MessageTo>();

            let proxy_config_cloned = configuration.clone();
            let system_data_cloned = system_data.clone();
            let mtx_clone = mtx.clone();

            context.add_pipeline_to_run(Box::new(
                move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                    setup_pipelines(
                        core,
                        p,
                        s,
                        &proxy_config_cloned.engine,
                        l234data.clone(),
                        flowdirector_map.clone(),
                        mtx_clone.clone(),
                        system_data_cloned.clone(),
                        f_select_server.clone(),
                        f_process_payload_c_s.clone(),
                    );
                },
            ));

            let cores = context.active_cores.clone();

            spawn_recv_thread(mrx, context, configuration.clone());
            mtx.send(MessageFrom::StartEngine(reply_mtx)).unwrap();

            // emulate clients
            let queries = configuration.test_size.unwrap();
            let proxy_addr = (
                configuration.engine.ipnet.parse::<Ipv4Net>().unwrap().addr(),
                configuration.engine.port,
            );
            // for this test tcp client timeout must be shorter than timeouts by timer wheel
            let timeout = Duration::from_millis(50 as u64);

            const CLIENT_THREADS: usize = 10;
            for _i in 0..CLIENT_THREADS {
                thread::spawn(move || {
                    for ntry in 0..queries {
                        match TcpStream::connect(&SocketAddr::from(proxy_addr)) {
                            Ok(mut stream) => {
                                debug!("test connection {}: TCP connect to proxy successful", ntry);
                                stream.set_write_timeout(Some(timeout)).unwrap();
                                stream.set_read_timeout(Some(timeout)).unwrap();
                                match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                                    Ok(_) => {
                                        debug!("successfully send {} stars", ntry);
                                        let mut buf = [0u8; 256];
                                        match stream.read(&mut buf[..]) {
                                            Ok(_) => info!(
                                                "on try {} we received {}",
                                                ntry,
                                                String::from_utf8(buf.to_vec()).unwrap()
                                            ),
                                            _ => {
                                                debug!("timeout on connection {} while waiting for answer", ntry);
                                            }
                                        };
                                    }
                                    _ => {
                                        panic!("error when writing to test connection {}", ntry);
                                    }
                                }
                            }
                            _ => {
                                panic!("test connection {}: 3-way handshake with proxy failed", ntry);
                            }
                        }
                    }
                });
            }
            thread::sleep(Duration::from_millis(5000)); // Wait for client timeouts

            println!("\nTask Performance Data:\n");
            mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
            thread::sleep(Duration::from_millis(1000 as u64));

            mtx.send(MessageFrom::FetchCounter).unwrap();
            mtx.send(MessageFrom::FetchCRecords).unwrap();

            let mut tcp_counters_c = HashMap::new();
            let mut tcp_counters_s = HashMap::new();
            let mut con_records = HashMap::new();

            loop {
                match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
                    Ok(MessageTo::Counter(pipeline_id, tcp_counter_c, tcp_counter_s, rx_tx_stats)) => {
                        print_tcp_counters(&pipeline_id, &tcp_counter_c, &tcp_counter_s);
                        if rx_tx_stats.is_some() { print_rx_tx_counters(&pipeline_id, &rx_tx_stats.unwrap()); }
                        tcp_counters_c.insert(pipeline_id.clone(), tcp_counter_c);
                        tcp_counters_s.insert(pipeline_id, tcp_counter_s);
                    }
                    Ok(MessageTo::CRecords(pipeline_id, con_records_c, con_records_s)) => {
                        debug!("{}: received CRecords", pipeline_id);
                        con_records.insert(pipeline_id, (con_records_c, con_records_s));
                    }
                    Ok(_m) => error!("illegal MessageTo received from reply_to_main channel"),
                    Err(RecvTimeoutError::Timeout) => {
                        break;
                    }
                    Err(e) => {
                        error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
                    }
                }
            }

            for (p, (c_records_c, _c_records_s)) in &con_records {
                info!("Pipeline {}:", p);
                if c_records_c.len() > 0 {
                    let mut completed_count = 0;
                    let mut min = c_records_c.iter().last().unwrap();
                    let mut max = min;
                    c_records_c.iter().enumerate().for_each(|(i, c)| {
                        info!("{:6}: {}", i, c);
                        if (c.get_release_cause() == ReleaseCause::PassiveClose || c.get_release_cause() == ReleaseCause::ActiveClose) && c.states().last().unwrap() == &TcpState::Closed {
                            completed_count += 1
                        }
                        if c.get_first_stamp().unwrap_or(u64::max_value()) < min.get_first_stamp().unwrap_or(u64::max_value()) { min = c }
                        if c.get_last_stamp().unwrap_or(0) > max.get_last_stamp().unwrap_or(0) { max = c }
                        if i == (c_records_c.len() - 1) && min.get_first_stamp().is_some() && max.get_last_stamp().is_some() {
                            let total = max.get_last_stamp().unwrap() - min.get_first_stamp().unwrap();
                            info!("total used cycles= {}, per connection = {}", total.separated_string(), (total / (i as u64 + 1)).separated_string());
                        }
                    });
                }
            }


            let mut completed_count_c = 0;
            for (_p, (con_recs, _)) in &con_records {
                for c in con_recs.iter() {
                    if c.get_release_cause() == ReleaseCause::ActiveClose
                        && c.last_state() == TcpState::Closed
                        {
                            completed_count_c += 1
                        };
                    assert_eq!(c.states(), [TcpState::Closed, TcpState::SynSent, TcpState::Established, TcpState::FinWait1, TcpState::Closed]);
                }
            }


            let mut completed_count_s = 0;
            for (_p, (_, con_recs)) in &con_records{
                for c in con_recs.iter() {
                    if c.get_release_cause() == ReleaseCause::PassiveClose
                        && c.last_state() == TcpState::Closed
                        {
                            completed_count_s += 1
                        };
                    assert_eq!(c.states(), [TcpState::Listen, TcpState::SynReceived, TcpState::LastAck, TcpState::Closed]);
                }
            }

            info!("completed connections c/s: {}/{}", completed_count_c, completed_count_s );
            assert_eq!(completed_count_c, configuration.test_size.unwrap() * CLIENT_THREADS);
            assert_eq!(completed_count_s, configuration.test_size.unwrap() * CLIENT_THREADS);

            mtx.send(MessageFrom::Exit).unwrap();
            thread::sleep(Duration::from_millis(2000));

            info!("terminating ProxyEngine ...");
            println!("\nPASSED\n");
            std::process::exit(0);
        }
        Err(ref e) => {
            error!("Error: {}", e);
            if let Some(backtrace) = e.backtrace() {
                debug!("Backtrace: {:?}", backtrace);
            }
            std::process::exit(1);
        }
    }
}
