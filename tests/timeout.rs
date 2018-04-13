extern crate ctrlc;
extern crate e2d2;
extern crate tcp_proxy;
extern crate time;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ipnet;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::env;
use std::time::Duration;
use std::thread;
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::channel;
use std::collections::HashMap;

use ipnet::Ipv4Net;

use e2d2::config::{basic_opts, read_matches};
use e2d2::native::zcsi::*;
use e2d2::interface::PmdPort;
use e2d2::scheduler::initialize_system;
use tcp_proxy::Connection;
use tcp_proxy::nftcp::setup_kni;
use tcp_proxy::read_proxy_config;
use tcp_proxy::get_mac_from_ifname;
use tcp_proxy::print_hard_statistics;
use tcp_proxy::SetupPipelines;
use tcp_proxy::Container;
use tcp_proxy::L234Data;
use tcp_proxy::MessageFrom;
use tcp_proxy::spawn_recv_thread;
use tcp_proxy::PipelineId;
use tcp_proxy::ConnectionStatistics;
use tcp_proxy::ReleaseCause;

#[test]
fn delayed_binding_proxy() {
    env_logger::init();
    info!("Testing timer_wheel of ProxyEngine ..");
    let toml_file = "tests/timeout.toml";

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

    let proxy_config = read_proxy_config(toml_file).unwrap();

    if proxy_config.queries.is_none() {
        error!("missing parameter 'queries' in configuration file");
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

    let args: Vec<String> = vec!["proxyengine", "-f", toml_file]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut configuration = read_matches(&matches, &opts);

    let l234data: Vec<L234Data> = proxy_config
        .servers
        .iter()
        .map(|srv_cfg| L234Data {
            mac: srv_cfg
                .mac
                .unwrap_or(get_mac_from_ifname(srv_cfg.linux_if.as_ref().unwrap()).unwrap()),
            ip: u32::from(srv_cfg.ip),
            port: srv_cfg.port,
        })
        .collect();

    let proxy_config_cloned = proxy_config.clone();

    // this is the closure, which selects the target server to use for a new TCP connection
    let f_select_server = move |c: &mut Connection| {
        let s = String::from_utf8(c.payload.to_vec()).unwrap();
        // read first item in string and convert to usize:
        let stars: usize = s.split(" ").next().unwrap().parse().unwrap();
        let remainder = stars % l234data.len();
        c.server = Some(l234data[remainder]);
        info!("selecting {}", proxy_config_cloned.servers[remainder].id);
        // initialize userdata
        if let Some(_) = c.userdata {
            c.userdata.as_mut().unwrap().init();
        } else {
            c.userdata = Some(Container::new());
        }
    };

    // this is the closure, which may modify the payload of client to server packets in a TCP connection
    let f_process_payload_c_s = |_c: &mut Connection, _payload: &mut [u8], _tailroom: usize| {};

    match initialize_system(&mut configuration) {
        Ok(mut context) => {
            context.start_schedulers();

            let (mtx, mrx) = channel::<MessageFrom>();
            let (sum_tx, sum_rx) = channel::<HashMap<PipelineId, Arc<ConnectionStatistics>>>();

            let proxy_config_cloned = proxy_config.clone();
            let boxed_fss = Arc::new(f_select_server);
            let boxed_fpp = Arc::new(f_process_payload_c_s);

            let setup_pipeline_cloner = SetupPipelines {
                proxy_engine_config: proxy_config_cloned,
                f_select_server: boxed_fss,
                f_process_payload_c_s: boxed_fpp,
                tx: mtx.clone(),
            };

            context.add_pipeline_to_run(setup_pipeline_cloner);
            spawn_recv_thread(mrx, sum_tx);
            context.execute();

            // set up kni
            debug!("Number of PMD ports: {}", PmdPort::num_pmd_ports());
            for port in context.ports.values() {
                debug!(
                    "port {}:{} -- mac_address= {}",
                    port.port_type(),
                    port.port_id(),
                    port.mac_address()
                );
                if port.is_kni() {
                    setup_kni(
                        port.linux_if().unwrap(),
                        &proxy_config.proxy.ipnet,
                        &proxy_config.proxy.mac,
                        &proxy_config.proxy.namespace,
                    );
                }
            }

            // emulate clients
            let queries = proxy_config.queries.unwrap();
            let proxy_addr = (proxy_config.proxy.ipnet.parse::<Ipv4Net>().unwrap().addr(), proxy_config.proxy.port);
            let timeout = Duration::from_millis(6000 as u64);

            const CLIENT_THREADS: usize = 10;
            for _i in 0..CLIENT_THREADS {
                debug!("starting thread {} with {} queries", _i, queries);
                thread::spawn(move || {
                    for ntry in 0..queries {
                        match TcpStream::connect(&SocketAddr::from(proxy_addr)) {
                            Ok(mut stream) => {
                                debug!("test connection {}: TCP connect to proxy successful", _i);
                                stream.set_write_timeout(Some(timeout)).unwrap();
                                stream.set_read_timeout(Some(timeout)).unwrap();
                                match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                                    Ok(_) => {
                                        debug!("successfully send {} stars", ntry);
                                        let mut buf = [0u8; 256];
                                        match stream.read(&mut buf[..]) {
                                            Ok(_) => info!("on try {} we received {}", ntry, String::from_utf8(buf.to_vec()).unwrap()),
                                            _ => {
                                                debug!("timeout on connection {} while waiting for answer", _i);
                                            }
                                        };
                                    }
                                    _ => {
                                        panic!("error when writing to test connection {}", _i);
                                    }
                                }
                            }
                            _ => {
                                panic!("test connection {}: 3-way handshake with proxy failed", _i);
                            }
                        }
                    }
                });
                thread::sleep(Duration::from_millis(48)); // roughly one event each third slot
            }
            thread::sleep(Duration::from_millis(3000)); // wait for clients to be started

            // now timer events in the wheel should have timed out, trigger another tick of the timer_wheel:
            match TcpStream::connect(&SocketAddr::from(proxy_addr)) {
                Ok(mut stream) => {
                    debug!("******** final TCP connect to proxy successful ********");
                    stream.set_write_timeout(Some(Duration::from_millis(200))).unwrap();
                    stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
                    match stream.write(&format!("{} stars", 1).to_string().into_bytes()) {
                        Ok(_) => {
                            let mut buf = [0u8; 256];
                            match stream.read(&mut buf[..]) {
                                Ok(_) => info!("we received {}", String::from_utf8(buf.to_vec()).unwrap()),
                                _ => {
                                    debug!("timeout while waiting for answer");
                                }
                            };
                        }
                        _ => {
                            panic!("error when writing to test connection");
                        }
                    }
                }
                _ => {
                    panic!("3-way handshake with proxy failed");
                }
            }
            thread::sleep(Duration::from_millis(500)); // Sleep for a bit

            print_hard_statistics(1u16);
            for port in context.ports.values() {
                println!("Port {}:{}", port.port_type(), port.port_id());
                port.print_soft_statistics();
            }

            info!("terminating ProxyEngine ...");
            mtx.send(MessageFrom::Exit).unwrap();
            thread::sleep(Duration::from_millis(500)); // wait for the statistics message

            let statistics = sum_rx.recv_timeout(Duration::from_millis(1000));
            assert!(statistics.is_ok());
            let statistics = statistics.unwrap();
            let mut tot_seized = 0u64;
            for c_stat in statistics.values() {
                assert_eq!(c_stat.get_seized() - 1, c_stat.c_released(ReleaseCause::Timeout));
                tot_seized += c_stat.get_seized();
            }
            assert_eq!(tot_seized, (queries * CLIENT_THREADS + 1) as u64);

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
