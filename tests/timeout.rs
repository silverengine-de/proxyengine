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
use std::collections::{ HashSet};
use std::fs::File;

use ipnet::Ipv4Net;

use e2d2::config::{basic_opts, read_matches};
use e2d2::native::zcsi::*;
use e2d2::interface::{ PortQueue};
use e2d2::scheduler::{initialize_system, StandaloneScheduler};
use e2d2::allocators::CacheAligned;

use tcp_proxy::Connection;
use tcp_proxy::{read_config, initialize_flowdirector};
use tcp_proxy::get_mac_from_ifname;
use tcp_proxy::setup_pipelines;
use tcp_proxy::Container;
use tcp_proxy::L234Data;
use tcp_proxy::{ MessageFrom, MessageTo };
use tcp_proxy::spawn_recv_thread;
use tcp_proxy::ReleaseCause;

#[test]
fn delayed_binding_proxy() {
    env_logger::init();
    info!("Testing timer_wheel of ProxyEngine ..");
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

    let proxy_config = read_config(toml_file.trim()).unwrap();

    if proxy_config.test_size.is_none() {
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
    let mut configuration = read_matches(&matches, &opts);

    let l234data: Vec<L234Data> = proxy_config
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

    let proxy_config_cloned = proxy_config.clone();

    // this is the closure, which selects the target server to use for a new TCP connection
    let f_select_server = move |c: &mut Connection| {
        let s = String::from_utf8(c.payload.to_vec()).unwrap();
        // read first item in string and convert to usize:
        let stars: usize = s.split(" ").next().unwrap().parse().unwrap();
        let remainder = stars % l234data.len();
        c.server = Some(l234data[remainder].clone());
        info!("selecting {}", proxy_config_cloned.targets[remainder].id);
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
            let flowdirector_map=initialize_flowdirector(&context, &proxy_config);
            context.start_schedulers();
            let (mtx, mrx) = channel::<MessageFrom>();
            let (reply_mtx, reply_mrx) = channel::<MessageTo>();

            let proxy_config_cloned = proxy_config.clone();
            let boxed_fss = Arc::new(f_select_server);
            let boxed_fpp = Arc::new(f_process_payload_c_s);

            let mtx_clone = mtx.clone();

            context.add_pipeline_to_run(Box::new(
                move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                    setup_pipelines(
                        core,
                        p,
                        s,
                        &proxy_config_cloned,
                        boxed_fss.clone(),
                        boxed_fpp.clone(),
                        flowdirector_map.clone(),
                        mtx_clone.clone(),
                    );
                },
            ));

            spawn_recv_thread(mrx, context, proxy_config.clone());

            mtx.send(MessageFrom::StartEngine(reply_mtx)).unwrap();

            // emulate clients
            let queries = proxy_config.test_size.unwrap();
            let proxy_addr = (
                proxy_config.engine.ipnet.parse::<Ipv4Net>().unwrap().addr(),
                proxy_config.engine.port,
            );
            let timeout = Duration::from_millis(6000 as u64);

            const CLIENT_THREADS: usize = 10;
            for _i in 0..CLIENT_THREADS {
                debug!("starting thread {} with {} test_size", _i, queries);
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
                                            Ok(_) => info!(
                                                "on try {} we received {}",
                                                ntry,
                                                String::from_utf8(buf.to_vec()).unwrap()
                                            ),
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

            info!("terminating ProxyEngine ...");
            mtx.send(MessageFrom::Exit).unwrap();

            match reply_mrx.recv_timeout(Duration::from_millis(5000)) {
                Ok(MessageTo::ConRecords(con_records)) => {
                    assert_eq!(con_records.len(), proxy_config.test_size.unwrap() * CLIENT_THREADS +1);
                    let mut timeouts =0;
                    for (_p, c) in &con_records {
                        if c.get_release_cause() == ReleaseCause::Timeout {
                            timeouts +=1;
                        }
                    }
                    assert_eq!(timeouts, proxy_config.test_size.unwrap() * CLIENT_THREADS);
                }
                Ok(_m) => error!("illegal MessageTo received from reply_to_main channel"),
                Err(e) => {
                    error!("error receiving from reply_to_main channel (reply_mrx): {}", e);
                }
            }

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
