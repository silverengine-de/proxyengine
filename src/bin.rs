extern crate ctrlc;
extern crate e2d2;
extern crate env_logger;
// Logging
#[macro_use]
extern crate log;
extern crate tcp_proxy;
extern crate serde_json;
extern crate uuid;
#[macro_use]
extern crate serde_derive;
extern crate netfcts;
extern crate ipnet;
extern crate separator;

use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{ PortType, PortQueue};
use e2d2::native::zcsi::*;
use e2d2::scheduler::{initialize_system, NetBricksContext, StandaloneScheduler};
use e2d2::allocators::CacheAligned;

use std::collections::{HashSet, HashMap};
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;
use std::net::SocketAddrV4;
use std::convert::From;
use std::str::FromStr;
use std::io::{BufWriter, Write};
use std::error::Error;
use std::fs::File;

use uuid::Uuid;
use ipnet::Ipv4Net;
use separator::Separatable;

use netfcts::initialize_flowdirector;
use netfcts::tcp_common::{ReleaseCause};
use netfcts::comm::{MessageFrom, MessageTo};
use netfcts::system::SystemData;

use tcp_proxy::{get_mac_from_ifname, read_config, setup_pipelines};
use tcp_proxy::Connection;
use tcp_proxy::Container;
use tcp_proxy::errors::*;
use tcp_proxy::L234Data;
use tcp_proxy::spawn_recv_thread;
use tcp_proxy::TcpState;

pub fn main() {
    env_logger::init();
    info!("Starting ProxyEngine ..");

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

    // read config file name from command line
    let args: Vec<String> = env::args().collect();
    let config_file;
    if args.len() > 1 {
        config_file = args[1].clone();
    } else {
        println!("try 'proxy_engine <toml configuration file>'\n");
        std::process::exit(1);
    }

    let configuration = read_config(&config_file).unwrap();

    fn am_root() -> bool {
        match env::var("USER") {
            Ok(val) => val == "root",
            Err(_e) => false,
        }
    }

    if !am_root() {
        error!(
            " ... must run as root, e.g.: sudo -E env \"PATH=$PATH\" $executable, see also test.sh\n\
             Do not run 'cargo test' as root."
        );
        std::process::exit(1);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    }).expect("error setting Ctrl-C handler");

    let opts = basic_opts();

    let args: Vec<String> = vec!["proxyengine", "-f", &config_file]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut netbricks_configuration = read_matches(&matches, &opts);

    //  let (tx, rx) = channel::<TcpEvent>();

    let l234data: Vec<L234Data> = configuration
        .targets
        .iter()
        .enumerate()
        .map(|(i, srv_cfg)| L234Data {
            mac: srv_cfg
                .mac
                .unwrap_or_else(|| get_mac_from_ifname(srv_cfg.linux_if.as_ref().unwrap()).unwrap()),
            ip: u32::from(srv_cfg.ip),
            port: srv_cfg.port,
            server_id: srv_cfg.id.clone(),
            index: i,
        }).collect();

    #[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
    pub struct CData {
        // connection data sent as first payload packet
        pub reply_socket: SocketAddrV4, // the socket on which the trafficengine expects the reply from the DUT
        pub client_port: u16,
        pub uuid: Option<Uuid>,
    }

    // this is the closure, which selects the target server to use for a new TCP connection
    let f_select_server = move |c: &mut Connection| {
        let cdata: CData = serde_json::from_slice(&c.payload).expect("cannot deserialize CData");

        for l234 in &l234data {
            if l234.port == cdata.reply_socket.port() && l234.ip == u32::from(*cdata.reply_socket.ip()) {
                c.server = Some((*l234).clone());
                break;
            }
        }

        if let Some(_) = c.userdata {
            c.userdata.as_mut().unwrap().init();
        } else {
            c.userdata = Some(Container::new());
        }
    };

    // this is the closure, which may modify the payload of client to server packets in a TCP connection
    let f_process_payload_c_s = |_c: &mut Connection, _payload: &mut [u8], _tailroom: usize| {};

    fn check_system(context: NetBricksContext) -> Result<NetBricksContext> {
        for port in context.ports.values() {
            if port.port_type() == &PortType::Dpdk {
                debug!("Supported filters on port {}:", port.port_id());
                for i in RteFilterType::RteEthFilterNone as i32 + 1..RteFilterType::RteEthFilterMax as i32 {
                    let result = unsafe { rte_eth_dev_filter_supported(port.port_id() as u16, RteFilterType::from(i)) };
                    debug!("{0: <30}: {1: >5}", RteFilterType::from(i), result);
                }
            }
        }
        Ok(context)
    }

    match initialize_system(&mut netbricks_configuration)
        .map_err(|e| e.into())
        .and_then(|ctxt| check_system(ctxt))
    {
        Ok(mut context) => {
            let flowdirector_map = initialize_flowdirector(
                &context,
                configuration.flow_steering_mode(),
                &Ipv4Net::from_str(&configuration.engine.ipnet).unwrap(),
            );
            unsafe {
                fdir_get_infos(1u16);
            }
            context.start_schedulers();
            let (mtx, mrx) = channel::<MessageFrom>();
            let (reply_mtx, reply_mrx) = channel::<MessageTo>();

            let proxy_config_cloned = configuration.clone();
            let system_data_cloned = system_data.clone();
            let mtx_clone = mtx.clone();
            let boxed_fss = Arc::new(f_select_server);
            let boxed_fpp = Arc::new(f_process_payload_c_s);

            context.add_pipeline_to_run(Box::new(
                move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                    setup_pipelines(
                        core,
                        p,
                        s,
                        &proxy_config_cloned.engine,
                        boxed_fss.clone(),
                        boxed_fpp.clone(),
                        flowdirector_map.clone(),
                        mtx_clone.clone(),
                        system_data_cloned.clone(),
                    );
                },
            ));

            let cores = context.active_cores.clone();

            spawn_recv_thread(mrx, context, configuration);
            mtx.send(MessageFrom::StartEngine(reply_mtx)).unwrap();
            // debug output on flow director:
            if log_enabled!(log::Level::Debug) {
                unsafe {
                    fdir_get_infos(1u16);
                }
            }

            //main loop
            println!("press ctrl-c to terminate proxy ...");
            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
            }

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
                    Ok(MessageTo::Counter(pipeline_id, tcp_counter_c, tcp_counter_s)) => {
                        println!("\n");
                        println!("{}: client side {}", pipeline_id, tcp_counter_c);
                        println!("{}: server side {}", pipeline_id, tcp_counter_s);
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
                        break;
                    }
                }
            }

            let mut completed_count_c = 0;
            for (_p, (con_recs, _)) in &con_records {
                for c in con_recs {
                    if (c.get_release_cause() == ReleaseCause::PassiveClose
                        || c.get_release_cause() == ReleaseCause::ActiveClose)
                        && c.last_state() == &TcpState::Closed
                    {
                        completed_count_c += 1
                    };
                }
            }

            let mut completed_count_s = 0;
            for (_p, (_, con_recs)) in &con_records {
                for c in con_recs {
                    if (c.get_release_cause() == ReleaseCause::PassiveClose
                        || c.get_release_cause() == ReleaseCause::ActiveClose)
                        && c.last_state() == &TcpState::Closed
                    {
                        completed_count_s += 1
                    };
                }
            }
            info!("completed connections c/s: {}/{}", completed_count_c, completed_count_s);

            let mut file = match File::create("c_records.txt") {
                Err(why) => panic!("couldn't create c_records.txt: {}", why.description()),
                Ok(file) => file,
            };
            let mut f = BufWriter::new(file);

            for (p, (mut c_records_c, mut c_records_s)) in con_records {
                info!("Pipeline {}:", p);
                f.write_all(format!("Pipeline {}:\n", p).as_bytes())
                    .expect("cannot write c_records");
                // make HashMap with key uuid
                let mut by_uuid = HashMap::with_capacity(c_records_s.len());
                for c in c_records_s {
                    by_uuid.insert(c.uuid.unwrap(), c.clone());
                }

                if c_records_c.len() > 0 {
                    let mut completed_count = 0;
                    let mut min = c_records_c.iter().last().unwrap().clone();
                    let mut max = min.clone();
                    c_records_c.sort_by(|a, b| a.sock.unwrap().port().cmp(&b.sock.unwrap().port()));

                    c_records_c.iter().enumerate().for_each(|(i, c)| {
                        let uuid = c.uuid.as_ref().unwrap();
                        let c_server = by_uuid.remove(uuid);
                        let line = format!("{:6}: {}\n", i, c);
                        f.write_all(line.as_bytes()).expect("cannot write c_records");
                        f.write_all(format!("        {}\n", c_server.unwrap()).as_bytes())
                            .expect("cannot write c_records");
                        if (c.get_release_cause() == ReleaseCause::PassiveClose
                            || c.get_release_cause() == ReleaseCause::ActiveClose)
                            && c.states().last().unwrap() == &TcpState::Closed
                        {
                            completed_count += 1
                        }
                        if c.get_first_stamp().unwrap_or(u64::max_value())
                            < min.get_first_stamp().unwrap_or(u64::max_value())
                        {
                            min = c.clone()
                        }
                        if c.get_last_stamp().unwrap_or(0) > max.get_last_stamp().unwrap_or(0) {
                            max = c.clone()
                        }
                        if i == (c_records_c.len() - 1) && min.get_first_stamp().is_some() && max.get_last_stamp().is_some()
                        {
                            let total = max.get_last_stamp().unwrap() - min.get_first_stamp().unwrap();
                            info!(
                                "total used cycles= {}, per connection = {}",
                                total.separated_string(),
                                (total / (i as u64 + 1)).separated_string()
                            );
                        }
                    });
                }
            }

            f.flush().expect("cannot flush BufWriter");
            mtx.send(MessageFrom::Exit).unwrap();

            info!("terminating ProxyEngine ...");
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
