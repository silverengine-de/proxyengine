extern crate ctrlc;
extern crate e2d2;
extern crate env_logger;
// Logging
#[macro_use]
extern crate log;
extern crate tcp_proxy;
//extern crate serde_json;
extern crate bincode;
extern crate uuid;
//#[macro_use]
extern crate serde_derive;
extern crate netfcts;
extern crate ipnet;
extern crate separator;

use e2d2::interface::PmdPort;
use e2d2::scheduler::StandaloneScheduler;
use e2d2::native::zcsi::mbuf_avail_count;

use std::collections::{HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;
use std::convert::From;
use std::io::{BufWriter, Write};
use std::fs::File;
use std::mem;

use separator::Separatable;

use netfcts::tcp_common::{ReleaseCause, CData, L234Data, TcpState};
use netfcts::comm::{MessageFrom, MessageTo, PipelineId};
use netfcts::io::{ print_tcp_counters };
#[cfg(feature = "profiling")]
use netfcts::io::print_rx_tx_counters;
use netfcts::system::get_mac_from_ifname;
use netfcts::recstore::Store64;
use netfcts::conrecord::{HasTcpState, HasConData, ConRecord};
use netfcts::RunTime;

use tcp_proxy::setup_pipes_delayed_proxy;
use tcp_proxy::{ProxyConnection, Extension, ProxyMode, Configuration};

fn write_and_evaluate_records(con_records: &mut HashMap<PipelineId, Store64<Extension>>) {
    let mut completed_count_c = 0;
    let mut completed_count_s = 0;
    for con_recs in con_records.values() {
        for c in con_recs.iter_0() {
            if (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
                && c.last_state() == TcpState::Closed
            {
                completed_count_c += 1
            };
        }
        for c in con_recs.iter_1() {
            if (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
                && c.last_state() == TcpState::Closed
            {
                completed_count_s += 1
            };
        }
    }

    info!("completed connections c/s: {}/{}", completed_count_c, completed_count_s);

    // write connection records into a file:
    let file = match File::create("c_records.txt") {
        Err(why) => panic!("couldn't create c_records.txt: {}", why),
        Ok(file) => file,
    };
    let mut f = BufWriter::new(file);

    for (p, c_records) in con_records {
        info!("Pipeline {}:", p);
        f.write_all(format!("Pipeline {}:\n", p).as_bytes())
            .expect("cannot write c_records");

        if c_records.len() > 0 {
            let mut completed_count = 0;
            let mut min = c_records.iter_0().last().unwrap().clone();
            let mut max = min.clone();
            c_records.sort_0_by(|a, b| a.sock().1.cmp(&b.sock().1));
            c_records.iter().enumerate().for_each(|(i, (c, s))| {
                let line_c = format!("{:6}: {}\n", i, c);
                f.write_all(line_c.as_bytes()).expect("cannot write c_records for client");
                let line_s = format!("        {}\n", s);
                f.write_all(line_s.as_bytes()).expect("cannot write c_records for server");

                if (c.release_cause() == ReleaseCause::PassiveClose || c.release_cause() == ReleaseCause::ActiveClose)
                    && c.states().last().unwrap() == &TcpState::Closed
                {
                    completed_count += 1
                }
                if c.get_first_stamp().unwrap_or(u64::max_value()) < min.get_first_stamp().unwrap_or(u64::max_value()) {
                    min = c.clone()
                }
                if c.get_last_stamp().unwrap_or(0) > max.get_last_stamp().unwrap_or(0) {
                    max = c.clone()
                }
                if i == (c_records.len() - 1) && min.get_first_stamp().is_some() && max.get_last_stamp().is_some() {
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
}

pub fn main() {
    env_logger::init();

    let mut run_time: RunTime<Configuration, Store64<Extension>> = match RunTime::init() {
        Ok(run_time) => run_time,
        Err(err) => panic!("failed to initialize RunTime {}", err),
    };
    info!("Starting ProxyEngine ..");

    // setup flowdirector for physical ports:
    run_time.setup_flowdirector().expect("failed to setup flowdirector");

    let run_configuration = run_time.run_configuration.clone();
    let configuration = &run_configuration.engine_configuration;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("received SIGINT or SIGTERM");
        r.store(false, Ordering::SeqCst);
    })
    .expect("error setting Ctrl-C handler");

    let l234data: Vec<L234Data> = run_configuration
        .engine_configuration
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
        })
        .collect();

    let l234data_clone = l234data.clone();
    // this is the closure, which selects the target server to use for a new TCP connection
    let f_by_payload = move |c: &mut ProxyConnection| {
        //let cdata: CData = serde_json::from_slice(&c.payload).expect("cannot deserialize CData");
        //no_calls +=1;
        let cdata: CData = bincode::deserialize::<CData>(c.payload_packet.as_ref().unwrap().get_payload(2))
            .expect("cannot deserialize CData");
        //info!("cdata = {:?}", cdata);
        for (i, l234) in l234data_clone.iter().enumerate() {
            if l234.port == cdata.reply_socket.port() && l234.ip == u32::from(*cdata.reply_socket.ip()) {
                c.set_server_index(i as u8);
                break;
            }
        }
    };

    let no_servers = l234data.len();
    let mut last_server: u8 = 0;
    let _f_round_robbin = move |c: &mut ProxyConnection| {
        if (last_server as usize) < no_servers - 1 {
            last_server += 1;
        } else {
            last_server = 0;
        }
        c.set_server_index(last_server);
    };

    // this is the closure, which may modify the payload of client to server packets in a TCP connection
    let f_process_payload_c_s = |_c: &mut ProxyConnection, _payload: &mut [u8], _tailroom: usize| {};

    run_time.start_schedulers().expect("cannot start schedulers");

    if *run_configuration
        .engine_configuration
        .engine
        .mode
        .as_ref()
        .unwrap_or(&ProxyMode::Delayed)
        == ProxyMode::Delayed
    {
        let run_configuration_cloned = run_configuration.clone();
        run_time
            .install_pipeline_on_cores(Box::new(
                move |core: i32, pmd_ports: HashMap<String, Arc<PmdPort>>, s: &mut StandaloneScheduler| {
                    setup_pipes_delayed_proxy(
                        core,
                        pmd_ports,
                        s,
                        run_configuration_cloned.clone(),
                        l234data.clone(),
                        f_by_payload.clone(),
                        f_process_payload_c_s.clone(),
                    );
                },
            ))
            .expect("cannot install pipelines");
    } else {
        // simple proxy
        error!("simple proxy still not implemented");
    }

    let cores = run_time.context().unwrap().active_cores.clone();

    // start the run_time receive thread
    run_time.start();

    let (mtx, reply_mrx) = run_time.get_main_channel().expect("cannot get main channel");
    mtx.send(MessageFrom::StartEngine).unwrap();
    thread::sleep(Duration::from_millis(2000 as u64));

    debug!(
        "Connection record sizes = {} + {} + {}",
        mem::size_of::<ProxyConnection>(),
        mem::size_of::<ConRecord>(),
        mem::size_of::<Extension>()
    );

    //main loop
    println!("press ctrl-c to terminate proxy ...");
    let mut loops: usize = 300;
    while running.load(Ordering::SeqCst) {
        if loops == 300 {
            loops = 0;
            info!("available mbufs in memory pool= {:6}", unsafe { mbuf_avail_count() });
        }
        thread::sleep(Duration::from_millis(200 as u64)); // Sleep for a bit
        loops += 1;
    }

    println!("\nTask Performance Data:\n");
    mtx.send(MessageFrom::PrintPerformance(cores)).unwrap();
    thread::sleep(Duration::from_millis(1000 as u64));

    mtx.send(MessageFrom::FetchCounter).unwrap();
    if configuration.engine.detailed_records.unwrap_or(false) {
        mtx.send(MessageFrom::FetchCRecords).unwrap();
    }

    let mut tcp_counters_c = HashMap::new();
    let mut tcp_counters_s = HashMap::new();
    let mut con_records = HashMap::new();

    loop {
        match reply_mrx.recv_timeout(Duration::from_millis(1000)) {
            Ok(MessageTo::Counter(pipeline_id, tcp_counter_c, tcp_counter_s, _rx_tx_stats)) => {
                print_tcp_counters(&pipeline_id, &tcp_counter_c, &tcp_counter_s);
                //#[cfg(feature = "profiling")]
                //print_rx_tx_counters(&pipeline_id, &_rx_tx_stats.unwrap());
                tcp_counters_c.insert(pipeline_id.clone(), tcp_counter_c);
                tcp_counters_s.insert(pipeline_id, tcp_counter_s);
            }
            Ok(MessageTo::CRecords(pipeline_id, Some(recv_con_records), _)) => {
                debug!("{}: received {} CRecords", pipeline_id, recv_con_records.len(),);
                con_records.insert(pipeline_id, recv_con_records);
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

    if configuration.engine.detailed_records.unwrap_or(false) {
        write_and_evaluate_records(&mut con_records);
    }
    mtx.send(MessageFrom::Exit).unwrap();
    thread::sleep(Duration::from_millis(200 as u64)); // give threads some time to process Exit
    info!("terminating ProxyEngine ...");
    std::process::exit(0);
}
