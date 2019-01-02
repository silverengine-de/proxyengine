#![feature(box_syntax)]
#![feature(integer_atomics)]

// Logging
#[macro_use]
extern crate log;
extern crate e2d2;
extern crate env_logger;
extern crate fnv;
extern crate rand;
extern crate toml;
extern crate separator;
#[macro_use]
extern crate serde_derive;
extern crate eui48;
extern crate ipnet;
extern crate serde;
extern crate uuid;
extern crate netfcts;

pub mod nftcp;
mod cmanager;

pub use netfcts::tcp_common::{CData, L234Data, UserData, TcpRole, TcpState, TcpCounter, TcpStatistics};
pub use netfcts::ConRecord;
pub use cmanager:: Connection;

use netfcts::tasks::TaskType;
use netfcts::tasks::KniHandleRequest;
use ipnet::Ipv4Net;
use eui48::MacAddress;
use uuid::Uuid;
use separator::Separatable;

use e2d2::common::ErrorKind as E2d2ErrorKind;
use e2d2::scheduler::*;
use e2d2::allocators::CacheAligned;
use e2d2::interface::{PortQueue, PmdPort, FlowDirector};

use netfcts::errors::*;
use netfcts::io::print_hard_statistics;
use nftcp::setup_forwarder;
use netfcts::{is_kni_core, setup_kni, FlowSteeringMode};
use netfcts::comm::{MessageFrom, MessageTo, PipelineId};
use netfcts::system::SystemData;

use std::fs::File;
use std::io::Read;
use std::any::Any;
use std::net::Ipv4Addr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::RecvTimeoutError;
use std::str::FromStr;

#[derive(Deserialize)]
struct Config {
    proxyengine: Configuration,
}

#[derive(Deserialize, Clone)]
pub struct Configuration {
    pub targets: Vec<TargetConfig>,
    pub engine: EngineConfig,
    pub test_size: Option<usize>,
}

impl Configuration {
    pub fn flow_steering_mode(&self) -> FlowSteeringMode {
        self.engine.flow_steering.unwrap_or(FlowSteeringMode::Port)
    }
}

#[derive(Deserialize, Clone)]
pub struct EngineConfig {
    pub flow_steering: Option<FlowSteeringMode>,
    pub namespace: String,
    pub mac: String,
    pub ipnet: String,
    pub timeouts: Option<Timeouts>,
    pub port: u16,
}

impl EngineConfig {
    pub fn get_l234data(&self) -> L234Data {
        L234Data {
            mac: MacAddress::parse_str(&self.mac).unwrap(),
            ip: u32::from(self.ipnet.parse::<Ipv4Net>().unwrap().addr()),
            port: self.port,
            server_id: "Engine".to_string(),
            index: 0,
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct TargetConfig {
    pub id: String,
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddress>,
    pub linux_if: Option<String>,
    pub port: u16,
}

#[derive(Deserialize, Clone)]
pub struct Timeouts {
    established: Option<u64>, // in millis
}

impl Default for Timeouts {
    fn default() -> Timeouts {
        Timeouts { established: Some(200) }
    }
}

impl Timeouts {
    pub fn default_or_some(timeouts: &Option<Timeouts>) -> Timeouts {
        let mut t = Timeouts::default();
        if timeouts.is_some() {
            let timeouts = timeouts.clone().unwrap();
            if timeouts.established.is_some() {
                t.established = timeouts.established;
            }
        }
        t
    }
}

pub fn read_config(filename: &str) -> Result<Configuration> {
    let mut toml_str = String::new();
    let _ = File::open(filename)
        .and_then(|mut f| f.read_to_string(&mut toml_str))
        .chain_err(|| E2d2ErrorKind::ConfigurationError(format!("Could not read file {}", filename)))?;

    info!("toml configuration:\n {}", toml_str);

    let config: Config = match toml::from_str(&toml_str) {
        Ok(value) => value,
        Err(err) => return Err(err.into()),
    };

    match config.proxyengine.engine.ipnet.parse::<Ipv4Net>() {
        Ok(_) => match config.proxyengine.engine.mac.parse::<MacAddress>() {
            Ok(_) => Ok(config.proxyengine),
            Err(e) => Err(e.into()),
        },
        Err(e) => Err(e.into()),
    }
}

struct MyData {
    c2s_count: usize,
    s2c_count: usize,
    avg_latency: f64,
}

impl MyData {
    fn new() -> MyData {
        MyData {
            c2s_count: 0,
            s2c_count: 0,
            avg_latency: 0.0f64,
        }
    }

    fn init(&mut self) {
        self.c2s_count = 0;
        self.s2c_count = 0;
        self.avg_latency = 0.0f64;
    }
}

// using the container makes compiler happy wrt. to static lifetime for the mydata content
pub struct Container {
    mydata: MyData,
}

impl UserData for Container {
    #[inline]
    fn ref_userdata(&self) -> &Any {
        &self.mydata
    }

    fn mut_userdata(&mut self) -> &mut Any {
        &mut self.mydata
    }

    fn init(&mut self) {
        self.mydata.init();
    }
}

impl Container {
    pub fn new() -> Box<Container> {
        Box::new(Container { mydata: MyData::new() })
    }
}

pub fn setup_pipelines<F1, F2>(
    core: i32,
    ports: HashSet<CacheAligned<PortQueue>>,
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
    let mut kni: Option<&CacheAligned<PortQueue>> = None;
    let mut pci: Option<&CacheAligned<PortQueue>> = None;
    for port in &ports {
        debug!(
            "setup_pipeline on core {}: port {} --  {} rxq {} txq {}",
            core,
            port.port,
            port.port.mac_address(),
            port.rxq(),
            port.txq(),
        );
        if port.port.is_kni() {
            kni = Some(port);
        } else {
            pci = Some(port);
        }
    }

    if pci.is_none() {
        panic!("need at least one pci port");
    }

    // kni receive queue is served on the first core (i.e. rxq==0)

    if kni.is_none() && is_kni_core(pci.unwrap()) {
        // we need a kni i/f for queue 0
        panic!("need one kni port for queue 0");
    }

    let uuid = Uuid::new_v4();
    let name = String::from("KniHandleRequest");

    if is_kni_core(pci.unwrap()) {
        sched.add_runnable(
            Runnable::from_task(
                uuid,
                name,
                KniHandleRequest {
                    kni_port: kni.unwrap().port.clone(),
                    last_tick: 0,
                },
            ).move_ready(), // this task must be ready from the beginning to enable managing the KNI i/f
        );
    }

    setup_forwarder(
        core,
        pci.unwrap(),
        kni.unwrap(),
        sched,
        engine_config,
        servers,
        flowdirector_map,
        tx,
        system_data,
        f_select_server,
        f_process_payload_c_s,
    );
}

pub fn spawn_recv_thread(mrx: Receiver<MessageFrom>, mut context: NetBricksContext, configuration: Configuration) {
    /*
        mrx: receiver for messages from all the pipelines running
    */
    let _handle = thread::spawn(move || {
        let mut senders = HashMap::new();
        let mut tasks: Vec<Vec<(PipelineId, Uuid)>> = Vec::with_capacity(TaskType::NoTaskTypes as usize);
        let mut reply_to_main = None;

        for _t in 0..TaskType::NoTaskTypes as usize {
            tasks.push(Vec::<(PipelineId, Uuid)>::with_capacity(16));
        }
        context.execute_schedulers();
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
                    &Ipv4Net::from_str(&configuration.engine.ipnet).unwrap(),
                    &configuration.engine.mac,
                    &configuration.engine.namespace,
                    if configuration.flow_steering_mode() == FlowSteeringMode::Ip {
                        context.active_cores.len() + 1
                    } else {
                        1
                    },
                );
            }
        }

        loop {
            match mrx.recv_timeout(Duration::from_millis(60000)) {
                Ok(MessageFrom::StartEngine(reply_channel)) => {
                    reply_to_main = Some(reply_channel);
                    debug!("received StartEngine");

                    for s in &context.scheduler_channels {
                        s.1.send(SchedulerCommand::SetTaskStateAll(true)).unwrap();
                    }
                }
                Ok(MessageFrom::PrintPerformance(indices)) => {
                    for i in &indices {
                        context
                            .scheduler_channels
                            .get(i)
                            .unwrap()
                            .send(SchedulerCommand::GetPerformance)
                            .unwrap();
                    }
                }
                Ok(MessageFrom::Task(pipeline_id, uuid, task_type)) => {
                    debug!("{}: task uuid= {}, type={:?}", pipeline_id, uuid, task_type);
                    tasks[task_type as usize].push((pipeline_id, uuid));
                }
                Ok(MessageFrom::Channel(pipeline_id, sender)) => {
                    debug!("got sender from {}", pipeline_id);
                    senders.insert(pipeline_id, sender);
                }
                Ok(MessageFrom::Exit) => {
                    debug!("received Exit");
                    // stop all tasks on all schedulers
                    for s in context.scheduler_channels.values() {
                        s.send(SchedulerCommand::SetTaskStateAll(false)).unwrap();
                    }

                    print_hard_statistics(1u16);

                    for port in context.ports.values() {
                        println!("Port {}:{}", port.port_type(), port.port_id());
                        port.print_soft_statistics();
                    }
                    println!("terminating ProxyEngine ...");
                    context.stop();
                    break;
                }
                Ok(MessageFrom::Counter(pipeline_id, tcp_counter_c, tcp_counter_s, tx_counter)) => {
                    debug!("{}: received Counter", pipeline_id);
                    if reply_to_main.is_some() {
                        reply_to_main
                            .as_ref()
                            .unwrap()
                            .send(MessageTo::Counter(pipeline_id, tcp_counter_c, tcp_counter_s, tx_counter))
                            .unwrap();
                    };
                }
                Ok(MessageFrom::FetchCounter) => {
                    for (_p, s) in &senders {
                        s.send(MessageTo::FetchCounter).unwrap();
                    }
                }
                Ok(MessageFrom::CRecords(pipeline_id, c_records_client, c_records_server)) => {
                    if reply_to_main.is_some() {
                        reply_to_main
                            .as_ref()
                            .unwrap()
                            .send(MessageTo::CRecords(pipeline_id, c_records_client, c_records_server))
                            .unwrap();
                    };
                }
                Ok(MessageFrom::FetchCRecords) => {
                    for (_p, s) in &senders {
                        s.send(MessageTo::FetchCRecords).unwrap();
                    }
                }

                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => {
                    error!("error receiving from message channel: {}", e);
                    break;
                }
                //_ => warn!("illegal message"),
            }
            match context
                .reply_receiver
                .as_ref()
                .unwrap()
                .recv_timeout(Duration::from_millis(10))
            {
                Ok(SchedulerReply::PerformanceData(core, map)) => {
                    for d in map {
                        info!(
                            "{:2}: {:20} {:>15} count= {:12}, queue length= {}",
                            core,
                            (d.1).0,
                            (d.1).1.separated_string(),
                            (d.1).2.separated_string(),
                            (d.1).3
                        )
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => {
                    error!("error receiving from SchedulerReply channel: {}", e);
                    break;
                }
            }
        }
        info!("exiting recv thread ...");
    });
}
