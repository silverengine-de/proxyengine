#![feature(box_syntax)]
#![feature(integer_atomics)]
#![feature(trait_alias)]

// Logging
#[macro_use]
extern crate log;
extern crate e2d2;
extern crate env_logger;
extern crate fnv;
extern crate toml;
extern crate separator;
#[macro_use]
extern crate serde_derive;
extern crate eui48;
extern crate ipnet;
extern crate serde;
extern crate uuid;
extern crate netfcts;

mod nftcp;
mod cmanager;

pub use cmanager::{ProxyConnection, Extension, ProxyRecStore};

use netfcts::tasks::TaskType;
use netfcts::tasks::KniHandleRequest;
use eui48::MacAddress;
use uuid::Uuid;
use separator::Separatable;

use e2d2::common::ErrorKind as E2d2ErrorKind;
use e2d2::scheduler::*;
use e2d2::interface::{PmdPort, FlowDirector};

use netfcts::io::print_hard_statistics;
use nftcp::setup_delayed_proxy;
use netfcts::{setup_kernel_interfaces, new_port_queues_for_core, physical_ports_for_core};
use netfcts::comm::{MessageFrom, MessageTo, PipelineId};
use netfcts::system::SystemData;
use netfcts::tcp_common::{L234Data, UserData};

use std::fs::File;
use std::io::Read;
use std::any::Any;
use std::net::Ipv4Addr;
use std::collections::{HashMap, };
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::RecvTimeoutError;

pub trait FnSelectServer = Fn(&mut ProxyConnection) + Sized + Send + Sync + Clone + 'static;
pub trait FnPayload = Fn(&mut ProxyConnection, &mut [u8], usize) + Sized + Send + Sync + Clone + 'static;

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

#[derive(Deserialize, Clone, PartialEq)]
pub enum ProxyMode {
    DelayedV0,
    Delayed,
}

#[derive(Deserialize, Clone)]
pub struct EngineConfig {
    pub timeouts: Option<Timeouts>,
    pub port: u16,
    pub detailed_records: Option<bool>,
    pub mode: Option<ProxyMode>,
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

pub fn read_config(filename: &str) -> e2d2::common::Result<Configuration> {
    let mut toml_str = String::new();
    if File::open(filename)
        .and_then(|mut f| f.read_to_string(&mut toml_str))
        .is_err()
    {
        return Err(E2d2ErrorKind::ConfigurationError(format!("Could not read file {}", filename)));
    }

    info!("toml configuration:\n {}", toml_str);

    let config: Config = match toml::from_str(&toml_str) {
        Ok(value) => value,
        Err(err) => return Err(err.into()),
    };

    Ok(config.proxyengine)
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

pub fn setup_pipes_delayed_proxy<F1, F2>(
    core: i32,
    pmd_ports: HashMap<String, Arc<PmdPort>>,
    sched: &mut StandaloneScheduler,
    engine_config: &EngineConfig,
    servers: Vec<L234Data>,
    flowdirector_map: HashMap<u16, Arc<FlowDirector>>,
    tx: Sender<MessageFrom<ProxyRecStore>>,
    system_data: SystemData,
    f_select_server: F1,
    f_process_payload_c_s: F2,
) where
    F1: FnSelectServer,
    F2: FnPayload,
{
    for pmd_port in physical_ports_for_core(core, &pmd_ports) {
        debug!("setup_pipelines for {} on core {}:", pmd_port.name(), core);
        let mut kni_port = None;
        if pmd_port.kni_name().is_some() {
            kni_port = pmd_ports.get(pmd_port.kni_name().unwrap());
        }
        let (pci, kni) = new_port_queues_for_core(core, &pmd_port, kni_port);
        if pci.is_some() {
            debug!(
                "pmd_port= {}, rxq= {}",
                pci.as_ref().unwrap().port_queue.port,
                pci.as_ref().unwrap().port_queue.rxq()
            );
        } else {
            debug!("pmd_port= None");
        }

        if kni.is_some() {
            debug!(
                "associated kni= {}, rxq= {}",
                kni.as_ref().unwrap().port,
                kni.as_ref().unwrap().rxq()
            );
        } else {
            debug!("associated kni= None");
        }

        let uuid = Uuid::new_v4();
        let name = String::from("KniHandleRequest");

        // Kni request handler runs on first core of the associated pci port (rxq == 0)
        if pci.is_some()
            && kni.is_some()
            && kni.as_ref().unwrap().port.is_native_kni()
            && pci.as_ref().unwrap().port_queue.rxq() == 0
        {
            sched.add_runnable(
                Runnable::from_task(
                    uuid,
                    name,
                    KniHandleRequest {
                        kni_port: kni.as_ref().unwrap().port.clone(),
                        last_tick: 0,
                    },
                )
                .move_ready(), // this task must be ready from the beginning to enable managing the KNI i/f
            );
        }

        if pci.is_some() && kni.is_some() {
            setup_delayed_proxy(
                core,
                pci.unwrap(),
                kni.unwrap(),
                sched,
                engine_config,
                servers.clone(),
                &flowdirector_map,
                &tx,
                system_data.clone(),
                f_select_server.clone(),
                f_process_payload_c_s.clone(),
            );
        }
    }
}

pub fn spawn_recv_thread(mrx: Receiver<MessageFrom<ProxyRecStore>>, mut context: NetBricksContext) {
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

        setup_kernel_interfaces(&context);

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
                Ok(MessageFrom::TimeStamps(p, t0, t1)) => {
                    if reply_to_main.is_some() {
                        reply_to_main
                            .as_ref()
                            .unwrap()
                            .send(MessageTo::TimeStamps(p, t0, t1))
                            .unwrap();
                    };
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
