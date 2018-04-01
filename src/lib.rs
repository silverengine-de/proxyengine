#![feature(box_syntax)]
#![feature(tcpstream_connect_timeout)]

// Logging
#[macro_use]
extern crate log;
extern crate e2d2;
extern crate env_logger;
extern crate fnv;
extern crate rand;
extern crate toml;
#[macro_use]
extern crate serde_derive;
extern crate eui48;
extern crate ipnet;
extern crate serde;
#[macro_use]
extern crate error_chain;

pub mod nftcp;
pub use nftcp::L234Data;
pub mod errors;

use std::fs::File;
use std::io::Read;
use std::any::Any;
use std::net::Ipv4Addr;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::ptr;

use ipnet::Ipv4Net;
use eui48::MacAddress;

use e2d2::native::zcsi::*;
use e2d2::common::ErrorKind as E2d2ErrorKind;
use e2d2::scheduler::*;
use e2d2::allocators::CacheAligned;
use e2d2::interface::PortQueue;

use errors::*;
use nftcp::*;

#[derive(Deserialize)]
struct Config {
    proxyengine: ProxyEngineConfig,
}

#[derive(Deserialize, Clone)]
pub struct ProxyEngineConfig {
    pub servers: Vec<ProxyServerConfig>,
    pub proxy: ProxyConfig,
    queries: Option<usize>,
}

#[derive(Deserialize, Clone)]
pub struct ProxyConfig {
    pub namespace: String,
    pub mac: String,
    pub ipnet: String,
    pub port: u16,
}

#[derive(Deserialize, Clone)]
pub struct ProxyServerConfig {
    pub id: String,
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddress>,
    pub linux_if: Option<String>,
    pub port: u16,
}

pub fn read_proxy_config(filename: &str) -> Result<ProxyEngineConfig> {
    let mut toml_str = String::new();
    let _ = File::open(filename)
        .and_then(|mut f| f.read_to_string(&mut toml_str))
        .chain_err(|| E2d2ErrorKind::ConfigurationError(format!("Could not read file {}", filename)))?;

    let config: Config = match toml::from_str(&toml_str) {
        Ok(value) => value,
        Err(err) => return Err(err.into()),
    };

    match config.proxyengine.proxy.ipnet.parse::<Ipv4Net>() {
        Ok(_) => match config.proxyengine.proxy.mac.parse::<MacAddress>() {
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

pub fn get_mac_from_ifname(ifname: &str) -> Result<MacAddress> {
    let iface = Path::new("/sys/class/net").join(ifname).join("address");
    let mut macaddr = String::new();
    fs::File::open(iface).map_err(|e| e.into()).and_then(|mut f| {
        f.read_to_string(&mut macaddr)
            .map_err(|e| e.into())
            .and_then(|_| MacAddress::parse_str(&macaddr.lines().next().unwrap_or("")).map_err(|e| e.into()))
    })
}

pub fn print_hard_statistics(port_id: u16) -> i32 {
    let stats = RteEthStats::new();
    let retval;
    unsafe {
        retval = rte_eth_stats_get(port_id, &stats as *const RteEthStats);
    }
    if retval == 0 {
        println!("Port {}:\n{}\n", port_id, stats);
    }
    retval
}

pub fn print_soft_statistics(port_id: u16) -> i32 {
    let stats = RteEthStats::new();
    let retval;
    unsafe {
        retval = rte_eth_stats_get(port_id, &stats as *const RteEthStats);
    }
    if retval == 0 {
        println!("Port {}:\n{}\n", port_id, stats);
    }
    retval
}

pub fn print_xstatistics(port_id: u16) -> i32 {
    let len;
    unsafe {
        len = rte_eth_xstats_get_names_by_id(port_id, ptr::null(), 0, ptr::null());
        if len < 0 {
            return len;
        }
        let xstats_names = vec![
            RteEthXstatName {
                name: [0i8; RTE_ETH_XSTATS_NAME_SIZE],
            };
            len as usize
        ];
        let ids = vec![0u64; len as usize];
        if len != rte_eth_xstats_get_names_by_id(port_id, xstats_names.as_ptr(), len as u32, ptr::null()) {
            return -1;
        };
        let values = vec![0u64; len as usize];

        if len != rte_eth_xstats_get_by_id(port_id, ptr::null(), values.as_ptr(), 0 as u32) {
            return -1;
        }

        for i in 0..len as usize {
            rte_eth_xstats_get_id_by_name(port_id, xstats_names[i].to_ptr(), &ids[i]);
            {
                println!("{}, {}: {}", i, xstats_names[i].to_str().unwrap(), values[i]);
            }
        }
    }
    len
}

pub fn setup_pipelines<S, F1, F2>(
    core: i32,
    ports: HashSet<CacheAligned<PortQueue>>,
    sched: &mut S,
    proxy_config: ProxyEngineConfig,
    f_select_server: Arc<F1>,
    f_process_payload_c_s: Arc<F2>,
) where
    S: Scheduler + Sized,
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

    if is_kni_core(pci.unwrap()) {
        sched
            .add_task(KniHandleRequest {
                kni_port: kni.unwrap().port.clone(),
            })
            .unwrap();
    }

    let proxy_data = L234Data {
        mac: MacAddress::parse_str(&proxy_config.proxy.mac).unwrap(),
        ip: u32::from(proxy_config.proxy.ipnet.parse::<Ipv4Net>().unwrap().addr()),
        port: proxy_config.proxy.port,
    };

    setup_forwarder(
        core,
        pci.unwrap(),
        kni.unwrap(),
        sched,
        proxy_data,
        f_select_server,
        f_process_payload_c_s,
        //        u32::from(CLIENT_IP.parse::<Ipv4Addr>().unwrap()),
        //        MacAddress::parse_str(CLIENT_MAC).unwrap(),
    );
}

#[cfg(test)]
mod tests {

    extern crate ctrlc;
    extern crate time;

    use log;
    use env_logger;
    use std;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::env;
    use std::time::Duration;
    use std::thread;
    use std::collections::HashSet;
    use std::io::Read;
    use std::io::Write;
    use std::net::{SocketAddr, TcpListener, TcpStream};

    use ipnet::Ipv4Net;

    use e2d2::config::{basic_opts, read_matches};
    use e2d2::native::zcsi::*;
    use e2d2::interface::{PmdPort, PortQueue};
    use e2d2::scheduler::{initialize_system, StandaloneScheduler};
    use e2d2::allocators::CacheAligned;

    use nftcp::{setup_kni, Connection};
    use read_proxy_config;
    use setup_pipelines;
    use get_mac_from_ifname;
    use print_hard_statistics;
    use Container;
    use L234Data;

    #[test]
    fn delayed_binding_proxy() {
        env_logger::init();
        info!("Testing ProxyEngine ..");

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
        let timeout = Duration::from_millis(1000 as u64);

        let proxy_config = read_proxy_config("proxy.toml").unwrap();

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
            error!(
                " ... must run as root, e.g.: sudo -E env \"PATH=$PATH\" $executable, see also test.sh\nDo not run 'cargo test' as root."
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

        let args: Vec<String> = vec!["proxyengine", "-f", "proxy.toml"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let matches = match opts.parse(&args[1..]) {
            Ok(m) => m,
            Err(f) => panic!(f.to_string()),
        };
        let mut configuration = read_matches(&matches, &opts);

        //  let (tx, rx) = channel::<TcpEvent>();

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
        let f_process_payload_c_s = |_c: &mut Connection, _payload: &mut [u8], _tailroom: usize| {
            /*
            if let IResult::Done(_, c_tag) = parse_tag(payload) {
                let userdata: &mut MyData = &mut c.userdata
                    .as_mut()
                    .unwrap()
                    .mut_userdata()
                    .downcast_mut()
                    .unwrap();
                userdata.c2s_count += payload.len();
                debug!(
                    "c->s (tailroom { }, {:?}): {:?}",
                    tailroom,
                    userdata,
                    c_tag,
                );
            }

            unsafe {
                let payload_sz = payload.len(); }
                let p_payload= payload[0] as *mut u8;
                process_payload(p_payload, payload_sz, tailroom);
            } */
        };

        match initialize_system(&mut configuration) {
            Ok(mut context) => {
                context.start_schedulers();

                let proxy_config_cloned = proxy_config.clone();
                let boxed_fss = Arc::new(f_select_server);
                let boxed_fpp = Arc::new(f_process_payload_c_s);
                context.add_pipeline_to_run(Arc::new(
                    move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler| {
                        setup_pipelines(core, p, s, proxy_config_cloned.clone(), boxed_fss.clone(), boxed_fpp.clone())
                    },
                ));

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

                // set up servers
                for server in proxy_config.servers {
                    let target_port = server.port; // moved into thread
                    let target_ip = server.ip;
                    let id = server.id;
                    thread::spawn(move || match TcpListener::bind((target_ip, target_port)) {
                        Ok(listener1) => {
                            debug!("bound server {} to {}:{}", id, target_ip, target_port);
                            for stream in listener1.incoming() {
                                let mut stream = stream.unwrap();
                                let mut buf = [0u8; 256];
                                stream.read(&mut buf[..]).unwrap();
                                debug!("server {} received: {}", id, String::from_utf8(buf.to_vec()).unwrap());
                                stream.write(&format!("Thank You from {}", id).to_string().into_bytes()).unwrap();
                            }
                        }
                        _ => {
                            panic!("failed to bind server {} to {}:{}", id, target_ip, target_port);
                        }
                    });
                }

                thread::sleep(Duration::from_millis(2000 as u64)); // wait for the servers

                // emulate clients
                for ntry in 0..proxy_config.queries.unwrap() {
                    match TcpStream::connect_timeout(
                        &SocketAddr::from((proxy_config.proxy.ipnet.parse::<Ipv4Net>().unwrap().addr(), proxy_config.proxy.port)),
                        timeout,
                    ) {
                        Ok(mut stream) => {
                            debug!("test connection {}: TCP connect to proxy successful", ntry);
                            stream.set_write_timeout(Some(timeout)).unwrap();
                            stream.set_read_timeout(Some(timeout)).unwrap();
                            match stream.write(&format!("{} stars", ntry).to_string().into_bytes()) {
                                Ok(_) => {
                                    debug!("successfully send {} stars", ntry);
                                    let mut buf = [0u8; 256];
                                    match stream.read(&mut buf[..]) {
                                        Ok(_) => info!("on try {} we received {}", ntry, String::from_utf8(buf.to_vec()).unwrap()),
                                        _ => {
                                            panic!("timeout on connection {} while waiting for answer", ntry);
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

                debug!("main thread goes sleeping ...");
                thread::sleep(Duration::from_millis(2000 as u64)); // Sleep for a bit
                debug!("main thread awake again");
                print_hard_statistics(1u16);

                for port in context.ports.values() {
                    println!("Port {}:{}", port.port_type(), port.port_id());
                    port.print_soft_statistics();
                }

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
}
