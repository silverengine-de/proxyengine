#![feature(box_syntax)]
#![feature(tcpstream_connect_timeout)]

// Logging
#[macro_use]
extern crate log;
extern crate env_logger;

extern crate e2d2;
extern crate fnv;
extern crate rand;

pub mod nftcp;

#[cfg(test)]
mod tests {

    extern crate ctrlc;
    extern crate ipnet;
    extern crate std;
    extern crate time;

    use env_logger;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::env;
    use std::time::Duration;
    use std::thread;
    use std::any::Any;
    use std::collections::HashSet;

    use self::ipnet::Ipv4Net;
    use std::net::Ipv4Addr;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::io::Write;
    use std::io::Read;
    use std::fs;
    use std::path::Path;

    use rand;
    use rand::distributions::{Sample, Range};
    use log;

    use e2d2::config::{basic_opts, read_matches};
    use e2d2::scheduler::*;
    use e2d2::interface::*;
    use e2d2::allocators::CacheAligned;
    use e2d2::headers::{MacAddress, ParseError};
    use e2d2::native::zcsi::*;

    use nftcp::*;

    const CONVERSION_FACTOR: f64 = 1000000000.;
    const KNI_NAME: &'static str = "vEth1_0"; //TODO use name from the argument list
    const KNI_NETNS: &'static str = "nskni";

    /// mac and IP address to assign to Linux KNI interface, i.e. the proxyengine
    const KNI_MAC: &'static str = "8e:f7:35:7e:73:91";
    const PROXY_IP: &'static str = "192.168.222.1/24";
    const PROXY_CPORT: u16 = 999;

    // only for test:
    const LINUX_IFACE: &'static str = "enp7s0f1";
    const TARGET_IP: &'static str = "192.168.222.3";
    const TARGET_PORT_BASE: u16 = 0xE000;

    /* not necessary for test
    const TARGET_IP1: &'static str = "192.168.222.3";
    const TARGET_PORT1: u16 = 54321;
    const TARGET_MAC1: &'static str = "a0:36:9f:82:9c:fe"; //TODO get this from linux, but maybe mac of gw

    const TARGET_IP2: &'static str = "192.168.222.3";
    const TARGET_PORT2: u16 = 54322;
    const TARGET_MAC2: &'static str = "a0:36:9f:82:9c:fe"; //TODO get this from linux, but maybe mac of gw
    */

    #[derive(Debug, Clone)]

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
    struct Container {
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
        fn new() -> Box<Container> {
            Box::new(Container { mydata: MyData::new() })
        }
    }

    pub fn setup_pipelines<S>(
        core: i32,
        ports: HashSet<CacheAligned<PortQueue>>,
        sched: &mut S,
        target_port: u16)
    where
        S: Scheduler + Sized,
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
            mac: MacAddress::parse_str(KNI_MAC).unwrap(),
            ip: u32::from(PROXY_IP.parse::<Ipv4Net>().unwrap().addr()),
            port: PROXY_CPORT,
        };

        let server_1 = L234Data {
            mac: get_mac_from_ifname(LINUX_IFACE).unwrap(),
            ip: u32::from(TARGET_IP.parse::<Ipv4Addr>().unwrap()),
            port: target_port,
        };

        let server_2 = L234Data {
            mac: get_mac_from_ifname(LINUX_IFACE).unwrap(),
            ip: u32::from(TARGET_IP.parse::<Ipv4Addr>().unwrap()),
            port: target_port+1,
        };

        debug!("server_macs = 1->{} 2->{}", server_1.mac, server_2.mac);

        let f_select_server = move |c: &mut Connection| {
            if c.payload[0] & 1u8 == 1u8 {
                c.server = Some(server_1);
                info!("selecting server 1");
            } else {
                c.server = Some(server_2);
                info!("selecting server 2");
            }

            if let Some(_) = c.userdata {
                c.userdata.as_mut().unwrap().init();
            } else {
                c.userdata = Some(Container::new());
            }
        };

        let f_process_payload_c_s = |c: &mut Connection, payload: &mut [u8], tailroom: usize| {
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

    fn get_mac_from_ifname(ifname: &str) -> Result<MacAddress, ParseError> {
        let iface = Path::new("/sys/class/net").join(ifname).join("address");
        /*
        let mut f = fs::File::open(iface).unwrap();
        f.read_to_string(&mut macaddr).unwrap();
        MacAddress::parse_str(&macaddr)
        */
        let mut macaddr = String::new();
        fs::File::open(iface).map_err(|e| ParseError::IOError(e)).and_then(|mut f| {
            f.read_to_string(&mut macaddr)
                .map_err(|e| ParseError::IOError(e))
                .and_then(|_| MacAddress::parse_str(&macaddr.lines().next().unwrap()))
        })
    }

    #[test]
    fn delayed_binding_proxy() {
        env_logger::init();
        info!("Testing ProxyEngine ..");

        let log_level_rte= if log_enabled!(log::Level::Debug) { RteLogLevel::RteLogDebug } else { RteLogLevel::RteLogInfo};
        unsafe {
            rte_log_set_global_level(log_level_rte);
            rte_log_set_level(RteLogtype::RteLogtypePmd, log_level_rte);
            info!("dpdk log global level: {}", rte_log_get_global_level());
            info!("dpdk log level for PMD: {}", rte_log_get_level(RteLogtype::RteLogtypePmd));
        }
        let timeout = Duration::from_millis(1000 as u64);

        fn am_root() -> bool {
            match env::var("USER") {
                Ok(val) => val == "root",
                Err(e) => false,
            }
        }

        if !am_root() {
            error!(" ... must run as root, e.g.: sudo -E env \"PATH=$PATH\" $executable, see also test.sh");
            std::process::exit(1);
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            info!("received SIGINT or SIGTERM");
            r.store(false, Ordering::SeqCst);
        }).expect("error setting Ctrl-C handler");

        let mut opts = basic_opts();
        opts.optflag("t", "test", "Test mode do not use real ports");

        let args: Vec<String> = vec!["proxyengine", "-f", "proxy.toml"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let matches = match opts.parse(&args[1..]) {
            Ok(m) => m,
            Err(f) => panic!(f.to_string()),
        };
        let mut configuration = read_matches(&matches, &opts);
        let b_phy_ports = !matches.opt_present("test");

        //  let (tx, rx) = channel::<TcpEvent>();

        match initialize_system(&mut configuration) {
            Ok(mut context) => {
                context.start_schedulers();
                debug!("Number of PMD ports: {}", PmdPort::num_pmd_ports());
                for port in context.ports.values() {
                    debug!(
                        "port {}:{} -- mac_address= {}",
                        port.port_type(),
                        port.port_id(),
                        port.mac_address()
                    );
                }

                let mut rng = rand::thread_rng();
                let mut between = Range::new(TARGET_PORT_BASE, 0xFFFF);
                let target_port = between.sample(&mut rng);
                if b_phy_ports {
                    context.add_pipeline_to_run(Arc::new(
                        move |core: i32, p: HashSet<CacheAligned<PortQueue>>, s: &mut StandaloneScheduler|
                            setup_pipelines(core, p, s, target_port),
                    ));
                }
                context.execute();
                setup_kni(KNI_NAME, PROXY_IP, KNI_MAC, KNI_NETNS);

                let target_port_copy = target_port; // moved into thread
                thread::spawn(move || {
                    let listener1: TcpListener;
                    if let Ok(listener1) = TcpListener::bind((TARGET_IP, target_port_copy)) {
                        debug!("bound first TcpListener to {}:{}", TARGET_IP, target_port_copy);
                        for stream in listener1.incoming() {
                            let mut stream = stream.unwrap();
                            let mut buf = [0u8; 16];
                            stream.read(&mut buf[..]);
                            debug!("first listener received a {}", buf[0]);
                            stream.write(&[11u8]);
                        }
                    } else {
                        panic!("failed to bind first TcpListener to {}:{}", TARGET_IP, target_port_copy);
                    }
                });

                let target_port_copy = target_port; // moved into thread
                thread::spawn(move || {
                    let listener2: TcpListener;
                    if let Ok(listener2) = TcpListener::bind((TARGET_IP, target_port_copy + 1u16)) {
                        debug!("bound second TcpListener to {}:{}", TARGET_IP, target_port_copy + 1u16);
                        for stream in listener2.incoming() {
                            let mut stream = stream.unwrap();
                            let mut buf = [0u8; 16];
                            stream.read(&mut buf[..]);
                            debug!("second listener received a {}", buf[0]);
                            stream.write(&[12u8]);
                        }
                    } else {
                        panic!("failed to bind second TcpListener to {}:{}", TARGET_IP, target_port_copy + 1u16);
                    }
                });

                thread::sleep(Duration::from_millis(2000 as u64)); // wait for the listeners
                // start setting up and releasing TCP connections
                let mut data= Range::new(1u8,3u8);
                for ntry in 1..100 {
                    if let Ok(mut stream) = TcpStream::connect_timeout(
                        &SocketAddr::from((PROXY_IP.parse::<Ipv4Net>().unwrap().addr(), PROXY_CPORT)),
                        timeout,
                    ) {
                        debug!("test connection {}: TCP connect to proxy successful", ntry);
                        stream.set_write_timeout(Some(timeout));
                        stream.set_read_timeout(Some(timeout));
                        let mut query:u8=data.sample(&mut rng);
                        if let Ok(_) = stream.write(&[query]) {
                            debug!("success in writing to test connection {}", ntry);
                            let mut buf = [0u8; 16];
                            if let Ok(_) = stream.read(&mut buf[..]) {
                                if query == 1u8 && buf[0] == 11u8 || query == 2u8 && buf[0] == 12u8 {
                                    info!("reply on connection {} is ok!", ntry);
                                } else {
                                    panic!("wrong reply on connection {}", ntry);
                                }
                            } else {
                                panic!("timeout on connection {} while waiting for answer", ntry);
                            };
                        } else {
                            panic!("error when writing to test connection {}", ntry);
                        }
                    } else {
                        panic!("test connection {}: 3-way handshake with proxy failed", ntry);
                    }
                }


                debug!("main thread goes sleeping ...");
                thread::sleep(Duration::from_millis(2000 as u64)); // Sleep for a bit
                debug!("main thread awake again");

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
