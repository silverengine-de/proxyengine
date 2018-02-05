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
    extern crate std;
    extern crate time;
    extern crate ipnet;

    use env_logger;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::env;
    use std::time::Duration;
    use std::thread;
    use std::any::Any;

    use self::ipnet::Ipv4Net;
    use std::net::Ipv4Addr;
    use std::net::{TcpStream, TcpListener, SocketAddr};
    use std::io::Write;
    use std::io::Read;

    use e2d2::config::{basic_opts, read_matches};
    use e2d2::scheduler::*;
    use e2d2::interface::*;
    use e2d2::allocators::CacheAligned;
    use e2d2::headers::MacAddress;

    use nftcp::*;

    const CONVERSION_FACTOR: f64 = 1000000000.;
    const KNI_NAME: &'static str = "vEth1"; //TODO use name from the argument list
    const KNI_NETNS: &'static str = "nskni";

    /// mac and IP address to assign to Linux KNI interface, i.e. the proxyengine
    const KNI_MAC: &'static str = "8e:f7:35:7e:73:91";
    const PROXY_IP: &'static str = "192.168.222.1/24";
    const PROXY_CPORT: u16 = 389;

    const TARGET_IP1: &'static str = "192.168.222.3";
    const TARGET_PORT1: u16 = 54321;
    const TARGET_MAC1: &'static str = "00:0c:29:64:43:ac"; //TODO get this from linux, maybe mac of gw

    const TARGET_IP2: &'static str = "192.168.222.3";
    const TARGET_PORT2: u16 = 54322;
    const TARGET_MAC2: &'static str = "00:0c:29:64:43:ac"; //TODO get this from linux, maybe mac of gw

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

    pub fn setup_pipelines<S>(ports: Vec<CacheAligned<PortQueue>>, sched: &mut S)
    where
        S: Scheduler + Sized,
    {
        let mut kni: Option<&CacheAligned<PortQueue>> = None;
        let mut pci: Option<&CacheAligned<PortQueue>> = None;
        for port in &ports {
            debug!(
                "setup_pipelines: port {} --  {} rxq {} txq {}",
                port.port.name(),
                port.port.mac_address(),
                port.rxq(),
                port.txq(),
            );
            if port.port.is_kni() {
                kni = Some(port);
                debug!("is kni port!");
                sched
                    .add_task(KniHandleRequest { kni_port: port.port.clone() })
                    .unwrap();
            } else {
                pci = Some(port);
            }
        }

        if kni.is_none() {
            panic!("need at least one kni port");
        }
        if pci.is_none() {
            panic!("need at least one pci port");
        }

        let proxy_data = L234Data {
            mac: MacAddress::parse_str(KNI_MAC).unwrap(),
            ip: u32::from(PROXY_IP.parse::<Ipv4Net>().unwrap().addr()),
            port: PROXY_CPORT,
        };

        let server_1 = L234Data {
            mac: MacAddress::parse_str(TARGET_MAC1).unwrap(),
            ip: u32::from(TARGET_IP1.parse::<Ipv4Addr>().unwrap()),
            port: TARGET_PORT1,
        };

        let server_2 = L234Data {
            mac: MacAddress::parse_str(TARGET_MAC2).unwrap(),
            ip: u32::from(TARGET_IP2.parse::<Ipv4Addr>().unwrap()),
            port: TARGET_PORT2,
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



    #[test]
    fn delayed_binding_proxy() {

        let timeout = Duration::from_millis(500 as u64);

        fn am_root() -> bool {
            match env::var("USER") {
                Ok(val) => val == "root",
                Err(e) => false,
            }
        }

        env_logger::init().unwrap();
        debug!("Testing ProxyEngine ...");
        if !am_root() {
            error!(" ... must run as root, e.g.: sudo -E env \"PATH=$PATH\" cargo test");
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

        // let args: Vec<String> = env::args().collect();
        let args: Vec<String> = vec![
            "proxyengine",
            "-m",
            "0",
            "-c",
            "1",
            "-c",
            "1",
            "-p",
            "03:00.0",
            "-p",
            "kni:vEth1",
            "-n",
            "proxyengine",
            "--primary",
            "--vdev",
            "net_kni0",
        ].iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let matches = match opts.parse(&args[1..]) {
            Ok(m) => m,
            Err(f) => panic!(f.to_string()),
        };
        let configuration = read_matches(&matches, &opts);
        let b_phy_ports = !matches.opt_present("test");

        //  let (tx, rx) = channel::<TcpEvent>();

        match initialize_system(&configuration) {
            //    match initialize_system::<TcpEvent>(&configuration) {
            Ok(mut context) => {
                context.start_schedulers();
                debug!("Number of PMD ports: {}", PmdPort::num_pmd_ports());
                for port in context.ports.values() {
                    debug!("port {} : mac_address= {}", port.name(), port.mac_address());
                }

                if b_phy_ports {
                    context.add_pipeline_to_run(Arc::new(move |p: Vec<CacheAligned<PortQueue>>,
                          s: &mut StandaloneScheduler| {
                        setup_pipelines(p, s)
                    }));
                }

                context.execute();

                setup_kni(KNI_NAME, PROXY_IP, KNI_MAC, KNI_NETNS);

                thread::spawn(|| {
                    let listener1: TcpListener;
                    if let Ok(listener1) = TcpListener::bind((TARGET_IP1, TARGET_PORT1)) {
                        debug!("bound first TcpListener to {}:{}", TARGET_IP1, TARGET_PORT1);
                        for stream in listener1.incoming() {
                            let mut stream = stream.unwrap();
                            let mut buf = [0u8; 16];
                            stream.read(&mut buf[..]);
                            debug!("first listener received a {}", buf[0]);
                            stream.write(&[11u8]);
                        }
                    } else {
                        panic!(
                            "failed to bind first TcpListener to {}:{}",
                            TARGET_IP1,
                            TARGET_PORT1
                        );
                    }
                });

                thread::spawn(|| {
                    let listener2: TcpListener;
                    if let Ok(listener2) = TcpListener::bind((TARGET_IP2, TARGET_PORT2)) {
                        debug!(
                            "bound second TcpListener to {}:{}",
                            TARGET_IP2,
                            TARGET_PORT2
                        );
                        for stream in listener2.incoming() {
                            let mut stream = stream.unwrap();
                            let mut buf = [0u8; 16];
                            stream.read(&mut buf[..]);
                            debug!("second listener received a {}", buf[0]);
                            stream.write(&[12u8]);
                        }
                    } else {
                        panic!(
                            "failed to bind second TcpListener to {}:{}",
                            TARGET_IP2,
                            TARGET_PORT2
                        );
                    }
                });

                thread::sleep(Duration::from_millis(100 as u64)); // wait for the listeners

                // create a first test connection
                if let Ok(mut stream1) = TcpStream::connect_timeout(
                    &SocketAddr::from((
                        PROXY_IP.parse::<Ipv4Net>().unwrap().addr(),
                        PROXY_CPORT,
                    )),
                    timeout,
                )
                {
                    debug!("first test connection: TCP connect to proxy successful");
                    stream1.set_write_timeout(Some(timeout));
                    stream1.set_read_timeout(Some(timeout));
                    if let Ok(_) = stream1.write(&[1u8]) {
                        debug!("success in writing to first test connection");
                        let mut buf = [0u8; 16];
                        if let Ok(_) = stream1.read(&mut buf[..]) {
                            if buf[0] == 11u8 {
                                info!("reply on first connection is ok!");
                            } else {
                                panic!("wrong reply on first connection");
                            }
                        } else {
                            panic!("timeout on first connection while waiting for answer");
                        };
                    } else {
                        panic!("error when writing to first test connection");
                    }
                } else {
                    panic!("first test connection: 3-way handshake with proxy failed");
                }

                // create a second test connection
                if let Ok(mut stream2) = TcpStream::connect_timeout(
                    &SocketAddr::from((
                        PROXY_IP.parse::<Ipv4Net>().unwrap().addr(),
                        PROXY_CPORT,
                    )),
                    timeout,
                )
                {
                    debug!("second test connection: TCP connect to proxy successful");
                    stream2.set_write_timeout(Some(timeout));
                    stream2.set_read_timeout(Some(timeout));
                    if let Ok(_) = stream2.write(&[2u8]) {
                        debug!("success in writing to second test connection");
                        let mut buf = [0u8; 16];
                        if let Ok(_) = stream2.read(&mut buf[..]) {
                            if buf[0] == 12u8 {
                                info!("reply on second connection is ok!");
                            } else {
                                panic!("wrong reply on second connection");
                            }
                        } else {
                            panic!("timeout on second connection while waiting for answer");
                        };
                    } else {
                        panic!("error when writing to second test connection");
                    }
                } else {
                    panic!("second test connection: 3-way handshake with proxy failed");
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
