#![feature(box_syntax)]

// Logging
#[macro_use]
extern crate log;
extern crate env_logger;

extern crate e2d2;
extern crate fnv;
extern crate rand;

mod nftcp;

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

    use e2d2::config::{basic_opts, read_matches};
    use e2d2::scheduler::*;
    use e2d2::interface::*;
    use e2d2::allocators::CacheAligned;
    use e2d2::headers::MacAddress;

    use nftcp::*;

    const CONVERSION_FACTOR: f64 = 1000000000.;
    const KNI_NAME: &'static str = "vEth1"; //TODO use name from the argument list

    /// mac and IP address to assign to Linux KNI interface
    const KNI_MAC: &'static str = "8e:f7:35:7e:73:91";
    const PROXY_IP: &'static str = "192.168.222.1/24";
    const PROXY_CPORT: u16 = 389;

    const TARGET_IP1: &'static str = "192.168.222.4";
    const TARGET_PORT1: u16 = 2389;
    const TARGET_MAC1: &'static str = "00:0c:29:64:43:b6"; //TODO get this from linux, maybe mac of gw

    const TARGET_IP2: &'static str = "192.168.222.5";
    const TARGET_PORT2: u16 = 2389;
    const TARGET_MAC2: &'static str = "00:0c:29:64:43:c0"; //TODO get this from linux, maybe mac of gw

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
            } else {
                c.server = Some(server_2);
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
        }).expect("Error setting Ctrl-C handler");


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

                setup_kni(KNI_NAME, PROXY_IP, KNI_MAC);

                let mut pkts_so_far = (0, 0);
                let mut last_printed = 0.;
                const MAX_PRINT_INTERVAL: f64 = 30.;
                const PRINT_DELAY: f64 = 15.;
                let sleep_delay = 10 as u64;
                let mut start = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
                let start0 = start;
                let sleep_time = Duration::from_millis(sleep_delay);

                info!("0 OVERALL RX 0.00 TX 0.00 CYCLE_PER_DELAY 0 0 0");
                while running.load(Ordering::SeqCst) {
                    thread::sleep(sleep_time); // Sleep for a bit
                    let now = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
                    if now - start > PRINT_DELAY {
                        let mut rx = 0;
                        let mut tx = 0;
                        for port in context.ports.values() {
                            for q in 0..port.rxqs() {
                                let (rp, tp) = port.stats(q);
                                rx += rp;
                                tx += tp;
                            }
                        }
                        let pkts = (rx, tx);
                        let rx_pkts = pkts.0 - pkts_so_far.0;
                        if rx_pkts > 0 || now - last_printed > MAX_PRINT_INTERVAL {
                            info!(
                                "{:.2}: {:.2} OVERALL RX {:.2} TX {:.2}",
                                now - start0,
                                now - start,
                                rx_pkts as f64 / (now - start),
                                (pkts.1 - pkts_so_far.1) as f64 / (now - start)
                            );
                            last_printed = now;
                            start = now;
                            pkts_so_far = pkts;
                        }
                    }
                }
                info!("terminating Opticur ...");
                std::process::exit(0);
            }
            Err(ref e) => {
                error!("Error: {}", e);
                if let Some(backtrace) = e.backtrace() {
                    error!("Backtrace: {:?}", backtrace);
                }
                std::process::exit(1);
            }
        }
    }
}
