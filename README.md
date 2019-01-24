#### ProxyEngine Overview

ProxyEngine is a user-space TCP-proxy written in Rust with following properties
* TCP pass-through
* customizable delayed binding
* high performance: multi-core, shared nothing, locking-free architecture
* client side receive side scaling (RSS), server side receive flow steering (RFS) by NIC
* customizable payload inspection and manipulation

It may be used for intelligent load-balancing and fire-walling of TCP based protocols, e.g. LDAP. Late binding allows to select the target server not till the first payload packet after the initial three-way hand-shake is received. In addition callbacks can be defined by which the proxy can modify the payload of the TCP based protocol. For this purpose additional connection state is maintained by the ProxyEngine.

First benchmarking shows that ProxyEngine can handle about 200,000 connections per second (cps) per core. Each connection exchanges seven packets between client and server.

Scaling happens by distributing incoming client-side TCP connections using RSS over the cores and by steering the incoming server side TCP connections to the appropriate core. This receive flow steering can be either based on the port or on the IP address of the server side connection (selected by parameter _flow_steering_ in the toml configuration file). In the first case port resources of the proxy are assigned to cores (based on paramater _dst_port_mask_ in the configuration file). In the second case each core uses a unique IP address for the server side connections.     

#### Architecture and Implementation

ProxyEngine builds on a fork of [Netbricks](https://github.com/NetSys/NetBricks) for the user-space networking. 
NetBricks itself utilizes _DPDK_ for fast I/O. 
NetBricks uses a significantly higher abstraction level than _DPDK_. 
This allows for quick and straight forward implementation of complex network functions by placing building blocks like packet filters and generators, flow splitters and mergers into a directed graph.
As all functions in the graph operate in the same memory space there is no need to copy memory (zero copy approach), or even worse to move packets between VNFs. 
This optimizes overall energy consumption and performance.
This is in obvious contrast to classical network function virtualization (NFV) concept using e.g. virtual machines to implement network functions (VNFs).
A very similar zero copy approach is currently followed by the Intel [NFF-Go](https://github.com/intel-go/nff-go) project.

We are using the above concept of NetBricks to implement a rather complex network function, namely a pass-through TCP proxy with delayed binding. 
The network function itself (nftcp.rs) encompasses only ~700 LOC.
This number includes already a significant amount of code for profiling, recording of TCP sessions, debugging and tracing.

Some specific features of ProxyEngine are:
* using Flow Director capabilities in Intel NICs to implement RSS and RFS (tested with 82599 and X710 NICs)
* zero-copy recording of session records including time-stamps for TCP state changes 
* timer wheels for scheduling and processing of timer events (e.g. for TCP timeouts)
* load and priority dependent scheduling of flow processing (e.g. for flow merging)
* code profiling feature for performance tuning
* secure multi-threading code based on Rust's borrow checker for memory isolation
* easy integration of C libraries with support by automatic binding [rust-bindgen](https://github.com/rust-lang/rust-bindgen)    

#### ProxyEngine Installation

First install NetBricks. ProxyEngine needs the branch e2d2-rstade from the fork at https://github.com/rstade/Netbricks. The required NetBricks version is tagged (starting with v0.2.0). Install NetBricks locally on your (virtual) machine by following the description of NetBricks. The (relative) installation path of e2d2 needs to be updated in the dependency section of Cargo.toml for the ProxyEngine. 

Note, that a local installation of NetBricks is necessary as it includes DPDK and some C-libraries for interfacing the Rust code of NetBricks with the DPDK. As we need DPDK kernel modules, DPDK needs to be re-compiled each time the kernel version changes. This can be done with the script [build.sh](https://github.com/rstade/NetBricks/blob/e2d2-rstade/build.sh) of NetBricks. Note also that the Linux linker _ld_ needs to be made aware of the location of the .so libraries created by NetBricks. This can be solved using _ldconfig_.

Secondly, ProxyEngine depends on the crate [netfcts](https://github.com/rstade/netfcts). _netfcts_ is an extension to _NetBricks_ with helper functions and data structures, and needs to be build using the locally installed _NetBricks_ to ensure consistent dependencies.

ProxyEngine includes a main program bin.rs (using example configurations _\*.toml_) and test modules (using configurations _tests/\*.toml_). For both the network interfaces of the test machine need to be prepared (see [prepNet.sh](https://github.com/silverengine-de/proxyengine/blob/master/prepNet.sh)). 

First a network interface for user-space DPDK is needed. This interface is used by the proxy to connect to clients and servers (in the example configuration this interface uses PCI slot 07:00.0). The current code is tested on physical servers with NIC X520-DA2 (82599) and recently also with NIC X710-DA2. Please note that X710 based NICs require that ProxyEngine is configured for IP address based RFS, because X710 does not allow for partial masking of TCP ports as it is possible with 82599 based NICs.

Secondly an extra Linux interface is required which is used by the test modules for placing client and server stacks. When one of the above two-port NICs are used, the second port of the NIC can be assigned to the Linux OS.

For running the tests both interfaces must be interconnected with a cross over cable. Using Wireshark on the Linux interface allows us to observe the complete traffic exchange between clients, the proxy and the servers.

In addition some parameters like the Linux interface name (linux_if), the PCI slot id and the IP / MAC addresses in the test module configuration files  tests/*.toml need to be adapted. 

Latest code of ProxyEngine was tested on two different 2-socket NUMA servers, each socket hosting 4, respectively 6 physical cores, running realtime kernel of Centos 7.5.

A recent performance test using [TrafficEngine](https://github.com/rstade/TrafficEngine) as traffic generator achieves ~200000 connections per second (cps) on a single core of a six-core E5-2640 with 2.50 GHz.


#### ProxyEngine Test Configuration

![proxyengine test configuration](https://github.com/silverengine-de/proxyengine/blob/master/proxyengine_config.png)
