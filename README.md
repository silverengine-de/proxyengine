_**ProxyEngine Overview**_

ProxyEngine is a user-space TCP-proxy written in Rust with following properties
* TCP pass-through
* customizable delayed binding
* high performance: multi-core, shared nothing, locking-free architecture
* client side receive side scaling (RSS), server side receive flow steering (RFS) by NIC
* customizable payload inspection and manipulation

It may be used for intelligent load-balancing and fire-walling of TCP based protocols, e.g. LDAP. Late binding allows to select the target server not till the first payload packet after the initial three-way hand-shake is received. In addition callbacks can be defined by which the proxy can modify the payload of the TCP based protocol. For this purpose additional connection state is maintained by the ProxyEngine.

First benchmarking shows that ProxyEngine can forward about 1.3 million packets per second per physical core (of a rather old 4 core L5520 CPU @ 2.27GHz with 32K/256K/8192K L1/L2/L3 Cache). Do not forget to compile with --release flag for any benchmarking ;-)

Scaling happens by distributing incoming client-side TCP connections using RSS over the cores and by steering the incoming server side TCP connections to the appropriate core. This receive flow steering can be either based on the port or on the IP address of the server side connection (selected by parameter _flow_steering_ in the toml configuration file). In the first case port resources of the proxy are assigned to cores (based on paramater _dst_port_mask_ in the configuration file). In the second case each core uses a unique IP address for the server side connections.     

ProxyEngine builds on [Netbricks](https://github.com/NetSys/NetBricks) which itself utilizes DPDK for user-space networking.

_**ProxyEngine Installation**_

First install NetBricks. ProxyEngine needs the branch e2d2-rstade from the fork at https://github.com/rstade/Netbricks. The required NetBricks version is tagged (starting with v0.2.0). Install NetBricks locally on your (virtual) machine by following the description of NetBricks. The (relative) installation path of e2d2 needs to be updated in the dependency section of Cargo.toml for the ProxyEngine. 

Note, that a local installation of NetBricks is necessary as it includes DPDK and some C-libraries for interfacing the Rust code of NetBricks with the DPDK. As we need DPDK kernel modules, DPDK needs to be re-compiled each time the kernel version changes. This can be done with the script [build.sh](https://github.com/rstade/NetBricks/blob/e2d2-0-1-1/build.sh) of NetBricks. Note also that the Linux linker _ld_ needs to be made aware of the location of the .so libraries created by NetBricks. This can be solved using _ldconfig_.

Secondly ProxyEngine depends on the crate _netfcts_ being part of [TrafficEngine](https://github.com/rstade/trafficengine). Currently you need to install TrafficEngine locally to get access to crate _netfcts_.

ProxyEngine includes a main program bin.rs (using example configurations _\*.toml_) and test modules (using configurations _tests/\*.toml_). For both the network interfaces of the test machine need to be prepared (see [prepNet.sh](https://github.com/silverengine-de/proxyengine/blob/master/prepNet.sh)). 

First a network interface for user-space DPDK is needed. This interface is used by the proxy to connect to clients and servers (in the example configuration this interface uses PCI slot 07:00.0). The current code is tested on physical servers with NIC X520-DA2 (82599) and recently also with NIC X710-DA2. Please note that X710 based NICs require that ProxyEngine is configured for IP address based RFS, because X710 does not allow for partial masking of TCP ports as it is possible with 82599 based NICs.

Secondly an extra Linux interface is required which is used by the test modules for placing client and server stacks. When one of the above two-port NICs are used, the second port of the NIC can be assigned to the Linux OS.

For running the tests both interfaces must be interconnected with a cross over cable. Using Wireshark on the Linux interface allows us to observe the complete traffic exchange between clients, the proxy and the servers.

In addition some parameters like the Linux interface name (linux_if), the PCI slot id and the IP / MAC addresses in the test module configuration files  tests/*.toml need to be adapted. 

Latest code of ProxyEngine was tested on two different 2-socket NUMA servers, each socket hosting 4, respectively 6 physical cores, running Centos 7.4. The benchmarking mentioned above was done with this two servers, one running iperf3 client and server instances, the other running the ProxyEngine as the device under test (DUT). More benchmarking to follow.


_**ProxyEngine Test Configuration**_

![proxyengine test configuration](https://github.com/silverengine-de/proxyengine/blob/master/proxyengine_config.png)
