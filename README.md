_**ProxyEngine Overview**_

ProxyEngine is a user-space TCP-proxy written in Rust with following properties
* TCP pass-through
* customizable delayed binding
* high performance: multi-core, receive side scaling (RSS) by NIC, receive flow steering (RFS) by NIC, shared nothing architecture
* customizable payload inspection and manipulation

It may be used for intelligent load-balancing and fire-walling of TCP based protocols, e.g. LDAP. Late binding allows to select the target server not till the first payload packet after the initial three-way hand-shake is received. In addition callbacks can be defined by which the proxy can modify the payload of the TCP based protocol. For this purpose additional connection state is maintained by the ProxyEngine.

ProxyEngine builds on [Netbricks](https://github.com/NetSys/NetBricks) which itself utilizes DPDK for user-space networking.

_**ProxyEngine Installation**_

First install NetBricks. ProxyEngine needs the branch e2d2-0-1-1 from the fork at https://github.com/rstade/Netbricks. Install the branch locally on your (virtual) machine by following the description of NetBricks. The (relative) installation path of e2d2 needs to be updated in the dependency section of Cargo.toml for the ProxyEngine. 

Note, that a local installation of NetBricks is necessary as it includes DPDK and some C-libraries for interfacing the Rust code of NetBricks with the DPDK. As we need DPDK kernel modules, DPDK needs to be re-compiled each time the kernel version changes. This can be done with the script [build.sh](https://github.com/rstade/NetBricks/blob/e2d2-0-1-1/build.sh) of NetBricks. Note also that the Linux linker _ld_ needs to be made aware of the location of the .so libraries created by NetBricks. This can be solved using _ldconfig_.

ProxyEngine includes a test module. However for using this module, the network interfaces of the test machine need to be prepared (see [prepNet.sh](https://github.com/silverengine-de/proxyengine/blob/master/prepNet.sh)). 

First a network interface for user-space DPDK is needed. This interface is used by the proxy to connect to clients and servers (in the example configuration this interface uses PCI slot 07:00.0). The latest code is tested with X520-DA2 (82599) and previous single rx/tx versions with e1000e and vmxnet3.

Secondly an extra Linux interface is required which is used by the test module for placing client and server stacks.

Both interfaces must be interconnected. In case of virtual interfaces, e.g. interfaces may be connected to a host-only network of the hypervisor. Using Wireshark on this network allows us to observe the complete traffic exchange between clients, the proxy and the servers. In case of physical interfaces, interfaces my be connected by a cross over cable.

In addition some parameters like the Linux interface name (linux_if) and the IP / MAC addresses in the test module configuration file proxy.toml need to be adapted. 

Latest code of ProxyEngine is tested on a 2-socket NUMA server, each socket hosting 4 physical cores, running Centos 7.4.


_**ProxyEngine Test Configuration**_

![proxyengine test configuration](https://github.com/silverengine-de/proxyengine/blob/master/proxyengine_config.png)
