#ProxyEngine

ProxyEngine is a user-space TCP-proxy with following properties
* pass-through
* delayed binding
* high performance
* customizable

It may be used for intelligent load-balancing and fire-walling of TCP based protocols. Late binding allows to select the target server not till the the next packet after the initial three-way hand-shake is received. In addition callbacks can be defined by which the proxy can modify the payload of the TCP based protocol. For this purpose additional connection state is maintained by the ProxyEngine.

ProxyEngine builds on [Netbricks](https://github.com/NetSys/NetBricks) which itself utilizes DPDK for user-space networking.