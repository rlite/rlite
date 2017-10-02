# Documentation

## Table of contents
1. Introduction
2. Software requirements
3. Build instructions
4. Overview of the software components
    41. Kernel modules
    42. Userspace IPCPs daemon
    43. Libraries
    44. Control tool
    45. Other tools
    46. Python bindings
5. Tutorials
	51. Using the demonstrator
    52. Hands-on tutorial #1: normal-over-shim-eth
	53. Hands-on tutorial #2: normal-over-shim-udp4
6. Configuration of IPC Processes
	61. shim-eth IPC Process
	62. shim-udp4 IPC Process
	63. shim-tcp4 IPC Process
	64. shim-loopback IPC Process
	65. Normal IPC Process
		651. IPCP flavours to support different data transfer constants
7. Tools
    71. rina-gw
    72. iporinad


## 1. Introduction

The *rlite* project provides a lightweight Free and Open Source implementation
of the Recursive InterNetwork Architecture (RINA) for GNU/Linux operating
systems. For information about RINA, including many introductions,
presentations and articles, visit http://www.pouzinsociety.org/.

The main goal of *rlite* is to become a baseline implementation for RINA
systems to be used in production. In order to achieve this goal, *rlite*
focuses on robustness and performance by leveraging on a clean keep-it-simple
design. The current implementation includes about 26 Klocs of C/C++ code,
splitted between kernel-space and user-space.

Considerable attention is devoted to provide a POSIX-like API for applications
that can be easily assimilated by programmers used to the socket API, while
additionally offering the QoS awareness built into RINA.
The application API can be found in the include/rina/api.h header file.

While the *rlite* software can be used to build RINA-only, IP-free networks,
it also provides tools to interoperate RINA networks with existing IP networks
in many different ways. The **shim-udp4** (section 6.2) enables RINA over IP;
**iporinad** (section 7.2) allows IP over RINA with an MPLS-like architecture;
finally, **rina-gw** (section 7.1) allows to deploy RINA next to IP.


## 2. Software requirements

This section lists the software packages required to build and run *rlite* on
Linux-based operating systems. Only Ubuntu 14.04 and Archlinux are explicitly
indicated here, but using other distributions should be equally
straightforward.

### Ubuntu 14.04 and Debian 8

* gcc
* g++
* libprotobuf-dev
* protobuf-compiler
* cmake
* linux-headers-$(uname -r)
* python, swig [optional, for python bindings]

### Archlinux

* gcc
* cmake
* protobuf
* linux-headers
* python, swig [optional, for python bindings]

On Archlinux *rlite* is available from the AUR repository. It can be installed
using yaourt:

    $ yaourt --noconfirm -S rlite-git



## 3. Build instructions

Download the repo and enter the root directory

    $ git clone https://github.com/vmaffione/rlite.git
    $ cd rlite

Run the configure script

    $ ./configure

Build both kernel-space and user-space software

    $ make

Install *rlite* on the system

    # make install




## 4. Overview of the software components

This section briefly describes the software components of *rlite*.

### 4.1. Kernel modules

A main kernel module **rlite** which implements core functionalities:

* A control device for managing IPCPs, flows, registrations, etc.
* An I/O device to read()/write() SDU and synchronize (poll(), select()), etc).
* IPCP factories

A separate module for each type of IPCP:

* **rlite-normal**, implementing the kernel-space part of the regular IPCPs.
                    Includes EFCP and RMT.
* **rlite-shim-eth**, implementing the shim IPCP over Ethernet.
* **rlite-shim-udp4**, implementing the kernel-space part of the shim IPCP
                       over UDP and IPv4.
* **rlite-shim-tcp4**, implementing the kernel-space part of the shim IPCP
                       over TCP and IPv4. This follows an older specification
                       and it is deprecated in favour of the UDP shim IPCP.
* **rlite-shim-hv**, implementing the shim IPCP over VMPI, to be used with
                     Virtual Machines.
* **rlite-shim-loopback**, implementing a loopback shim IPCP.


### 4.2. Userspace IPCPs daemon

A daemon program, **rlite-uipcps**, which implements the user-space part of
the normal IPCP, the shim-udp4, and shim-tcp4. A main thread listens on a UNIX
socket to serve incoming requests from the **rlite-ctl** control tool.
A different thread is used for each IPCP running in the system.

For the normal IPCP, uipcps daemon implements the following components:

* Enrollment, a procedure by which an IPCP (the enrollee) joins an existing
  DIF, using a second IPCP (the enroller, which is already part of the DIF)
  as an access point.
* Routing, forwarding, and management of lower flows (i.e. N-1-flows) and
  neighbors.
* Application registration and unregistration.
* Flow allocation.
* Address allocation for the DIF members.
* Codecs for RIB objects.

Run

    # rlite-uipcps -h

to see the available options.


### 4.3. Libraries

The following libraries are available:

* **rina-api**, the main library, which wraps the control device and I/O device
                to provide the RINA POSIX-like API.
                This is the library used by applications to register names
                and allocate flows.
* **rlite-conf**, implementing the management and monitoring functionalities
                     of *rlite*, such as IPCP creation, removal and
                     configuration, flow monitoring, etc.
* **cdap**, a C++ implementation of the CDAP protocol.


### 4.4. Control tool

The **rlite-ctl** command line tool is used for the administration of the
*rlite* stack, in the same way as the *iproute2* tool is used to administer
the Linux TCP/IP stack.

Available commands:
* ipcp-create: Create a new IPCP in the system
* ipcp-destroy: Destroy an IPCP currently running in the system
* ipcp-config: Configure an IPCP
* ipcp-register: Register an IPCP into a DIF
* ipcp-unregister: Unregister an IPCP from a DIF
* ipcp-enroll: Enroll an IPCP into a DIF
* ipcps-show: Show the list of IPCPs that are currently running in the system
* dif-rib-show: Show the RIB of a DIF in the system
* flows-show: Show the allocated flows that have a local IPCP as one of the
              endpoints
* flows-dump: Show the detailed DTP/DTCP state of a given flow
* regs-show: Show all the names registered to any of the local IPCPs
* dif-policy-mod: Modify a policy for a DIF running in the system

To show all the available command and the corresponding usage, use

    $ rlite-ctl -h


### 4.5. Other tools

Other programs are available for testing and deployment:

* **rinaperf**, a multi-threaded client/server application for network
                throughput and latency performance measurement. Use
                `rinaperf -h` to see the available commmands.
* **rina-echo-async**, a single-threaded client/server application
                       implementing a echo service using only
                       non-blocking I/O. This application is able to allocate
                       and manage multiple flows in parallel, without using
                       blocking allocation or blocking I/O.
* **rina-gw**, a deamon program implementing a gateway between a TCP/IP
               network and a RINA network.
* **iporinad**, a daemon program which is able to tunnel IP traffic over
                a RINA network
* **rina-toy**, a simple echo program written using the Python bindings.

#### Examples of rinaperf usage

Run the server, registering on a DIF called *n.DIF*:

    $ rinaperf -l -d n.DIF

Note that rinaperf is multi-threaded, and can serve multiple requests
concurrently.

Run the client in ping mode, asking a DIF called *n.DIF* to allocate three
flows in parallel:

    $ rinaperf -p 3 -t ping -d n.DIF

Run the client in perf mode, asking a DIF called *n.DIF* to allocate a
flow, using 1200 bytes sized SDUs:

    $ rinaperf -t perf -d -n.DIF -s 1200


### 4.6. Python bindings

If your system supports Python, you can write applications using the *rlite*
Python bindings, which are a wrapper for the POSIX-like API exported by
the **rina-api** library. Run

    >>> import rina
    >>> help(rina)

in the Python interpreter, in order to see the available functionalities.
The **rina-toy** script is a trivial example written using these bindings.



## 5. Tutorials

### 5.1 Using the demonstrator

The demonstrator is a tool written in Python which allows you to deploy
arbitrarily complex RINA networks, within your PC, using light Virtual
Machines (VMs).
The tool is conceived to run directly on your physical machine/laptop.
All it does is to create QEMU VMs, TAP interfaces and software bridges,
so it does not harm your computer nor it installs any files.
Make sure QEMU is installed on your machine and kernel/processor
support KVM (Intel VT-x or AMD-V).

Enter the demo directory in the repository and run

    $ ./demo.py -h

to see available options.

The *rlite* demonstrator is compatible with the one
available at https://github.com/IRATI/demonstrator, which means that the
configuration files are interchangeable. The documentation contained
in the README.md file of the latter repository is still valid, with the
following differences:

1. The **policy** and **appmap** directives are not supported
2. The name of **eth** instances does not need to be a valid VLAN id


#### 5.1.1 Mini-tutorial

Enter the demo directory and run

    $ ./demo.py -c demo.conf

to generate the bootstrap (up.sh) and teardown (down.sh) scripts
for a RINA network of three nodes. More examples are available
in the demo/examples directory.

Run the bootstrap script and wait for it to finish (it will take 10-20
seconds):

    $ ./up.sh

Access node **a** and run **rinaperf** in server mode:

    $ ./access.sh a
    # rlite-ctl ipcps-show  # Show the IPCPs in the system
    # rinaperf -l -d n1.DIF

Using another terminal, access node **c** and run **rinaperf** in
client request/response (rr) mode:

    $ ./access.sh c
    # rlite-ctl ipcps-show  # Show the IPCPs in the system
    # rinaperf -t rr -d n1.DIF -c 1000 -s 460

This will produce 1000 request/response transactions between client and server,
and the client will report the average round trip time.

To look at the RIB of the normal DIF (n1.DIF), use the following command:

    # rlite-ctl dif-rib-show n1.DIF

In the DFT (Directory Forwarding Table) part of the RIB you can see an
entry for the **rinaperf** application registered on node **a**.

Always in the same terminal, you can run **rinaperf** in ping mode with the
following command:

    # rinaperf -d n1.DIF

Exit the node shell and teardown the scenario:

    $ ./down.sh


### 5.2 Hands-on tutorial #1: normal-over-shim-eth
#############################################################################

This tutorial shows how to manually reproduce the configuration described
in demo/demo.conf, assuming that *rlite* is installed on all the three nodes.
The nodes can be realized either with physical or virtual machines.

In the demo.conf configuration, three nodes (A, B and C) are connected through
Ethernet links to form a linear topology:

    A <---eth---> B <---eth---> C

and a single normal DIF is stacked over the link-to-link shim DIFs.

In the following, we will assume the following local names for nodes
network interfaces:

* On node A, the interface towards B is named eth0
* On node B, the interface towards A is named eth0, while the interface
  towards C is named eth1
* On node C, the interface towards B is named eth0

An all the three nodes, load the kernel modules and run the userspace
daemon (in the example the daemon is run in foreground):

    $ sudo modprobe rlite
    $ sudo modprobe rlite-normal
    $ sudo modprobe rlite-shim-eth
    $ sudo rlite-uipcps

On node A, set-up the interface towards B and create a shim IPCP
over Ethernet:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethAB.IPCP:1 shim-eth ethAB.DIF

Bind the shim IPCP to eth0, so that the network interface will be used
to send and receive packets:

    $ sudo rlite-ctl ipcp-config ethAB.IPCP:1 netdev eth0

Create a normal IPCP in the normal DIF:

    $ sudo rlite-ctl ipcp-create a.IPCP:1 normal n.DIF

Let the normal IPCP register to the shim DIF:

    $ sudo rlite-ctl ipcp-register a.IPCP:1 ethAB.DIF


On node B, similar operations are carried out for both the interfaces:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethAB.IPCP:1 shim-eth ethAB.DIF
    $ sudo rlite-ctl ipcp-config ethAB.IPCP:1 netdev eth0
    $
    $ sudo ip link set eth1 up
    $ sudo rlite-ctl ipcp-create ethBC.IPCP:1 shim-eth ethBC.DIF
    $ sudo rlite-ctl ipcp-config ethBC.IPCP:1 netdev eth1
    $
    $ sudo rlite-ctl ipcp-create b.IPCP:1 normal n.DIF
    $ sudo rlite-ctl ipcp-register b.IPCP:1 ethAB.DIF
    $ sudo rlite-ctl ipcp-register b.IPCP:1 ethBC.DIF

On node C:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethBC.IPCP:1 shim-eth ethBC.DIF
    $ sudo rlite-ctl ipcp-config ethBC.IPCP:1 netdev eth0
    $
    $ sudo rlite-ctl ipcp-create c.IPCP:1 normal n.DIF
    $ sudo rlite-ctl ipcp-register c.IPCP:1 ethBC.DIF

Once the IPCPs are set up, we have to carry out the enrollments in
the normal DIF. Among the possible strategies, we can enroll A and
C against B, so that B will be the initial node in the DIF.

On node A, enroll a.IPCP:1 into n.DIF using ethAB.DIF as a supporting
DIF and b.IPCP:1 as a neighbor:

    $ sudo rlite-ctl ipcp-enroll a.IPCP:1 n.DIF ethAB.DIF b.IPCP:1

On node C, enroll c.IPCP:1 into n.DIF using ethBC.DIF as a supporting
DIF and b.IPCP:1 as a neighbor:

    $ sudo rlite-ctl ipcp-enroll c.IPCP:1 n.DIF ethBC.DIF b.IPCP:1

On any node, you can check the standard output of the userspace daemon,
to check that the previous operations are completed with success.
Also the kernel log (dmesg) contains valuable log information.

It is also possible to check the list of IPCPs running in the local system:

    $ sudo rlite-ctl ipcps-show

or see the flows allocated in the local system (in this case the 0-flows
provided by the shim DIFs, which are being used by the normal DIF):

    $ sudo rlite-ctl flows-show


At this point, the setup is completed, and it is possible to run
applications on top of the normal DIF. As an example, we may run
the **rinaperf** application in server mode on node A, and the
same application in client perf mode on node C, while B will forward
the traffic.

On node A:

    $ rinaperf -l -d n.DIF

On node C:

    $ rinaperf -d n.DIF -t perf -s 1400 -c 100000


### 5.3 Hands-on tutorial #2: normal-over-shim-udp4

This tutorial illustrates a simple example of deploying the shim-udp4 to
allow two RINA networks to communicate over an IP network like the
Internet or a LAN. Using the shim-udp4, the RINA traffic between the two
RINA networks is transported through an UDP tunnel.

    NETWORK_X <---udp-tunnel---> NETWORK_Y

A normal DIF is also stacked over the shim over UDP, in order to provide
reliable flows (that UDP cannot provide) and all the services of a
fully-featured DIF.

Also this tutorial can be easily realized by using two physical machines
on the same LAN or two VMs on the same *emulated* LAN, once *rlite* is
installed in both machines.

To keep the example simple (and without loss of generality w.r.t. the
configuration) here we will assume that each network is composed by only one
node; let X be the node of the first network and Y the node of the second
network. In a real deployment, of course, X and Y would be just the edge
nodes of a bigger RINA nework (e.g. with nodes physically connected through
shim-eth DIFs like shown in section 5.2), and act as a *gateway* towards
the IP network.

We will assume that IP connectivity has been setup properly between X and Y.
In this particular example, we also assume that X and Y are on the same
IP subnet, with the IP address of X being 10.10.10.4/24 and the IP address
of Y being 10.10.10.52/24.
Before going ahead, check that there is IP connectivity, e.g.
trying to ping X from Y

    $ ping 10.10.10.4

As a first step, access both machine X and Y and append the following lines
to /etc/hosts (making sure that they not clash with other entries):

    10.10.10.4      xnorm.IPCP
    10.10.10.52     ynorm.IPCP

On both X and Y, load *rlite* kernel modules and run the **rlite-uipcps**
deamon (in foreground in the example)

    $ sudo modprobe rlite
    $ sudo modprobe rlite-normal
    $ sudo modprobe rlite-shim-udp4
    $ sudo rlite-uipcps

On machine X, create a shim-udp4 IPCP and a normal IPCP, and register the
normal IPCP in the shim-udp4 DIF:

    $ sudo rlite-ctl ipcp-create xipgateway.IPCP shim-udp4 udptunnel.DIF
    $ sudo rlite-ctl ipcp-create xnorm.IPCP normal normal.DIF
    $ sudo rlite-ctl ipcp-register xnorm.IPCP udptunnel.DIF

Carry out similar operations on node Y:

    $ sudo rlite-ctl ipcp-create yipgateway.IPCP shim-udp4 udptunnel.DIF
    $ sudo rlite-ctl ipcp-create ynorm.IPCP normal normal.DIF
    $ sudo rlite-ctl ipcp-register ynorm.IPCP udptunnel.DIF

Finally, access X and enroll X with Y (or the other way around) in the
normal DIF:

    $ sudo rlite-ctl ipcp-enroll xnorm.IPCP normal.DIF udptunnel.DIF ynorm.IPCP

The setup is now complete and your RINA applications on X can talk with
applications running on Y, with the traffic being forwarded through the UDP
shim DIF. As an example, run a **rinaperf** server on X (the normal DIF
will be automatically selected):

    $ rinaperf -l

Access Y and run the rinaperf client (in ping mode):

    $ rinaperf


## 6. Configuration of IPC Processes

Each type of IPC Process has different configuration needs. shim IPC
Processes, in particular, wrap a legacy transport technology; their
configuration is closely related to the corresponding technology.


### 6.1. shim-eth IPC Process

The shim DIF over Ethernet wraps an L2 Ethernet network. A shim-eth IPCP
must be configured with the O.S. name of the Ethernet Network Interface Card
(NIC) that is attached to the network.

In the following example

    $ sudo rlite-ctl ipcp-config ether3:181 netdev eth2

a shim IPCP called ether3:181 is assigned a network interface called eth2.


### 6.2. shim-udp4 IPC Process

The shim DIF over UDP/IPv4 wraps an arbitrary IPv4 network that supports UDP
as a transport protocol. As a lower level mechanisms, regular UDP sockets are
used to transmit/receive PDUs. For an application to use (register, allocate
flows) this shim DIF, a mapping must be defined between IP addresses and
application name. Each IP address univocally identifies a network interface
of a node in the shim IPCP, and therefore it also univocally identifies the
node itself. An IP address must be mapped to a single application name, so
that all flow allocation requests (UDP packets) arriving to that IP are
forwarded to that application. The mappings must be stored in the standard
/etc/hosts file of each node taking part in the shim DIF, or in a DNS
server.

An example of /etc/hosts configuration is the following:

    127.0.0.1       localhost.localdomain   localhost
    ::1             localhost.localdomain   localhost
    8.12.97.231     xyz-abc--
    8.12.97.230     asd-63--

In this example, the IP 8.12.97.231 is mapped to an application called
xyz:abc, while the IP 8.12.97.230 is mapped to another application
called asd:63. This means that this shim UDP implements a tunnel
between two nodes. The first endpoint node has a network interface configured
with the address 8.12.97.231 (with some netmask), and a RINA application
called xyz:abc can register to the local shim UDP IPCP. The other endpoint
node has a network interface configured with the address 8.12.97.232, and a
RINA application called asd:63 can register to the local shim UDP IPCP.

Note that while an IP address corresponds to one and only one application
name, an application name may correspond to multiple IP addresses. This
simply means that the same application is available at different network
interfaces (which could be useful for load balancing and high availability).

The /etc/hosts file (or DNS records) must be configured before any application
registration or flow allocation operation can be performed.
The current implementation does not dynamically update the
/etc/hosts file nor the DNS servers. Configuration has to be done
statically. This is not usually a real limitation, since you may probably
want to use the shim UDP to create a tunnel (over the Internet) between two
or a few RINA-only networks, in a VPN-like fashion. In this case a few lines
in /etc/hosts on each host which act as a tunnel endpoints will suffice.

Note that because of its nature, a single shim UDP IPCP for each node is
enough for any need. In other words, creating more shim IPCPs on the same node
is pointless.


### 6.3. shim-tcp4 IPC Process

In spite of the name being similar, the shim DIF over TCP/IPv4 is fundamentally
different from its UDP counterpart. While the name of an application running
over the shim UDP is mapped to an IP address, the name of an application
running over the shim TCP is mapped to a couple (IP address, TCP port).
The difference is explained by the fact that the shim UDP automatically
allocates a new local UDP port for each flow to allocate.
Nevertheless, both shims use sockets as an underlying transport technology,
and the use cases are similar.

As a consequence, the configuration for the shim TCP is not specified using
a standard configuration file (e.g. /etc/hosts). An ad-hoc configuration
file is stored at /etc/rlite/shim-tcp4-dir.

An example configuration is the following:

    rinaperf-data:client 10.0.0.1 6789 i.DIF
    rinaperf-data:server 10.0.0.2 6788 i.DIF

where the application named rinaperf-data:client is mapped (bound) to the
TCP socket with address 10.0.0.1:6789 and rinaperf-data:server is mapped
to the TCP socket 10.0.0.1:6788. These mappings are valid for a shim DIF
called i.DIF.

Note that the shim DIF over UDP should be preferred over the TCP one, for
two reasons:
    - Configuration does not use a standard file, and allocation of TCP ports
      must be done statically.
    - SDU serialization is needed, since TCP is not message (datagram)
      oriented, but stream oriented; SDU length has to be encoded in the
      stream, and this adds overhead and is more error prone
    - TCP handshake, retransmission and flow control mechanism add overhead
      and latency, introduces latency; moreover, these tasks should be
      carried out by EFCP.

In conclusion, the shim TCP is to be considered legacy, and future developments
are not expected to focus on it. It is strongly recommended to always use the
UDP shim when interfacing *rlite* with IP networks.


### 6.4. shim-loopback IPC Process

The shim-loopback conceptually wraps a loopback network device. SDUs sent on
a flow supported by this shim are forwarded to another flow supported by the
same shim. It is mostly used for testing purpose and as a stub module for
the other software components, since the normal IPCP support the
same functionalities (i.e. self-flows). However, it may be used for local
IPC without the need of the uipcp server.

It supports two configuration parameter:
 * **queued**: if 0, SDUs written are immediately forwarded (e.g. in process
    context to the destination flow; if different from 0, SDUs written are
    fowarded in a deferred context (a Linux workqueue in the current
    implementation).
 * **drop_fract**: if different from 0, an SDU packet is dropped every
                    **drop_fract** SDUs.


### 6.5. Normal IPC Process

A normal IPC Process can be manually configured with an address unique in its
DIF.
This step is not necessary, since a simple default policy for distributed
address allocation is already available.
To deactivate automatic address allocation, you need to pass the "-A manual"
option to the **rlite-uipcps** program, and configure addresses manually
like in the following example:

    $ sudo rlite-ctl ipcp-config normal1:xyz address 7382

where a normal IPCP called normal1:xyz is given the address 7382 to be used
in its DIF.


### 6.5.1. IPCP flavours to support different data transfer constants

The data transfer constants of the normal IPCP (e.g. size of EFCP sequence
numbers, addresses, CEP-ids, ...) are hardcoded in the **normal.ko** kernel
module, for better performance and (way) simpler code structure.
However, it is possible to generate (by recompilation) multiple
_flavours_ of the normal IPCP with different combinations of the constants.
In this sense, *rlite* supports a form of programmability of the EFCP
header.
The flavours are specified at configure time, so that the build system
can create the necessary kernel modules in addition to the default one.
The management part of the normal IPCP process, implemented by the
**rlite-uipcps** deamon, is instead used by all the flavours.
The flavours.conf file in the root directory contains the flavours
specification, where each line has the following syntax

    flavourname    addr=x seq=y pdulen=z cepid=w qosid=u

with x,y,z,w, and u in {1,2,4,8}. By default, a _tiny_flavour is specified
as follows:

    tiny    addr=1 seq=2 pdulen=2 cepid=1 qosid=1

which can be used for very small DIFs. A kernel module called
**normal-tiny.ko** is built and can be used as it were a completely
separate IPCP type (i.e. w.r.t. the default **normal.ko**). Actually,
it is just the same code (normal.c) recompiled with different values
of some macros.
You are free to add/modify flavours depending on your needs, and use
the different flavours together.


## 7. Tools
This section documents useful programs that are part of the *rlite*
software, but they are not part of the stack implementation.

### 7.1. rina-gw
The **rina-gw** program is a C++ daemon that acts as a proxy/gateway
between a TCP/IP network and a RINA network, as depicted in the following
figure.

![RINA/TCP gateway](https://bitbucket.org/vmaffione/rina-images/downloads/rina-gw.png)

On the one side, the gateway accepts TCP connections coming from
a TCP/IP network and proxies them by allocating RINA flows towards the
proper server applications in the RINA network. On the other side,
the gateway accepts flow allocation requests coming from the RINA network
and proxies them to a TCP server by means of new TCP connections.

The proxy needs therefore to be configured with a mapping between TCP/IP
names (IP and ports) and RINA names (DIF and application names).
In the current prototype, the mapping can be specified only with a
configuration file that rina-gw reads at startup; future versions may
implement a mechanism to allow for dynamic reconfiguration. Each line in
the configuration file specifies a single mapping. Two types of mappings
are possible, one for each direction: an I2R directive maps TCP
clients to RINA servers, whereas an R2I directive maps RINA
clients to TCP servers.

In the following configuration file example

    I2R serv.DIF rinaservice2 0.0.0.0 9063
    R2I vpn3.DIF tcpservice1 32.1.42.190 8729

the first directive cofigures rina-gw to proxy incoming connections on
destination port 9063 (on any host interface) towards the rinaservice2
application running in serv.DIF; the second directive asks rina-gw to proxy
incoming flow allocation requests for the destination application
tcpservice1 (on DIF vpn3.DIF) towards a TCP server on host 32.1.42.190
on port 8279.

The rina-gw program has been designed as a multi-threaded event-loop based
application. The RINA API is used in non-blocking mode together
with the socket API.
The main thread event-loop is responsible for the TCP connection setup and RINA
flow allocation, while the data forwarding -- i.e. reading data from a TCP
socket and writing it on a RINA flow and the other way around -- happens within
dedicated worker threads. It is worth observing that the only data structure
that worker threads use is a map that maps each file descriptor into another
file descriptor (e.g. std::map<int, int>). As a consequence, the
worker thread is generic code that is not aware of what kind of network I/O is
using -- TCP sockets, RINA flows, or others. This transparency property is
possible because of the file descriptor abstraction provided by the new
RINA API.
In the current prototype, only a single worker
thread is used to handle all the active sessions; future versions are expected
to use multiple worker threads to scale up with the number of sessions.

At startup, the main thread reads the configuration file and issues all the
bind()/listen() and rina\_register() calls that are necessary
to listen for incoming TCP connection (I2R) or RINA incoming flow requests
(R2I). The main poll-based event-loop waits for any of the four
event types that can happen:
 * A flow allocation request comes from the RINA network, matching one
   of the R2I directives. A TCP connection is initiated towards the
   mapped IP and port, calling connect() in non-blocking mode.
 * A TCP connection comes from the TCP/IP network, matching one of
   the I2R directives. A RINA flow allocation is initiated towards the
   mapped DIF and application name, using rina\_flow\_alloc()
   with the {RINA\_F\_NOWAIT} set.
 * A flow allocation response comes, matching one of the proxied TCP
   connections associated to an I2R directive. The
   rina\_flow\_alloc\_wait() function is called to complete
   the flow allocation and the new session is dispatched to a worker
   thread.
 * A TCP connection handshake completes for one of the proxied flow
   allocations associated to an R2I directive. The new session is
   is dispatched to a worker thread.

The main event-loop uses some data structures to keep track of the ongoing
connection setups.

### 7.2 iporinad
The **iporinad** program is a C++ daemon that tunnels IP traffic over a RINA
network. Such a RINA network has a role similar to MPLS within traditional
IP/MPLS deployments. The daemon runs in the *edge* nodes at the boundary
between the IP network and the RINA network, encapsulating or
decapsulating IP packets into/from RINA flows.

Each RINA flow operates as an IP tunnel between two iporinad instances running
on two different edge nodes. On the IP side, each tunnel endpoint is
implemented using a **tun** device. The iporinad programs implements the
encapsulation and decapsulation by forwarding the IP traffic from the tun
device towards the associated RINA flow endpoint, and the other way around.

The iporinad daemon creates tunnel towards its peers and advertise IP routes
according to its configuration file.
In the following example, two iporinad daemons run on different edge nodes
that belong to the same DIF n.DIF. In this case, n.DIF is the RINA network
that supports the IP tunnels. Each daemon is configured to register within
RINA, connect to the other peer, and advertise to the other some routes that
are reachable on its side.

    # Configuration file for the first iporina daemon
    #
    # Application name and DIF names for this daemon, used
    # for name registrations
    local       iporina1        n.DIF

    # Information about remote tunnel endpoints, with application name
    # (and DIF name) for flow allocation, and IP subnet to be used
    # for the point-to-point IP tunnel.
    remote      iporina2        n.DIF       192.168.134.0/30

    # Routes that are locally reachable, which are going to be advertised
    # to the remote endpoints
    route       10.9.0.0/24
    route       10.9.1.0/24

The `local` directive (which must be unique) specifies the daemon name
and the DIFs to register to.
Each `remote` directive specifies application and DIF name of a remote
iporina daemon to connect to, together with an IP subnet to use for
the IP tunnel (a /30 is preferable, as only two IP addresses are needed).
More `remote` directive are possible, one for each peer. A different tun
device will be created for each remote peer.
The `route` directive specifies a locally reachable route that the daemon
will advertise to all its peers.
When an iporina daemon receives a route from a peer, it adds an entry
in the local IP routing table to forward IP traffic for that destination
towards the tun device associated to the peer.

    # Configuration file for the second iporina daemon
    #
    # Application name and DIF names for this daemon, used
    # for name registrations
    local       iporina2        n.DIF

    # Information about remote tunnel endpoints, with application name
    # (and DIF name) for flow allocation, and IP subnet to be used
    # for the point-to-point IP tunnel.
    remote      iporina1        n.DIF       192.168.134.0/30

    # Routes that are locally reachable, which are going to be advertised
    # to the remote endpoints
    route       10.9.2.0/24
    route       10.9.3.0/24



## Credits

*rlite* is a community-driven project partially supported by the EU FP7
projects PRISTINE and ARCFIRE.

Author:         Vincenzo Maffione

Contributors:   Michal Koutenský
