#############################################################################
## Table of contents                                                        #
#############################################################################

* 0. Introduction
* 1. Software requirements
* 2. Build instructions
* 3. Overview of the software components
    * 3.1. Kernel modules
    * 3.2. Userspace IPCPs daemon
    * 3.3. Libraries
    * 3.4. Control tool
    * 3.5. Other tools
    * 3.6. Python bindings
* 4. Tutorials
    * 4.1 Using the demonstrator
    * 4.2 Hands-on tutorial #1: normal-over-shim-eth
    * 4.3 Hands-on tutorial #2: normal-over-shim-udp
* 5. Configuration of IPC Processes
    * 5.1. shim-eth IPC Process
    * 5.2. shim-udp4 IPC Process
    * 5.3. shim-tcp4 IPC Process
    * 5.4. shim-loopback IPC Process
    * 5.5. Normal IPC Process


#############################################################################
## 0. Introduction                                                          #
#############################################################################

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


#############################################################################
## 1. Software requirements                                                 #
#############################################################################

This section lists the software packages required to build and run *rlite* on
Linux-based operating systems. Only Ubuntu 14.04 and Archlinux are explicitly
indicated here, but using other distributions should be equally
straightforward.

### Ubuntu 14.04 and Debian 8
#############################################################################

* gcc
* g++
* libprotobuf-dev
* protobuf-compiler
* cmake
* linux-headers-$(uname -r)
* python, swig [optional, for python bindings]

### Archlinux
#############################################################################

* gcc
* cmake
* protobuf
* linux-headers
* python, swig [optional, for python bindings]



#############################################################################
## 2. Build instructions                                                       #
#############################################################################

Download the repo and enter the root directory

    $ git clone https://github.com/vmaffione/rlite.git
    $ cd rlite

Run the configure script

    $ ./configure

Build both kernel-space and user-space software

    $ make

Install *rlite* on the system

    # make install



#############################################################################
## 3. Overview of the software components                                   #
#############################################################################

This section briefly describes the software components of *rlite*.

### 3.1. Kernel modules
#############################################################################

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


### 3.2. Userspace IPCPs daemon
#############################################################################

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


### 3.3. Libraries
#############################################################################

The following libraries are available:

* **librlite**, the main library, which wraps the control device and I/O device
                to provide the RINA POSIX-like API.
                This is the library used by applications to register names
                and allocate flows.
* **librlite-conf**, implementing the management and monitoring functionalities
                     of *rlite*, such as IPCP creation, removal and
                     configuration, flow monitoring, etc.
* **librlite-cdap**, a C++ implementation of the CDAP protocol.


### 3.4. Control tool
#############################################################################

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
* ipcp-rib-show: Show the RIB of an IPCP running in the system
* flows-show: Show the allocated flows that have a local IPCP as one of the
              endpoints
* flows-dump: Show the detailed DTP/DTCP state of a given flow

To show all the available command and the corresponding usage, use

    $ rlite-ctl -h


### 3.5. Other tools
#############################################################################

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


### 3.6. Python bindings
#############################################################################

If your system supports Python, you can write applications using the *rlite*
Python bindings, which are a wrapper for the POSIX-like API exported by
the **librlite** library. Run

    >>> import rlite
    >>> help(rlite)

in the Python interpreter, in order to see the available functionalities.
The **rina-toy** script is a trivial example written using these bindings.



#############################################################################
## 4. Tutorials                                                             #
#############################################################################

### 4.1 Using the demonstrator
#############################################################################

The demonstrator is a tool written in Python which allows you to deploy
arbitrarily complex RINA networks, in your PC, using light Virtual Machines.

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
3. The legacy mode is not supported, only the buildroot mode is


#### 4.1.1 Mini-tutorial

Enter the demo directory and run

    $ ./demo.py -c demo.conf

to generate the bootstrap (up.sh) and teardown (down.sh) scripts.

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


### 4.2 Hands-on tutorial #1: normal-over-shim-eth
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

    $ sudo rlite-ctl ipcp-register ethAB.DIF a.IPCP:1


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
    $ sudo rlite-ctl ipcp-register ethAB.DIF b.IPCP:1
    $ sudo rlite-ctl ipcp-register ethBC.DIF b.IPCP:1

On node C:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethBC.IPCP:1 shim-eth ethBC.DIF
    $ sudo rlite-ctl ipcp-config ethBC.IPCP:1 netdev eth0
    $
    $ sudo rlite-ctl ipcp-create c.IPCP:1 normal n.DIF
    $ sudo rlite-ctl ipcp-register ethBC.DIF c.IPCP:1

Once the IPCPs are set up, we have to carry out the enrollments in
the normal DIF. Among the possible strategies, we can enroll A and
C against B, so that B will be the initial node in the DIF.

On node A, enroll a.IPCP:1 to the neighbor b.IPCP:1 using
ethAB.DIF as a supporting DIF:

    $ sudo rlite-ctl ipcp-enroll n.DIF a.IPCP:1 b.IPCP:1 ethAB.DIF

On node C, enroll c.IPCP:1 to the neighbor b.IPCP:1 using
ethBC.DIF as a supporting DIF:

    $ sudo rlite-ctl ipcp-enroll n.DIF c.IPCP:1 b.IPCP:1 ethBC.DIF

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


### 4.3 Hands-on tutorial #2: normal-over-shim-udp
#############################################################################

This tutorial illustrates a simple example of deploying the shim-udp to
allow two RINA networks to communicate over an IP network like the
Internet or a LAN. Using the shim-udp, the RINA traffic between the two
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
shim-eth DIFs like shown in section 4.2), and act as a *gateway* towards
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

On both X and Y, load *rlite* kernel modules and run the rlite-uipcps
deamon (in foreground in the example)

    $ sudo modprobe rlite
    $ sudo modprobe rlite-normal
    $ sudo modprobe rlite-shim-udp4
    $ sudo rlite-uipcps

On machine X, create a shim-udp4 IPCP and a normal IPCP, and register the
normal IPCP in the shim-udp4 DIF:

    $ sudo rlite-ctl ipcp-create xipgateway.IPCP shim-udp4 udptunnel.DIF
    $ sudo rlite-ctl ipcp-create xnorm.IPCP normal normal.DIF
    $ sudo rlite-ctl ipcp-register udptunnel.DIF xnorm.IPCP

Carry out similar operations on node Y:

    $ sudo rlite-ctl ipcp-create yipgateway.IPCP shim-udp4 udptunnel.DIF
    $ sudo rlite-ctl ipcp-create ynorm.IPCP normal normal.DIF
    $ sudo rlite-ctl ipcp-register udptunnel.DIF ynorm.IPCP

Finally, access X and enroll X with Y (or the other way around) in the
normal DIF:

    $ sudo rlite-ctl ipcp-enroll normal.DIF xnorm.IPCP ynorm.IPCP udptunnel.DIF

The setup is now complete and your RINA applications on X can talk with
applications running on Y, with the traffic being forwarded through the UDP
shim DIF. As an example, run a **rinaperf** server on X (the normal DIF
will be automatically selected):

    $ rinaperf -l

Access Y and run the rinaperf client (in ping mode):

    $ rinaperf


#############################################################################
## 5. Configuration of IPC Processes                                        #
#############################################################################

Each type of IPC Process has different configuration needs. shim IPC
Processes, in particular, wrap a legacy transport technology; their
configuration is closely related to the corresponding technology.


### 5.1. shim-eth IPC Process
#############################################################################

The shim DIF over Ethernet wraps an L2 Ethernet network. A shim-eth IPCP
must be configured with the O.S. name of the Ethernet Network Interface Card
(NIC) that is attached to the network.

In the following example

    $ sudo rlite-ctl ipcp-config ether3:181 netdev eth2

a shim IPCP called ether3:181 is assigned a network interface called eth2.


### 5.2. shim-udp4 IPC Process
#############################################################################

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


### 5.3. shim-tcp4 IPC Process
#############################################################################

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


### 5.4. shim-loopback IPC Process
#############################################################################

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


### 5.5. Normal IPC Process
#############################################################################

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

