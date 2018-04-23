# Documentation

## Table of contents
````
1. Introduction
    11. Features at a glance
    12. Basic performance evaluation
2. Software requirements
3. Build instructions
4. Overview of the software components
    41. Kernel modules
    42. Userspace IPCPs daemon
    43. Libraries
    44. Administration tools
    45. Other tools
    46. Python bindings
5. Tutorials
    51. Using the demonstrator
    52. Hands-on tutorial #1: normal-over-shim-eth
    53. Hands-on tutorial #2: normal-over-shim-udp4
    54. Hands-on tutorial #3: normal-over-shim-wifi
    55. Using configen
6. Configuration of IPC Processes
	61. shim-eth IPC Process
	62. shim-udp4 IPC Process
	63. shim-tcp4 IPC Process
	64. shim-loopback IPC Process
	65. Normal IPC Process
		651. IPCP flavours to support different data transfer constants
		652. Available policies and parameters
7. Tools
    71. rina-gw
    72. iporinad
    73. rinaperf
    74. rina-echo-async
8. Development workflow
9. RINA API
    91. Server-side operations
    92. Client-side operations
    93. API specification
    94. Mapping sockets API to RINA API
        941. Server-side mapping
        942. Client-side mapping
````

## 1. Introduction

The *rlite* project provides a lightweight Free and Open Source implementation
of the Recursive InterNetwork Architecture (RINA) for GNU/Linux operating
systems. For information about RINA, including many introductions,
presentations and articles, visit http://www.pouzinsociety.org/.

The main goal of *rlite* is to become a baseline implementation for RINA
systems to be used in production. In order to achieve this goal, *rlite*
focuses on robustness and performance by leveraging on a clean keep-it-simple
design. The current implementation includes about 30 Klocs of C/C++ code,
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


### 1.1. Features at a glance

The prototype supports the following features (and more):

* Arbitrary composition and stacking of IPC layers (DIFs).
* Programmability of the layer constants (e.g. bit-width of addresses,
  sequence numbers and other protocol fields).
* Programmability of some layer components (i.e. support for policies).
* Ability to run over legacy media like Ethernet, WiFi or UDP.
* Enrollment procedure for a node to join an existing layer; the new
  member receives the layer configuration (e.g. policies and other
  parameters) and the current dynamic information.
* Support for flow control and retransmission control.
* Inspection tools to show current status of a layer, e.g., the current
  configuration and dynamic information (RIB contents), the active flows,
  the locally registered applications, etc.
* A POSIX-like C API for network applications, plus the associated
  bindings for the Python scripting language.
* Tools to interoperate with IP networks.
* Example applications, including throughput and latency benchmarking.
* A simple tool to realize the RINA configuration specified by a
  given configuration file.
* An implementation of the CDAP protocol.
* Support for integration tests and tests based on emulated networks.


### 1.2. Basic performance evaluation

This section reports the results of some experiments to evaluate the
performance of the current implementation.

The following figure shows throughput experiments between two
hosts directly connected through a 40Gbit cable. Both hosts are 8-core
single-socket machines (4 physical cores, 8 hyperthreads in total) with
i7 processors (i7-3770K CPU at 3.5 GHz) and 1.33 GHz DDR3 memory.
The hosts run Linux 4.13. The NIC is an Intel XL710 (40 Gbit/s) with 8 PCIe-v3
lanes at 8Gbit/s each.
The plots show the throughput of a single (rinaperf) flow for different
packet sizes, using reliable flows or unreliable flows. When using unreliable
flows we show the throughput measured at the sender (first plot) and the
goodput measured at the receiver (second plot), as there can be packet loss.
For reliable flows throughput and goodput are the same, so we show a single
plot.
Each test combination is repeated 10 times, computing the average (shown
in the plot) and the standard deviation (not shown as less than 3%).
For reproducibility of the tests, rinaperf is pinned to a core and CPU
frequency scaling is disabled.

![Throughput performance between two hosts with 40Gbit NIC](https://bitbucket.org/vmaffione/rina-images/downloads/rlite-40g-l1.png)


## 2. Software requirements

This section lists the software packages required to build and run *rlite* on
GNU/Linux operating systems. Only Ubuntu, Debian, Archlinux and CentOS are
explicitly indicated here, but using other distributions should be equally
straightforward.

The software has been developed and tested on Linux (vanilla) kernels starting
from the 4.1 series up to the most recent ones. Using older Linux versions is
possible down to 3.11 kernels, as the `./configure` script is able to detect
some of the differences in the internal API that change across Linux versions.
The 3.10 kernels and older ones are not supported. In any case it is
recommended to use recent versions (e.g. from 4.1 onward) where possible.

### Ubuntu 14.04 (or higher) and Debian 8 (or higher)

List of required packages:

* gcc
* g++
* libprotobuf-dev
* protobuf-compiler
* cmake
* linux-headers-$(uname -r)
* python, swig [optional, for python bindings]
* wpasupplicant, hostapd [optional, for shim-wifi]

### Archlinux

List of required packages:

* gcc
* cmake
* protobuf
* linux-headers
* python, swig [optional, for python bindings]
* wpa_supplicant, hostapd [optional, for shim-wifi]

On Archlinux *rlite* is available from the AUR repository. It can be installed
using yaourt:

    $ yaourt --noconfirm -S rlite-git

### CentOS 7

List of required packages:

* gcc
* gcc-c++
* protobuf
* protobuf-compiler
* protobuf-devel
* kernel-devel
* cmake
* python, swig [optional, for python bindings]
* wpa_supplicant, hostapd [optional, for shim-wifi]



## 3. Build instructions

Download the repo and enter the root directory

    $ git clone https://github.com/vmaffione/rlite.git
    $ cd rlite

Run the configure script (as a normal user)

    $ ./configure

Build both kernel-space and user-space software (as a normal user)

    $ make

Install *rlite* on the system (as root user)

    # make install depmod


## 4. Overview of the software components

This section briefly describes the software components of *rlite*.

### 4.1. Kernel modules

A main kernel module **rlite** which implements core functionalities:

* A control device for managing IPCPs, flows, registrations, etc.
* An I/O device to read()/write() SDU and synchronize (poll(), select()), etc).
* IPCP factories

A separate module for each type of IPCP:

* **rlite-normal**: Implements the kernel-space part of the regular IPCPs.
                    Includes EFCP and RMT.
* **rlite-shim-eth**: Implements the shim IPCP over Ethernet. The same datapath
                      is also used by the shim-wifi.
* **rlite-shim-udp4**: Implements the kernel-space part of the shim IPCP
                       over UDP and IPv4.
* **rlite-shim-tcp4**: Implements the kernel-space part of the shim IPCP
                       over TCP and IPv4. This follows an older specification
                       and it is deprecated in favour of the UDP shim IPCP.
* **rlite-shim-loopback**: Implements a loopback shim IPCP.


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
* Flow allocation with support for QoS.
* Address allocation for the DIF members.

Run

    # rlite-uipcps -h

to see the available options.


### 4.3. Libraries

The following libraries are available:

* **rina-api**, the main library, which wraps the control device and I/O device
                to provide the RINA POSIX-like API.
                This is the library used by applications to register names
                and allocate flows.
* **cdap**, a C++ implementation of the CDAP protocol.
* **rlite-conf**: implements the management and monitoring functionalities
                  of *rlite*, such as IPCP creation, removal and
                  configuration, flow monitoring, etc. This library is the
                  backend of the **rlite-ctl** tool.


### 4.4. Administration tools

The **rlite-ctl** command line tool is used for the administration of the
*rlite* stack, in the same way as the *iproute2* tool is used to administer
the Linux TCP/IP stack.

Available commands:
* `ipcp-create`: Create a new IPCP in the system.
* `ipcp-destroy`: Destroy an existing IPCP.
* `ipcp-config`: Configure an IPCP.
* `ipcp-register`: Register an N-IPCP into an N-1-DIF.
* `ipcp-unregister`: Unregister an N-IPCP from an N-1-DIF.
* `ipcp-enroller-enable`: Enable an IPCP to act as enroller for its DIF.
                        This is needed for the first IPCP of a DIF, that
                        does not enroll to another IPCP.
* `ipcp-enroll`: Enroll an N-IPCP into an N-DIF.
* `ipcp-reset`: Destroy all the IPCPs of the system.
* `ipcps-show`: Show the list of IPCPs that are currently running in the system.
* `dif-rib-show`: Show the RIB of a DIF running in the system.
* `flows-show`: Show the allocated N-flows that have a local N-IPCP as one of the
              endpoints.
* `flows-dump`: Show the detailed DTP/DTCP state of a given flow.
* `regs-show`: Show all the (N+1)names registered to any of the local N-IPCPs.
* `dif-policy-mod`: Modify a policy for a DIF running in the system.
* `dif-policy-list`: Show current and available policies for a DIF.
* `dif-policy-param-mod`: Modify a policy parameter for a DIF running in the
                        system.
* `dif-policy-param-list`: Show DIF parameters together with their current
                           values.
* `ipcp-route-add`: Add or update a routing rule for a local IPCP; valid for
                    the static routing policy.
* `ipcp-route-del`: Remove a routing rule from a local IPCP; valid for the
                    static routing policy.

To show the available commands and the corresponding usage, run

    $ rlite-ctl -h

The **rlite-node-config** tool can be used to run a sequence of **rlite-ctl**
commands specified by a configuration file (the _initscript_).
This is particularly useful to setup the IPCPs once a machine boots.
The _initscript_ is a list of commands that are executed sequentially,
e.g.:

    ipcp-create e1.IPCP shim-eth e.DIF
    ipcp-create n1.IPCP normal n.DIF
    ipcp-create m1.IPCP normal m.DIF
    ipcp-register n1.IPCP e.DIF
    ipcp-register m1.IPCP n.DIF
    ipcp-config e1.IPCP netdev ens4
    ipcp-enroll n1.IPCP n.DIF e.DIF n2.IPCP
    ipcp-enroll m1.IPCP m.DIF n.DIF m2.IPCP

The node configurator aborts immediately if a non-enrollment command fails,
as such a failure happens on misconfiguration or lack of system resources.
If an enrollment command fails, conversely, it is likely that the remote
enroller node is not up yet, or network is temporarily down; for this reason,
on failure the program waits for a few seconds and tries again, as many times
as it is necessary. When the current enrollment succeeds, it proceeds to
the next one, until all the enrollments are completed.
By default **rlite-node-config** starts with a reset operation to remove all
the existing IPCPs, and then reads the initscript stored at
`/etc/rina/initscript`.

Note that the `.DIF` and `.IPCP` suffixes are not required for DIF and IPCP
names; however, they are widely used in the following examples and tutorial
with the only purpose of clarify which names refer to IPC processes and which
ones refer to DIFs.


### 4.5. Other tools

Other programs are available for testing and deployment:

* **rinaperf**, a multi-threaded client/server application for network
                throughput and latency performance measurement. Use
                `rinaperf -h` to see the available commmands. This program
                is described in section 7.3.
* **rina-echo-async**, a single-threaded client/server application
                       implementing a echo service using only
                       non-blocking I/O. This application is able to allocate
                       and manage multiple flows in parallel, without using
                       blocking allocation or blocking I/O. This program is
                       described in section 7.4.
* **rina-gw**, a deamon program implementing a gateway between a TCP/IP
               network and a RINA network.
* **iporinad**, a daemon program which is able to tunnel IP traffic over
                a RINA network
* **rina-toy**, a simple echo program written using the Python bindings.

#### Examples of rinaperf usage

Run the server, registering on a DIF called *n.DIF* (if no DIF name is
specified, the system will chose the one with the higher rank):

    $ rinaperf -l -d n.DIF

Note that rinaperf is multi-threaded, and can serve multiple requests
concurrently.

Run the client in ping mode with the default 2-bytes size, asking a DIF
called *n.DIF* to allocate three flows in parallel:

    $ rinaperf -p 3 -t ping -d n.DIF

Run the client in perf mode, asking a DIF called *n.DIF* to allocate a
flow, using 1200 bytes sized SDUs (if no size is specified, in perf mode
rinaperf will use the maximum SDU size):

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

to see the available options and features.

The *rlite* demonstrator is compatible with the one
available at https://github.com/IRATI/demonstrator, which means that the
configuration files are interchangeable. The documentation contained
in the README.md file of the latter repository is still valid, with some
differences:

1. The **policy** and **appmap** directives are not supported
2. The name of **eth** instances does not need to be a valid VLAN id

Note that the rlite demonstrator has some features that are not currently
supported by the IRATI demonstrator.

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

On all the three nodes, load the kernel modules and run the userspace
daemon (in the example the daemon is run in foreground):

    $ sudo modprobe rlite
    $ sudo modprobe rlite-normal
    $ sudo modprobe rlite-shim-eth
    $ sudo rlite-uipcps

On node A, set-up the interface towards B and create a shim IPCP
over Ethernet:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethAB.IPCP shim-eth ethAB.DIF

Bind the shim IPCP to eth0, so that the network interface will be used
to send and receive packets:

    $ sudo rlite-ctl ipcp-config ethAB.IPCP netdev eth0

Create a normal IPCP in the normal DIF:

    $ sudo rlite-ctl ipcp-create a.IPCP normal n.DIF

Let the normal IPCP register to the shim DIF:

    $ sudo rlite-ctl ipcp-register a.IPCP ethAB.DIF


On node B, similar operations are carried out for both the interfaces:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethAB.IPCP shim-eth ethAB.DIF
    $ sudo rlite-ctl ipcp-config ethAB.IPCP netdev eth0
    $
    $ sudo ip link set eth1 up
    $ sudo rlite-ctl ipcp-create ethBC.IPCP shim-eth ethBC.DIF
    $ sudo rlite-ctl ipcp-config ethBC.IPCP netdev eth1
    $
    $ sudo rlite-ctl ipcp-create b.IPCP normal n.DIF
    $ sudo rlite-ctl ipcp-register b.IPCP ethAB.DIF
    $ sudo rlite-ctl ipcp-register b.IPCP ethBC.DIF

On node C:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethBC.IPCP shim-eth ethBC.DIF
    $ sudo rlite-ctl ipcp-config ethBC.IPCP netdev eth0
    $
    $ sudo rlite-ctl ipcp-create c.IPCP normal n.DIF
    $ sudo rlite-ctl ipcp-register c.IPCP ethBC.DIF

Once the IPCPs are set up, we have to carry out the enrollments in
the normal DIF. Among the possible strategies, we can enroll A and
C against B, so that B will be the initial node in the DIF.

On node B, enable b.IPCP to act as an enroller even if it is not
enrolled to any other node (as it is the first node):

    $ sudo rlite-ctl ipcp-enroller-enable b.IPCP

On node A, enroll a.IPCP into n.DIF using ethAB.DIF as a supporting
DIF and b.IPCP as a neighbor:

    $ sudo rlite-ctl ipcp-enroll a.IPCP n.DIF ethAB.DIF b.IPCP

On node C, enroll c.IPCP into n.DIF using ethBC.DIF as a supporting
DIF and b.IPCP as a neighbor:

    $ sudo rlite-ctl ipcp-enroll c.IPCP n.DIF ethBC.DIF b.IPCP

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
to /etc/hosts (making sure that they do not clash with other entries):

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

Finally, enable Y to be the first enroller for the normal DIF (you may ignore
failures related to registration of DAF names)

    $ sudo rlite-ctl ipcp-enroller-enable ynorm.IPCP

and access X and enroll X with Y in the normal DIF:

    $ sudo rlite-ctl ipcp-enroll xnorm.IPCP normal.DIF udptunnel.DIF ynorm.IPCP

The setup is now complete and your RINA applications on X can talk with
applications running on Y, with the traffic being forwarded through the UDP
shim DIF. As an example, run a **rinaperf** server on X (the normal DIF
will be automatically selected):

    $ rinaperf -l

Access Y and run the rinaperf client (in ping mode):

    $ rinaperf


### 5.4 Hands-on tutorial #3: normal-over-shim-wifi

This tutorial shows how to deploy RINA over a WiFi wireless LAN. One of the
nodes is configured in Access Point (AP) mode, while the others can associate
to the AP. The association to an AP is mapped to a RINA enrollment procedure.
The shim-wifi implementation uses the *hostapd* software to implement the AP
functionalities of the enroller IPCP; similarly, *wpa_supplicant* is used
for the enrollee IPCP. These daemons need their configuration that must be
prepared by the administrator in addition to the RINA configuration.

For the sake of simplicity, in this tutorial we use only two nodes, each
having its own WiFI NIC; one of them acts as an AP, while the other is a
client station.
On top of the shim-wifi DIF we stack a normal DIF to provide complete
services to the applications; the shim-wifi inherits the limitations of the
shim-eth (e.g. only a single flow supported between two nodes in the DIF),
that is used to implement its datapath.

On both nodes, load the kernel modules and run the userspace daemon
(in the example the daemon is run in background):

    $ sudo modprobe rlite
    $ sudo modprobe rlite-normal
    $ sudo modprobe rlite-shim-eth
    $ sudo rlite-uipcps -d

On the AP side, the following *hostapd* configuration file can be stored
in `/etc/hostapd/rlite.conf`:

    interface=wlp2s0
    ssid=rinawlanpwd.DIF
    wpa_passphrase=password
    auth_algs=3
    channel=7
    driver=nl80211
    hw_mode=g
    logger_stdout=-1
    logger_stdout_level=2
    max_num_sta=5
    rsn_pairwise=CCMP
    wpa=2
    wpa_key_mgmt=WPA-PSK
    wpa_pairwise=TKIP CCMP

In the configuration file above you should replace `wlp2s0` with your local
WiFi interface name. In this tutorial we assume that the NIC supports AP mode
(a.k.a. *master* mode); you should make sure that this is the case also for
your hardware.
On the client side, the following *wpa_supplicant* configuration file can be
stored in `/etc/wpa_supplicant/rlite.conf`

    ctrl_interface=/var/run/wpa_supplicant
    eapol_version=1
    ap_scan=1
    fast_reauth=1
    update_config=1

    network={
        ssid="rinawlanpwd.DIF"
        psk="password"
    }

On both client and AP nodes, make sure that no additional *wpa_supplicant*
or network manager software is running, to avoid conflicts on the WiFI NIC.

On the AP node, we use the following RINA configuration (specified as
configuration for **rlite-node-config**):

    # Create a shim-wifi IPCP
    ipcp-create x.IPCP shim-wifi rinawlanpwd.DIF
    # Configure the IPCP with the interface name (needed by the shim-eth
    # kernel module to bind to the network interface)
    ipcp-config x.IPCP netdev wlp2s0
    # Enable AP mode, running hostapd
    ipcp-enroller-enable x.IPCP
    # Create a normal IPCP, register into the shim-wifi DIF, and
    # enable as enroller.
    ipcp-create nx.IPCP normal n.DIF
    ipcp-register nx.IPCP rinawlanpwd.DIF
    ipcp-enroller-enable nx.IPCP

On the client node, we use the following RINA configuration (assuming
`wlp3s0` is the name of the WiFi network interface):

    # Create a shim-wifi IPCP
    ipcp-create y.IPCP shim-wifi rinawlanpwd.DIF
    # Configure the IPCP with the interface name (needed by the shim-eth
    # kernel module to bind to the network interface)
    ipcp-config y.IPCP netdev wlp3s0
    # Create a normal IPCP and register into the shim-wifi DIF
    ipcp-create ny.IPCP normal n.DIF
    ipcp-register ny.IPCP rinawlanpwd.DIF
    # Enroll the shim-wifi IPCP to rinawlanpwd.DIF
    ipcp-enroll y.IPCP rinawlanpwd.DIF null
    # Enroll to the normal DIF
    ipcp-enroll ny.IPCP n.DIF rinawlanpwd.DIF nx.IPCP

On both nodes, the RINA configuration can be realized with the following
command:

    $ sudo rlite-node-config -vd

To test connectivity, you can run a rinaperf server on one of the
two nodes (it will register on the normal DIF by default):

    (node A)$ rinaperf -l

while the other node runs the client in ping mode

    (node B)$ rinaperf


## 5.5 Using configen

The `configen` tool, located in `demo/configen.py`, can generate initscripts
for `rlite-node-config`, using similar configuration files as the
demonstrator.
However, this tool is meant to be used with physical machines, and so the
`eth` directive has different syntax and semantics: it gives instructions
to create a shim-eth IPCP and bind it to a given network interface.

The new syntax for the `eth` directive is the following:

    eth NODE IPCP DIF NETDEV

where `NODE` is the name of the node where the IPCP will be created, `IPCP`
and `DIF` are the names of the shim-eth IPCP and DIF, and `NETDEV` is the
name of the network interface to bind.

An example of `configen` configuration (corresponding to the example
reported in **5.2**) is the following:

    eth A ethAB ethAB eth0
    eth B ethAB ethAB eth0
    eth B ethBC ethBC eth1
    eth C ethBC ethBC eth0
    dif n A ethAB
    dif n B ethAB ethBC
    dif n C ethBC

## 6. Configuration of IPC Processes

Each type of IPC Process has different configuration needs. shim IPC
Processes, in particular, wrap a legacy transport technology; their
configuration is closely related to the corresponding technology.


### 6.1. shim-eth IPC Process

The shim DIF over Ethernet wraps an L2 Ethernet network. A shim-eth IPCP
must be configured with the O.S. name of the Ethernet Network Interface Card
(NIC) that is attached to the network.

In the following example

    $ sudo rlite-ctl ipcp-config ether3 netdev eth2

a shim IPCP called ether3 is assigned a network interface called eth2.


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
    8.12.97.231     xyz.abc
    8.12.97.230     asd63

In this example, the IP 8.12.97.231 is mapped to an application called
xyz.abc, while the IP 8.12.97.230 is mapped to another application
called asd63. This means that this shim UDP implements a tunnel
between two nodes. The first endpoint node has a network interface configured
with the address 8.12.97.231 (with some netmask), and a RINA application
called xyz.abc can register to the local shim UDP IPCP. The other endpoint
node has a network interface configured with the address 8.12.97.232, and a
RINA application called asd63 can register to the local shim UDP IPCP.

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
file is stored at /etc/rina/shim-tcp4-dir.

An example configuration is the following:

    rinaperf-data|client 10.0.0.1 6789 i.DIF
    rinaperf-data|server 10.0.0.2 6788 i.DIF

where the application named rinaperf-data|client is mapped (bound) to the
TCP socket with address 10.0.0.1:6789 and rinaperf-data|server is mapped
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
To deactivate automatic address allocation, you need to set the **manual**
policy for the **addralloc** component using **rlite-ctl** program,
and configure addresses manually like in the following example:

    $ sudo rlite-ctl dif-policy-mod n.DIF adddress-allocator manual
    $ sudo rlite-ctl ipcp-config normal1.IPCP address 7382

where a normal IPCP called normal1.IPCP is given the address 7382 to be used
in its DIF.

The following table contains the parameters of a normal IPCP that can be
modified using the `ipcp-config` command:

| Parameter name  | Description                       |
| --------------- |-----------------------------------|
| address         | IPCP address in its DIF. It should be changed only with manual address allocation policy. |
| ttl             | Initial value for the TTL (Time To Live) field in the PDU header (default 64). |
| csum            | Checksum to perform on each PDU: possible values are "none" (default, no checksum) or "inet" (Internet checksum). |

#### 6.5.1. IPCP flavours to support different data transfer constants

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

with x,y,z,w, and u in {1,2,4,8}. By default, a _tiny_ flavour is
specified as follows:

    tiny    addr=1 seq=2 pdulen=2 cepid=1 qosid=1

which can be used for very small DIFs. A kernel module called
**normal-tiny.ko** is built and can be used as it were a completely
separate IPCP type (i.e. w.r.t. the default **normal.ko**). Actually,
it is just the same code (normal.c) recompiled with different values
of some macros.
You are free to add/modify flavours depending on your needs, and use
the different flavours together.

#### 6.5.2. Available policies and parameters
The following table reports policies that are available for the internal
components of a normal IPCP process:

| Component           | Policy name      | Description                       |
| ------------------- | -----------------|-----------------------------------|
| addralloc           | manual           | Manual address allocation         |
| addralloc           | distributed      | Automated address allocation      |
| dft                 | fully-replicated | Every node has a full copy of the DFT |
| dft                 | centralized-fault-tolerant | DFT stored by a fault-tolerant cluster of replicas |
| routing             | link-state       | Link state routing algorithm      |
| routing             | link-state-lfa   | Link state enhanced with Loop Free Alternate |
| routing             | static           | Statically configured routing rules |

This is an example of how to change the routing policy of the IPCP in a local
DIF

    # rlite-ctl dif-policy-mod n.DIF routing link-state-lfa

The following table reports parameters that can be changed for the components
of a normal IPCP process:

| Component           | Policy            | Parameter          | Description     |
| --------------------| ------------------|--------------------|-----------------|
| addralloc   | distributed       | nack-wait-secs     | Time to wait for a NACK before deciding that the address is good. |
| dft                 | centralized-fault-tolerant | replicas  | Name of the IPCPs that constitute the fault-tolerant cluster. |
| enrollment          | *                 | timeout            | Enrollment timeout in milliseconds. |
| enrollment          | *                 | keepalive          | Neighbor keepalive timeout in seconds (0 to disable). |
| enrollment          | *                 | keepalive-thresh   | Number of allowed unacked keepalive requests. If exceeded, the N-1 low is pruned. |
| enrollment          | *                 | auto-reconnect     | Automatically re-enroll to neighbors pruned because unresponsive. |
| flowalloc           | local             | force-flow-control | If false, flow control is used only with reliable flows. If true, flow control is always used. |
| flowalloc           | local             | max-rtxq-len       | Maximum size of the retransmission queue (in PDUs). |
| flowalloc           | local             | initial-rtx-timeout| Initial value for the DTCP retransmission timer (in milliseconds). |
| flowalloc           | local             | initial-a          | Initial value for the DTCP A timer (in milliseconds). |
| flowalloc           | local             | initial-credit     | Initial size of the DTCP flow control window (in PDUs). |
| flowalloc           | local             | max-cwq-len        | Maximum size of the DTCP closed window queue (in PDUs). |
| resalloc            | *                 | reliable-flows     | Use reliable N-flows if reliable N-1-flows are not available (boolean). |
| resalloc            | *                 | reliable-n-flows   | Use dedicated reliable N-1-flows for management traffic rather than reusing kernel-bound unreliable N-1 flows if possible (boolean). |
| resalloc            | *                 | broadcast-enroller | Let the IPCP register the name of the DIF (DAF name) in addition to the IPCP name (boolean). |
| ribd                | *                 | refresh-intval     | Time interval (in seconds) between two consecutive periodic RIB synchronizations. |
| routing             | *                 | age-incr-intval    | Time interval (in seconds) between two consecutive increments of the age of LFDB entries. |
| routing             | *                 | age-incr-max       | Maximum age (in seconds) allowed for an LFDB entry before being discarded. |

This is an example of how to change the nack-wait-secs parameter of the
distributed address allocation policy of a normal IPCP process

    # rlite-ctl dif-policy-param-mod n.DIF addralloc nack-wait-secs 4

This is an example how to enable reliable flows in the resource allocator

    # rlite-ctl dif-policy-param-mod n.DIF resalloc reliable-flows true

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
file descriptor. As a consequence, the
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

The iporinad daemon creates tunnels towards its peers and advertises IP routes
according to its configuration file.
In the following example, two iporinad daemons run on different edge nodes
that belong to the same DIF _n.DIF_. In this case, _n.DIF_ is the RINA network
that provides the IP tunnels. Each daemon is configured to register within
RINA, connect to the other peer, and advertise to the peer some routes that
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
Many `remote` directives are possible, one for each peer. A different tun
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

In the current iporinad prototype peers do not perform any routing or
dissemination protocol. As an example, if node A specifies B in its remotes,
A will send its local routes to B (and B will send its own to A at a later
time).
If B has a remote C that A does not have, then the routes received by B
from A will not be disseminated to C. It follows that the iporinad user
is normally expected to specify a full mesh in the configuration files
(e.g., A specifies B and C, B specifies A and C, and C specifies A and B).
Note that a proper routing protocol is anyway used by the DIF that supports
the tunnel, so it may be that when A tunnels an IP packet towards C, the
encapsulated RINA packet is routed to B to reach C.


### 7.3 rinaperf
The rinaperf program is a simple multi-threaded client/server application that is able to measure
network throughput and latency. It aims at providing basic performance measurement functionalities
akin to those provided by the popular netperf [12] and iperf [13] tools. In particular, rinaperf
tries to imitate netperf. In addition to that, rinaperf can also be seen as an example program
showing the usage of the RINA API in blocking mode.
When the -l option is used, rinaperf runs in server mode, otherwise it runs in client mode.
The server main thread runs a loop to accept new flow requests (`rina_flow_accept()`), and
each request is handled by a dedicated worker thread created on-demand. The main loop is also
responsible for joining the worker threads that finished serving their requests. A limit on the total
number of worker threads at each moment is used to keep the memory usage under control.
In client mode, rinaperf uses `rina_flow_alloc()` to allocate a flow, and then uses blocking
I/O to perform the test. The -p option can be specified to provide the number of flows that the
client is asked to allocate in parallel. Each flow is allocated and handled by a dedicated thread. The
default value for the -p option is 1, so that by default rinaperf allocates only one flow (using the
main thread). The client can specify various options to customize the performance test, including
the number of packets to send (or transactions to perform), the packet size, the flow QoS, the DIF
to use, the inter-packet transmission interval, the burst size, etc.
To date, three test types are supported:
 * ping, implementing a simple ping functionality for quick connectivity checks.
 * perf, which provides an unidirectional throughput test, similar to netperf UDP STREAM or
TCP STREAM tests.
 * rr, which measures the average latency of request/response transactions, similar to netperf
TCP RR or UDP RR tests.

For both client and server, each thread manages the I/O for a single flow, blocking on the I/O
calls when necessary. Concurrency is therefore achieved by means of multithreading. Running
rinaperf with the -h option will list all the available options.
As an example, the following rinaperf invocation will perform request-response tests with a
million transactions of 400 bytes packets:

    user@host ˜/rina # rinaperf -c 1000000 -t rr -s 400
    Starting request-response test; message size: 400, number of messages: 1000000, duration: inf
            Transactions    Kpps        Mbps        Latency (ns)
    Sender  1000000         145.569     465.821     6869

while the following performs a five seconds long undirectional throughput test with 1460 bytes
packets:

    user@host ˜/rina # rinaperf -t perf -s 1460 -D 5
    Starting unidirectional throughput test; message size: 1460, number of messages: inf, duration: 5 secs
                Packets     Kpps        Mbps
    Sender      6790377     1358.417    15866.311
    Receiver    5037989     988.051     11540.436


### 7.4 rina-echo-async
The rina-echo-async program is a single-threaded client/server application that implements an
echo service using only non-blocking I/O. Differently from rinaperf, rina-echo-async is meant to
be used for functional testing only; nevertheless, it is a compact educational example that shows
all the features of the RINA API in non-blocking mode.
When the -l option is used, rinaperf runs in server mode, otherwise it runs in client mode.
Both client and server are able to manage multiple flows in parallel, using a single thread and
without blocking on allocation, registration, accept or I/O. To achieve concurrency with a single
thread, the program is structured as an event-loop that manages an array of state machines. The
client state machine is illustrated in Figure 5. The edges in the graph show the pre-conditions for
the state transition (if any) and the actions to be performed when the transition happens. After
completing the flow allocation, the client writes a message to the server and receives the echoed
response coming back. In client mode, rina-echo-async keeps an array of independent client state
machines, to handle multiple concurrent echo sessions. The -p option can be used to specify how
many flows (sessions) to create and handle; by default, only a single flow is created.

![Client state machine](https://bitbucket.org/vmaffione/rina-images/downloads/rina-echo-async-client.png)

The server state machines are illustrated in Figure 6. After completing the registration, the
server starts accepting new sessions, denying them if the number of ongoing sessions grows beyond
a limit (128 in the current implementation). A new state machine is created for each accepted
session. The server therefore manages two types of state machines: one to accept new requests
(top of Figure 6), and the other one to serve a single client (bottom of Figure 6). There is one
instance of the first kind and multiple instance of the second, one per client. The per-client state
machine just receives the echo request and sends the echo response back to the client.

![Server state machine](https://bitbucket.org/vmaffione/rina-images/downloads/rina-echo-async-server.png)


## 8. Development workflow
The *rlite* project defines a verfication workflow that developers should follow
after performing any modification to the software.

![Development and verification workflow](https://bitbucket.org/vmaffione/rina-images/downloads/verification-workflow-rlite.png)

The demonstrator (`demo/demo.py`) and buildroot
(https://github.com/vmaffione/buildroot) are the main tools that
are used to quickly verify the correctness of any software modification,
as explained in the following (and illustrated in the diagram above).

To prepare your verification environment, first step is to download a
clone of buildroot, modified with rlite support, changing the last
line of `update.sh` (before running it), as indicated by the comments
inside the script itself:

    $ git clone https://github.com/vmaffione/buildroot
    $ cd buildroot
    $ vi update.sh  # change the last line to specify the path of your local rlite repo
    $ ./update.sh   # step 8 (make buildroot image)

Note that the first time you run the ./update.sh script, it will download and
build a complete GNU/Linux system from source; it may take hours, depending on the
speed of your internet connection and the computing power of your machine.
Subsequent invocations will only rebuild
rlite, which does not usually take more than 40 seconds.
The `update.sh` script will also copy the generated images to the `buildroot/`
directory inside your rlite local repo. This is necessary to let the
demonstrator use your generated images rather than the default ones.

By default, buildroot builds the rlite code from the master branch of the
github repository (https://github.com/vmaffione/rlite). However, you almost
always want to test a modified version of the code contained in your local
repository. To do so, modify the `package/rlite/rlite.mk` file, setting
`RLITE_SITE_METHOD` to `local` and `RLITE_SITE` to point to your local repo,
as suggested by the comments in the `.mk` file itself.

    $ cd buildroot
    $ vi package/rlite/rlite.mk

At this point you can run `./update.sh` after any modification to your
local repo, to create an updated version of the buildroot images.

Once you have built the images (kernel and ramdisk) from the code you want
to test, you can run the demonstrator to check that your code works
as expected.

    $ cd demo
    $ ./demo.py -c examples/two-layers.conf -r
    $ ./up.sh

You usually want to use the `-r` option to let each node register (in each DIF) an
instance of rina-echo-async server. Once the `up.sh` script terminates correctly,
you can check that all the DIFs provide connectivity, using the rina-echo-async
client to try to reach all the nodes (for each DIF). This is done automatically
by the `echo.sh` scripted (generated by the demonstrator tool).

    $ ./echo.sh

The demonstrator is also able to simulate random rinaperf clients on all the
nodes, running the `rlite-rand-clients` script on each node:

    $ ./demo.py -c examples/two-layers.conf -s

The `-M`, `-T`, `-D` and `-I` options can be used to tune the simulator
behaviour (see `./demo.py -h`).

To quickly carry out tests at scale, you can use the `--ring` option rather
than specifying a demonstrator configuration file

    $ ./demo.py --ring 200 -r -k 0

so that the demonstrator will automatically define a network of 200 nodes
arranged in a ring, with a single normal DIF including them all. On a machine
with 64 GB of RAM it is possible to deploy a ring of 350 nodes, when
giving each node the default amount of memory.


## 9. RINA API documentation
A convenient way to introduce the RINA API is to show how a simple application
would use the client-side and server-side API calls. This also eases the
comparison with sockets, where a similar walkthrough is often presented. Note
that in this context the term client simply refers to the initiator of the
flow allocation procedure (or TCP connection), while the term server refers to
the other peer. The discussion here, in other words, does not imply that the
client/server paradigm must be applied; the walkthrough is more general, being
valid also for other distributed application paradigms (e.g. peer-to-peer).
The workflow presented in this subsection refers to the
case of blocking operation, that is the API calls may block waiting for
asynchronous events; moreover, for the sake
of exposition, we assume that the operations do not fail.

![RINA API workflow for blocking operation](https://bitbucket.org/vmaffione/rina-images/downloads/api-blocking-workflow.png)

Non-blocking operations and errors are however covered by the API specification
(section 9.3) and the examples (sections 7.3 and 7.4).

### 9.1 Server-side operations
The first operation needed by the server, (1) the figure above, is `rina_open`, which
takes no arguments and returns a listening file descriptor (an integer, as
usual) to be used for subsequent server-side calls. This file descriptor is the
handler for an instance of a RINA control device which acts as a receiver for
incoming flow allocation requests. At (2), the server calls `rina_register` to
register a name with the RINA control device, specifying the associated
listening file descriptor (`lfd`), the name of the DIF to register to (`dif`)
and the name to be registered (`appl`). The DIF argument is optional and
advisory: the API implementation may choose to ignore it, and use some
namespace management strategy to decide into which DIF the name should be
registered. After a successful registration, the server can receive flow
allocation requests, by calling `rina_flow_accept` on the listening file
descriptor (3). Since the listening file descriptor was not put in
non-blocking mode, this call will block until a flow request arrives. When this
happens, the function returns a new file descriptor (`cfd`), the name of the
remote application (`src`) and the QoS granted to the flow. The returned file
descriptor is an handler for an instance of a RINA I/O device, to be used for
data I/O.
At this point (4) flow allocation is complete, and the server can exchange
SDUs with the client, using the `write` and `read` blocking calls or working in
non-blocking mode (possibly mutliplexing with other I/O devices, sockets, etc.)
by means of `poll` or `select`. This I/O phase is completely analogous to the
I/O exchange that happens with TCP or UDP sockets, only the QoS may be
different. Once the I/O session ends, the server can close the flow, triggering
flow deallocation through the `close` system call (5). The server can then decide
whether to terminate or accept another flow allocation request (3).


### 9.2 Client-side operations
Client operation is straightforward; the client calls `rina_flow_alloc` (1) to
issue a flow allocation request, passing as arguments the name of the DIF that
is asked to support the flow (`dif`), the name of the client (`src`, i.e. the
source application name), the name of the destination application (`dst`, i.e.
the server name) and the required QoS for the flow (`qos`). The call will block
until the flow allocation completes successfully, returning an file descriptor
(`fd`) to be used for data I/O. At this point the client can exchange SDUs with
the server (2), using the I/O file descriptor either in blocking or non-blocking
mode, similarly to what is possible to do with sockets. When the I/O
session terminates, the client can deallocate the flow with the `close` system
call.


### 9.3 API specification 
In the following, the API calls are listed and documented in depth.
Some general considerations:
 * The API functions typically return 0 or a positive value on success. On
   error, -1 is returned with the errno variable set accordingly to the
   specific error.
 * Each application name is specified using a C string, where the name’s components
(Application Process Name, Application Process Instance, Application Entity Name and
Applicatiion Entity Instance) are separated by the | separator (pipe).
The separator can be omitted if
it is only used to separate empty strings or a non-empty string from an empty string. Valid
strings are for instance "aa|bb|cc|dd", "aa|bb||", "aa|bb", "aa".


```
int rina_open(void)
```
    
This function opens a RINA control device that can be used to register/unregister names,
and manage incoming flow allocation requests. On success, it returns a file descriptor that can
be later passed to `rina_register()`, `rina_unregister()`, `rina_flow_accept()`, and
`rina_flow_respond()`. On error -1 is returned with errno set properly. Applications typically
call this function as a first step to implement server-side functionalities.

    int rina_register(int fd, const char *dif, const char *appl, int flags)
    
This function registers the application name appl to a DIF in the system. After a successful
registration, flow allocation requests can be received on fd by means of `rina_flow_accept()`.
If dif is not NULL, the system may register the application to dif. However, the dif argument
is only advisory and the implementation is free to ignore it. If DIF is NULL, the system au-
tonomously decide to which DIF appl will be registered to.
If `RINA_F_NOWAIT` is not specified in flags, this function will block the caller until the
operation completes, and 0 is returned on success.
If `RINA_F_NOWAIT` is specified in flags, the function returns a file descriptor (different
from fd) which can be used to wait for the operation to complete (e.g. using POLLIN with
poll() or select()). In this case the operation can be completed by a subsequent call to
`rina_register` wait().
On error -1 is returned, with the errno code properly set.

    int rina_unregister(int fd, const char *dif, const char *appl, int flags)
    
This function unregisters the application name appl from the DIF where it was registered to. The
dif argument must match the one passed to `rina_register()`. After a successful unregistration,
flow allocation requests can no longer be received on fd. The meaning of the `RINA_F_NOWAIT`
flag is the same as in `rina_register()`, allowing non-blocking unregistration, to be
later completed by calling `rina_register_wait()`.
Returns 0 on success, -1 on error, with the errno code properly set.

    int rina_register_wait(int fd, int wfd)
    
This function is called to wait for the completion of a (un)registration procedure previously
initiated with a call to `rina_register()` or `rina_unregister` on fd which had the `RINA_F_NOWAIT`
flag set. The wfd file descriptor must match the one that was returned by
rina[un]register(). It returns 0 on success, -1 error, with the errno code properly set.

    int rina_flow_accept(int fd, char **remote_appl,
                        struct rina_flow_spec *spec, unsigned int flags)

This function is called to accept an incoming flow request arrived on fd. If flags does not
contain `RINA_F_NORESP`, it also sends a positive response to the requesting application;
otherwise, the response (positive or negative) can be sent by a subsequent call to the
`rina_flow_respond()`. On success, the char* pointed by remote appl, if not NULL, is assigned the
name of the requesting application. The memory for the requestor name is allocated by the callee
and must be freed by the caller. Moreover, if spec is not NULL, the referenced data structure is
filled with the QoS specification specified by the requesting application.
If flags does not contain `RINA_F_NORESP`, on success this function returns a file descriptor
that can be subsequently used with standard I/O system calls (write(), read(), select()...)
to exchange SDUs on the flow and synchronize. If flags does contain `RINA_F_NORESP`, on
success a positive number is returned as an handle to be passed to a subsequent call to
`rina_flow_respond()`. Hence the code

    cfd = rina_flow_accept(fd, &x, flags &  RINA_F_NORESP)
    
is functionally equivalent to

    h = rina_flow_accept(sfd, &x, flags | RINA_F_NORESP);
    cfd = rina_flow_respond(sfd, h, 0 /* positive response */);
    
On error -1 is returned, with the errno code properly set.

    int rina_flow_respond(int fd, int handle, int response)

This function is called to emit a verdict on the flow allocation request identified by handle,
that was previously received on fd by calling `rina_flow_accept()` with the `RINA_F_NORESP`
flag set. A zero response indicates a positive response, which completes the flow allocation procedure.
A non-zero response indicates that the flow allocation request is denied. In both cases
response is sent to the requesting application to inform it about the verdict. When the response
is positive, on success this function returns a file descriptor that can be subsequently used with
standard I/O system calls to exchange SDUs on the flow and synchronize. When the response is
negative, 0 is returned on success. In any case, -1 is returned on error, with the errno code properly
set.

    int rina_flow_alloc(const char *dif, const char *local_appl,
                        const char *remote_appl,
                        const struct rina_flow_spec *flowspec,
                        unsigned int flags);
                        
This function is called to issue a flow allocation request towards the destination application
called remote appl, using local appl as a source application name. If flowspec is not
NULL, it specifies the QoS parameters to be used for the flow, should the flow allocation request
be successful. If it is NULL, an implementation-specific default QoS will be assumed instead
(which typically corresponds to a best-effort QoS). If dif is not NULL the system may look for
remote appl in a DIF called dif. However, the dif argument is only advisory and the system
is free to ignore it and take an autonomous decision.
If flags specifies `RINA_F_NOWAIT`, a call to this function does not wait until the completion
of the flow allocation procedure; on success, it just returns a control file descriptor that can be
subsequently fed to `rina_flow_alloc_wait()` to wait for completion and obtain the flow I/O
file descriptor. Moreover, the control file descriptor can be used with poll(), select() and
similar.
If flags does not specify `RINA_F_NOWAIT`, a call to this function waits until the flow allocation
procedure is complete. On success, it returns a file descriptor that can be subsequently used
with standard I/O system calls to exchange SDUs on the flow and synchronize.
In any case, -1 is returned on error, with the errno code properly set.

    int rina_flow_alloc_wait(int wfd)
    
This function waits for the completion of a flow allocation procedure previosuly initiated with
a call to `rina_flow_alloc()` with the `RINA_F_NOWAIT` flag set. The wfd file descriptor
must match the one returned by `rina_flow_alloc()`. On success, it returns a file descriptor
that can be subsequently used with standard I/O system calls to exchange SDUs on the flow and
synchronize. On error -1 is returned, with the errno code properly set.

    struct rina_flow_spec {
        uint64_t max_sdu_gap; /* in SDUs */
        uint64_t avg_bandwidth; /* in bits per second */
        uint32_t max_delay; /* in microseconds */
        uint16_t max_loss; /* percentage */
        uint32_t max_jitter; /* in microseconds */
        uint8_t in_order_delivery; /* boolean */
        uint8_t msg_boundaries; /* boolean */
    };
    void rina_flow_spec_unreliable(struct rina_flow_spec *spec)
        
This function fills in the provided spec with an implementation-specific default QoS, which
should correspond to a best-effort QoS. The fields of the rina flow spec data structure specify
the QoS of a RINA flow as follows:
 * max sdu gap specifies the maximum number of consecutive SDUs that can be lost without
violating the QoS. Specifying -1 means that there is no maximum, and so the flow is
unreliable; 0 means that no SDU can be lost and so the flow is reliable.
 * avg bandwidth specifies the maximum bandwidth that should be guaranteed on this flow,
in bits per second.
 * max delay specifies the maximum one-way latency that can be experienced by SDUs of
this flow without violating the QoS, expressed in microseconds.
 * max loss specifies the maximum percentage of SDUs that can be lost on this flow without
violating the QoS.
 * max jitter specifies the maximum jitter that can be experienced by SDUs on this flow
without violating the QoS.
 * in order delivery, if true requires that the SDUs are delivered in order on this flow
(no SDU reordering is allowed).
 * msg boundaries: if true, the flow is stream-oriented, like TCP; a stream-oriented flow
does not preserve message boundaries, and therefore write() and read() system calls
are used to exchange a stream of bytes, and the granularity of the exchange is the byte.
If false, the flow is datagram-oriented, like UDP, and does preserve message boundaries.
The I/O system calls are used to exchanges messages (SDUs), and the granularity of the
exchange is the message.    


### 9.4 Mapping sockets API to RINA API
The walkthough presented in sections 9.1 and 9.2 highlights the strong relationship between
the RINA POSIX API and the socket API. In this section we will explore this relationship in depth,
in order to
 * Define a clear mapping from socket calls to RINA calls, that can be used as a reference
strategy to port existing socket applications to RINA; it can never be stressed enough how
important the availability of real-world applications is to attract people to RINA.
 * Highlight the functionalities in the RINA API that are left outside the mapping, as there is
no corresponding functionality in the socket API.

The mapping is illustrated separately for client-side operations and server-side ones. Moreover,
for the sake of simplicity, it refers to Internet sockets, i.e. sockets belonging to the AF INET
and AF INET6 family.

![Mapping to the socket API](https://bitbucket.org/vmaffione/rina-images/downloads/socket-rina-mapping.png)

#### 9.4.1 Client-side mapping
The typical workflow of a TCP or UDP client – w.r.t socket calls – starts by creating a kernel socket
with the socket() system call; the arguments specify the type of socket to be created, i.e. the
address family (usually internet addresses over IPv4 or IPv6) and the contract with the application
(stream-oriented or datagram-oriented socket). The system call returns a file descriptor that is
passed to subsequent API and I/O calls. The client can optionally bind a local name to the socket,
that is a name for the local endpoint (e.g. source IP address and/or source UDP/TCP port); this
operation can be performed with the bind() system call.
Afterwards, the client can specify the name of the remote endpoint (e.g. destination IP address
and destination UDP/TCP port), using the connect() system call. This step is mandatory for
TCP sockets since it is also used to perform (or at least initiate) the TCP handshake, whereas it
is only optional for UDP sockets. A connected UDP socket can be useful when there is a single
remote endpoint, so that the client can use the write(), send(), read() and recv() system
calls that do not require the address of the remote address as an argument. If multiple endpoints
are possible (and the the client does not want to use multiple connected UDP sockets) a single
not-connected socket can be used with the sendmsg, sendto, recvmsg, recvfrom variants
to specify the address of the remote endpoint at each I/O operation.
If the socket file descriptor is set in non-blocking mode, the connect() system call on a
TCP socket will not block waiting for the TCP handshake to complete, but return immediately;
the client can then feed the file descriptor to select() (or poll()) waiting for it to become
writable, and when this happens it means that the TCP handshake is complete. Once the client-side
operations are done, I/O can start with the standard I/O system calls (write, read) or socketspecific
ones (recv(), send(), ...). When the session ends, the client closes the socket with
close().
The corresponding client-side operations can be done with the RINA API through
`rina_flow_alloc` and `rina_flow_alloc_wait`. In detail, `rina_flow_alloc` replaces the socket(),
bind() and connect() calls:
 * The name of the local endpoint is specified by the local appl argument.
 * The name of the remote endpoint is specified by the remote appl argument.
 * The return value is a file descriptor that can be used for flow I/O, so that there is no need for
a specific call to create the file descriptor (like socket()).

The non-blocking connect functionality is supported by passing the `RINA_F_NOWAIT` flag
to `rina_flow_alloc`; when this happens, the function does not wait for flow allocation to
complete, but returns a control file descriptor that can then be used with select/poll to wait;
when the control file descriptor becomes readable, it means that the flow allocation procedure is
complete and the client can call `rina_flow_alloc_wait` to receive the I/O file descriptor.
This analysis outlines the capabilities that the RINA API offers and that are not available
through the socket API:
 * In RINA the client can optionally specify the layer (i.e. the DIF) where the flow allocation
should happen, while with sockets the layer is implicit.
 * In RINA the client can specify the QoS required for the flow.
 * RINA has a complete naming scheme that is valid for any network application, whereas
sockets have multiple families with different (incomplete) naming schemes like IPv4+TCP/UDP,
IPv6+TCP/UDP, etc.

#### 9.4.2 Server-side mapping
Server-side socket operations start with the creation of a socket to be used to listen for incoming
requests. Similarly to the client, this is done with the socket system call and the returned file
descriptor is used for subsequent operations. The server then binds a local name to the socket,
using the bind() system call; differently from the client case, this step is mandatory, as the server
must indicate on what IP address and ports it is available to receive incoming TCP connections
or UDP datagrams. If the socket is UDP, at this point the server can start receiving and sending
datagrams, using the recvfrom, recvmsg, sendto and sendmsg system calls. It could
also optionally bind a remote name with connect(), if it is going to serve only a client (the
considerations about connected UDP sockets reported in section 9.4.1 are also valid here).
If the socket is TCP, the server needs to call the listen() system call to indicate that is going
to accept incoming TCP connection on the address and port bound to the socket, indicating the size
of the backlog queue as a parameter. This operation puts the socket in listening mode. Afterwards,
the server can invoke the accept() system call to wait for the next TCP connection to come
from a client. The accept() function returns a new file descriptor and the name of the remote
endpoint (that is the address and port of the client). The file descriptor can then be used to perform
the I/O with the client, using read(), write(), send(), recv(), etc., and possibly using
I/O multiplexing (select and poll). Moreover, if the listening socket is set in non-blocking
mode, the server can use select() or poll() to wait for the socket to become readable, which
indicates a new TCP connection has arrived and can be accepted with accept(). When the I/O
session ends, the server closes the client socket with close().
Similar server-side operations can be performed with the RINA API. A RINA control device
to receive incoming flow request is open with `rina_open`, similarly to the socket() call. This
function returns a file descriptor that can be used to register names and accept requests. The
`rina_register` function is called to register an application name, possibly specifying a DIF
name; the control file descriptor is passed as a first parameter, so that the file descriptor can be
used to accept requests for the registered name. The `rina_register` operations corresponds
therefore to the combined effect of bind and listen for sockets. It is possible to call
`rina_register` multiple times to register multiple names.
At this point the server can start accepting incoming flow allocation requests by calling
`rina_flow_accept` on the control file descriptor (passed as first argument). When the
`RINA_F_NOWAIT` flag is not specified, this operation has the same meaning of the socket accept
call. In detail:
 * The function blocks until a flow allocation request comes, and the request is implicitely
accepted.
 * A file descriptor is returned to be used for flow I/O.
 * The name of the remote application can be obtained through the remote appl output
argument.
 * The QoS of the new flow (specified by the remote application) can be obtained through the
spec output argument.

Non-blocking accept is also possible, since the control file descriptor can be set in non-blocking
mode and passed to poll/select. The control file descriptor becomes readable when there is a
pending flow allocation request ready to be accepted.
Also the server-side analysis, summarized in the figure abovev, uncovers some capabilities
of the RINA API that are not possible with the socket API:
 * When the `RINA_F_NOWAIT` flag is passed to `rina_flow_accept`, the application can
decide whether to accept or deny the flow allocation request, possibly taking into account
the flow QoS, the remote application name and the server internal state. The verdict is
emitted using the `rina_flow_respond` call.
 * The server can use the QoS to customize its action (e.g. a video streaming server application
could choose among different encodings).




## Credits

*rlite* is a community-driven project partially supported by the EU FP7
projects PRISTINE and ARCFIRE.

Author:         Vincenzo Maffione

Contributors:   Michal Koutenský
