#############################################################################
## 1. Software requirements                                                 #
#############################################################################

This sections lists the software packages required to build and run *rlite* on
Linux-based operating systems. Only Ubuntu 14.04 and Archlinux are indicated
here, but using other distributions should be straightforward.

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
## 3. Overview of the software components                                      #
#############################################################################

This section briefly describes the software components of *rlite*.

### 3.1. Kernel modules
#############################################################################

A main kernel module **rlite** which implements core functionalities:

* The control device for managing IPCPs, flows, registrations, etc.
* The I/O device for SDU write and read
* IPCP factories

A separate module for each type of IPCP:

* **rlite-normal**, implementing the kernel-space part of the regular IPCPs.
                    Includes EFCP and RMT.
* **rlite-shim-eth**, implementing the Shim IPCP over Ethernet.
* **rlite-shim-tcp4**, implementing the kernel-space part of the Shim IPCP
                        over TCP/UDP and IPv4.
* **rlite-shim-hv**, implementing the Shim IPCP over VMPI.
* **rlite-shim-loopback**, implementing a loopback Shim IPCP.


### 3.2. Userspace IPCPs daemon
#############################################################################

A daemon program, **rlite-uipcps**, which implements the user-space part of
the normal IPCP and of the shim-tcp4 IPCP. A main thread listens on a UNIX
socket to serve incoming requests from the **rlite-ctl** control tool.
A different thread is used for each IPCP running in the system.

For the normal IPCP, uipcps daemon implements the following components:

* Enrollment
* Routing, management of lower flows and neighbors
* Application registrarion
* Flow allocation
* Codecs for RIB objects


### 3.3. Libraries
#############################################################################

Four libraries are available:

* **librlite**, the main library, wrapping the control device and I/O device.
                This is the library used by applications to register names
                and allocate flows.
* **librlite-evloop**, implementing an extensible event-loop over a control
                       device. Used by **rlite-uipcps** and the RINA
                       gateway application.
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

In order to show all the available command and the corresponding usage, use

    $ rlite-ctl -h


### 3.5. Other tools
#############################################################################

Other programs are available for testing and deployment:

* **rinaperf**, an application for network throughput and latency performance
                measurement. Use `rinaperf -h` to see the availble commmands.
* **rina-gw**, a deamon program implementing a gateway between a TCP/IP
               network and a RINA network.
* **rina-rr-tool**, a simple echo program written using the Python bindings.

#### Examples of rinaperf usage

Run the server, registering on a DIF called *n.DIF*:

    $ rinaperf -l -d n.DIF

Note that the server can only manage requests one by one.

Run the client in ping mode, asking a DIF called *n.DIF* to allocate a flow:

    $ rinaperf -d -n.DIF

Run the client in perf mode, asking a DIF called *n.DIF* to allocate a flow,
using 1200 bytes sized SDUs:

    $ rinaperf -d -n.DIF -s 1200


### 3.6. Python bindings
#############################################################################

If your system runs Python, you can write applications using the *rlite*
Python bindings, which are a wrapper for the **librlite** library. Run

    >>> import rlite
    >>> help(rlite)

in the Python interpreter, in order to see the available classes.
The **rina-rr-tool** script is an example written using these bindings.



#############################################################################
## 4. Tutorials                                                             #
#############################################################################

### 4.1 Using the demonstrator
#############################################################################

The demonstrator is a tool written in Python which allows you to deploy
arbitrarily complex networks, in your PC, using light Virtual Machines.

Enter the demo directory in the repository and run

    $ ./demo.py -h

to see available options.

The *rlite* demonstrator is compatible with the one
available at https://github.com/IRATI/demonstrator, which means that the
configuration files are interchangeable. The documentation contained
in the README.md file of the latter repository is still valid, with the
following differences:

1. The **policy** directive is not supported
2. The name of **eth** instances does not need to be a valid VLAN id
3. The legacy mode is not supported, only the buildroot mode is supported


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

Using another termial, access node **c** and run **rinaperf** in
client ping mode:

    $ ./access.sh c
    # rlite-ctl ipcps-show  # Show the IPCPs in the system
    # rinaperf -d n1.DIF -c 1000 -s 460

This will produce 1000 request/response transactions between client and server,
and the client will report the average round trip time.

Exit the node shell and teardown the scenario:

    $ ./down.sh


### 4.2 Hands-on tutorial
#############################################################################

This tutorial shows how to manually reproduce the configuration described
in demo/demo.conf, assuming that *rlite* is installed on all the three nodes.
The nodes can be realized either with physical or virtual machines.

In the demo.conf configuration, three nodes (A, B and C) are connected through
Ethernet links to form a linear topology:

    A ----- B ---- C

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

On node A, set-up the interface towards B and create a Shim IPCP
over Ethernet:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethAB.IPCP 1 shim-eth ethAB.DIF

Bind the shim IPCP to eth0, so that the network interface will be used
to send and receive packets:

    $ sudo rlite-ctl ipcp-config ethAB.IPCP 1 netdev eth0

Create a normal IPCP and give it an address in the normal DIF:

    $ sudo rlite-ctl ipcp-create a.IPCP 1 normal n.DIF
    $ sudo rlite-ctl ipcp-config a.IPCP 1 address 71

Let the normal IPCP register to the shim DIF:

    $ sudo rlite-ctl ipcp-register ethAB.DIF a.IPCP 1


On node B, similar operations are carried out for both the interfaces:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethAB.IPCP 1 shim-eth ethAB.DIF
    $ sudo rlite-ctl ipcp-config ethAB.IPCP 1 netdev eth0
    $
    $ sudo ip link set eth1 up
    $ sudo rlite-ctl ipcp-create ethBC.IPCP 1 shim-eth ethBC.DIF
    $ sudo rlite-ctl ipcp-config ethBC.IPCP 1 netdev eth1
    $
    $ sudo rlite-ctl ipcp-create b.IPCP 1 normal n.DIF
    $ sudo rlite-ctl ipcp-config b.IPCP 1 address 72
    $ sudo rlite-ctl ipcp-register ethAB.DIF b.IPCP 1
    $ sudo rlite-ctl ipcp-register ethBC.DIF b.IPCP 1

On node C:

    $ sudo ip link set eth0 up
    $ sudo rlite-ctl ipcp-create ethBC.IPCP 1 shim-eth ethBC.DIF
    $ sudo rlite-ctl ipcp-config ethBC.IPCP 1 netdev eth0
    $
    $ sudo rlite-ctl ipcp-create c.IPCP 1 normal n.DIF
    $ sudo rlite-ctl ipcp-config c.IPCP 1 address 73
    $ sudo rlite-ctl ipcp-register ethBC.DIF c.IPCP 1

Once the IPCPs are set up, we have to carry out the enrollments in
the normal DIF. Among the possible strategies, we can enroll A and
C against B, so that B will be the initial node in the DIF.

On node A, enroll a.IPCP/1// to the neighbor b.IPCP/1// using
ethAB.DIF as a supporting DIF:

    $ sudo rlite-ctl ipcp-enroll n.DIF a.IPCP 1 b.IPCP 1 ethAB.DIF

On node C, enroll c.IPCP/1// to the neighbor b.IPCP/1// using
ethBC.DIF as a supporting DIF:

    $ sudo rlite-ctl ipcp-enroll n.DIF c.IPCP 1 b.IPCP 1 ethBC.DIF

On any node, you can check the standard output of the userspace daemon,
to check that the previous operations are completed with success.
Also the kernel log (dmesg) contains valuable log information.

It is also possible to check the list of IPCPs running in the local system:

    $ sudo rlite-ctl ipcps-show

or see the flows allocated in the local system (in this case the 0-flows
provided by the Shim DIFs, which are being used by the normal DIF):

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

