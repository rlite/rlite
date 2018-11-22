#!/bin/bash -e

source tests/libtest.sh

# Create a veth pair
create_veth_pair rinau.veth
ip addr add 10.11.12.13/24 dev rinau.veth.0
ip addr add 10.11.12.14/24 dev rinau.veth.1
cp /etc/hosts /etc/hosts.save
cumulative_trap "cp /etc/hosts.save /etc/hosts" "EXIT"
echo "10.11.12.13 rpinstance5" > /etc/hosts

# Create a shim-udp4 for each end of the pair. DIF should be
# the same, but we'll cheat only for the purpose of testing.
rlite-ctl ipcp-create us0 shim-udp4 d0
rlite-ctl ipcp-create us1 shim-udp4 d1
rlite-ctl ipcp-config us0 flow-del-wait-ms 100
rlite-ctl ipcp-config us1 flow-del-wait-ms 100

# Register an application on the first shim-udp4 and run a client
# from the other shim.
start_daemon rina-echo-async -lw -z rpinstance5 -d d0
rina-echo-async -z rpinstance5 -d d1
# Register an application that has no mapping in /etc/hosts, to check
# it fails.
rina-echo-async -l -z rpinstance6 -d d0 && exit 1
# Another client
rina-echo-async -z rpinstance5 -d d1
