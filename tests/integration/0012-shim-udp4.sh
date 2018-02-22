#!/bin/bash

function cleanup() {
    pkill rina-echo-async
    rlite-ctl reset || exit 1
    ip link del rinau.veth0 || exit 1
    cp /etc/hosts.save /etc/hosts
}

function abort() {
    cleanup
    exit 1
}

# Create a veth pair
ip link add rinau.veth0 type veth peer name rinau.veth1
ip link set rinau.veth0 up
ip link set rinau.veth1 up
ip addr add 10.11.12.13/24 dev rinau.veth0
ip addr add 10.11.12.14/24 dev rinau.veth1
cp /etc/hosts /etc/hosts.save
echo "10.11.12.13 rpinstance5" > /etc/hosts

# Create a shim-udp4 for each end of the pair. DIF should be
# the same, but we'll cheat only for the purpose of testing.
rlite-ctl ipcp-create us0 shim-udp4 d0 || abort
rlite-ctl ipcp-create us1 shim-udp4 d1 || abort

# Register an application on the first shim-udp4 and run a client
# from the other shim.
rina-echo-async -lw -z rpinstance5 -d d0 || abort
rina-echo-async -z rpinstance5 -d d1 || abort
# Register an application that has no mapping in /etc/hosts, to check
# it fails.
rina-echo-async -l -z rpinstance6 -d d0 && abort
# Another client
rina-echo-async -z rpinstance5 -d d1 || abort

# Cleanup
cleanup
