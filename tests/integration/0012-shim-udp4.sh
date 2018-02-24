#!/bin/sh

cleanup() {
    local ret=0
    pkill rina-echo-async
    rlite-ctl reset || ret=1
    ip link set rinau.veth0 up || ret=1
    ip link set rinau.veth1 up || ret=1
    ip link del rinau.veth0 || ret=1
    cp /etc/hosts.save /etc/hosts
    [ "$ret" != 0 ] && return 1 || return 0
}

abort() {
    cleanup
    exit 1
}

# Create a veth pair
ip link add rinau.veth0 type veth peer name rinau.veth1 || exit 1
ip link set rinau.veth0 up || abort
ip link set rinau.veth1 up || abort
ip addr add 10.11.12.13/24 dev rinau.veth0 || abort
ip addr add 10.11.12.14/24 dev rinau.veth1 || abort
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
