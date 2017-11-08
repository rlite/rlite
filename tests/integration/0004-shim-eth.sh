#!/bin/bash

# Create a veth pair
ip link add rina.veth0 type veth peer name rina.veth1
ip link set rina.veth0 up
ip link set rina.veth1 up

# Create a shim-eth for each end of the pair. DIF should be
# the same, but we'll cheat only for the purpose of testing.
rlite-ctl ipcp-create s0 shim-eth d0 || exit 1
rlite-ctl ipcp-create s1 shim-eth d1 || exit 1
rlite-ctl ipcp-config s0 netdev rina.veth0 || exit 1
rlite-ctl ipcp-config s1 netdev rina.veth1 || exit 1

# Register an application on the first shim-eth
rina-echo-async -lw -z rpinstance4 -d d0 || exit 1
# Run some clients on the other shim-eth
rina-echo-async -z rpinstance4 -d d1 || exit 1

# Cleanup
pkill rina-echo-async
rlite-ctl reset || exit 1
ip link del rina.veth0 || exit 1
