#!/bin/bash

source tests/libtest.sh

# Create a veth pair
create_veth_pair rina.veth || exit 1

cumulative_trap "rlite-ctl reset" "EXIT"

# Create a shim-eth for each end of the pair. DIF should be
# the same, but we'll cheat only for the purpose of testing.
rlite-ctl ipcp-create s0 shim-eth d0 || exit 1
rlite-ctl ipcp-create s1 shim-eth d1 || exit 1
rlite-ctl ipcp-config s0 netdev rina.veth0 || exit 1
rlite-ctl ipcp-config s1 netdev rina.veth1 || exit 1
rlite-ctl ipcp-config s1 netdev rina.veth0 && exit 1
rlite-ctl ipcp-config-get s0 netdev | grep "\<rina.veth0\>" || exit 1
rlite-ctl ipcp-config-get s0 wrongy && exit 1
rlite-ctl ipcp-config s0 flow-del-wait-ms 100 || exit 1
rlite-ctl ipcp-config s1 flow-del-wait-ms 100 || exit 1

# Register an application on the first shim-eth
start_daemon rina-echo-async -lw -z rpinstance4 -d d0 || exit 1
# Run some clients on the other shim-eth
rina-echo-async -z rpinstance4 -d d1 || exit 1
