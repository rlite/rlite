#!/bin/bash -e

source tests/libtest.sh

# Create two namespaces, a veth pair, and assign each end of the pair
# to a different namespace.
create_veth_pair veth green red
create_namespace green
create_namespace red
ip link set veth.green netns green
ip link set veth.red netns red

# Normal over shim eth setup in the green namespace
ip netns exec green ip link set veth.green up
ip netns exec green rlite-ctl ipcp-create green.eth shim-eth edif
ip netns exec green rlite-ctl ipcp-config green.eth netdev veth.green
ip netns exec green rlite-ctl ipcp-config green.eth flow-del-wait-ms 100
ip netns exec green rlite-ctl ipcp-create green.n normal mydif
ip netns exec green rlite-ctl ipcp-config green.n flow-del-wait-ms 100
ip netns exec green rlite-ctl dif-policy-mod mydif addralloc static
ip netns exec green rlite-ctl ipcp-config green.n address 8172
ip netns exec green rlite-ctl ipcp-enroller-enable green.n
ip netns exec green rlite-ctl ipcp-register green.n edif
start_daemon_namespace green rinaperf -lw -z rpinst1

# Normal over shim eth setup in the red namespace
ip netns exec red ip link set veth.red up
ip netns exec red rlite-ctl ipcp-create red.eth shim-eth edif
ip netns exec red rlite-ctl ipcp-config red.eth netdev veth.red
ip netns exec red rlite-ctl ipcp-config red.eth flow-del-wait-ms 100
ip netns exec red rlite-ctl ipcp-create red.n normal mydif
ip netns exec red rlite-ctl ipcp-config red.n flow-del-wait-ms 100
ip netns exec red rlite-ctl dif-policy-mod mydif addralloc static
ip netns exec green rlite-ctl ipcp-config green.n address 2718
ip netns exec red rlite-ctl ipcp-register red.n edif
ip netns exec red rlite-ctl ipcp-enroll red.n mydif edif
ip netns exec red rinaperf -z rpinst1 -p 1 -c 7 -i 20
