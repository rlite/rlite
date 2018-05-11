#!/bin/sh

cleanup() {
    local ret=0
    pkill rinaperf
    ip netns exec green rlite-ctl reset || ret=1
    ip netns exec green rlite-ctl terminate || ret=1
    ip netns exec red rlite-ctl reset || ret=1
    ip netns exec red rlite-ctl terminate || ret=1
    rlite-ctl reset || ret=1
    ip netns delete green || ret=1
    ip netns delete red || ret=1
    # veths are autodeleted once the namespace is deleted
    [ "$ret" != 0 ] && return 1 || return 0
}

abort() {
    cleanup
    exit 1
}

# Create two namespaces, a veth pair, and assign each end of the pair
# to a different namespace.
ip link add veth.green type veth peer name veth.red || abort
ip link set veth.red up || abort
ip netns add green || abort
ip netns add red || abort
ip link set veth.green netns green || abort
ip link set veth.red netns red || abort

# Normal over shim eth setup in the green namespace
ip netns exec green ip link set lo up || abort
ip netns exec green rlite-uipcps -d || abort
ip netns exec green ip link set veth.green up || abort
ip netns exec green rlite-ctl ipcp-create green.eth shim-eth edif || abort
ip netns exec green rlite-ctl ipcp-config green.eth netdev veth.green || abort
ip netns exec green rlite-ctl ipcp-create green.n normal mydif || abort
ip netns exec green rlite-ctl ipcp-enroller-enable green.n || abort
ip netns exec green rlite-ctl ipcp-register green.n edif || abort
ip netns exec green rlite-ctl dif-policy-param-mod mydif addralloc nack-wait 1s || abort
ip netns exec green rinaperf -lw -z rpinst1 || abort

# Normal over shim eth setup in the red namespace
ip netns exec red ip link set lo up || abort
ip netns exec red rlite-uipcps -d || abort
ip netns exec red ip link set veth.red up || abort
ip netns exec red rlite-ctl ipcp-create red.eth shim-eth edif || abort
ip netns exec red rlite-ctl ipcp-config red.eth netdev veth.red || abort
ip netns exec red rlite-ctl ipcp-create red.n normal mydif || abort
ip netns exec red rlite-ctl ipcp-register red.n edif || abort
ip netns exec red rlite-ctl ipcp-enroll red.n mydif edif green.n || abort

# Check that policy parameters were transferred
ip netns exec red rlite-ctl dif-policy-param-list mydif addralloc nack-wait | grep "\<1000ms\>" || abort

# Check application connectivity
ip netns exec red rinaperf -z rpinst1 -p 1 -c 7 -i 20 || abort

# Check if uipcp-stats-show works
ip netns exec red rlite-ctl uipcp-stats-show || abort
ip netns exec green rlite-ctl uipcp-stats-show || abort

cleanup
