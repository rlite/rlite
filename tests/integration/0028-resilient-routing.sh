#!/bin/bash

# Multi-namespace test for link-state-lfa (resilient routing).

cleanup() {
    local ret=0
    pkill rinaperf
    for cont in a b c d; do
        ip netns exec ${cont} rlite-ctl reset || ret=1
        ip netns exec ${cont} rlite-ctl terminate || ret=1
        ip netns delete ${cont} || ret=1
    done
    [ "$ret" != 0 ] && return 1 || return 0
}

abort() {
    cleanup
    exit 1
}

# Create four namespaces, connected on the same LAN through a software
# bridge and veth pairs.
#
#     A----B
#     | \  |
#     |  \ |
#     |   \|
#     C----D
#
for cont in a b c d; do
    ip netns add ${cont} || abort
    ip netns exec ${cont} ip link set lo up || abort
    ip netns exec ${cont} rlite-uipcps -d || abort
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.n normal normdif || abort
done
for li in ab ac ad bd cd; do
    ip link add veth.${li}l type veth peer name veth.${li}r || abort
    ip link set veth.${li}l up || abort
    ip link set veth.${li}r up || abort
    left=${li:0:1}
    right=${li:1:1}
    ip link set veth.${li}l netns $left || abort
    ip link set veth.${li}r netns $right || abort
    ip netns exec $left ip link set veth.${li}l up || abort
    ip netns exec $right ip link set veth.${li}r up || abort
    # Normal over shim setup in all the namespaces
    ip netns exec $left rlite-ctl ipcp-create ${li}l.eth shim-eth ${li}dif || abort
    ip netns exec $right rlite-ctl ipcp-create ${li}r.eth shim-eth ${li}dif || abort
    ip netns exec ${left} rlite-ctl ipcp-config ${li}l.eth netdev veth.${li}l || abort
    ip netns exec ${right} rlite-ctl ipcp-config ${li}r.eth netdev veth.${li}r || abort
    ip netns exec ${left} rlite-ctl ipcp-register ${left}.n ${li}dif || abort
    ip netns exec ${right} rlite-ctl ipcp-register ${right}.n ${li}dif || abort
done

# Carry out the enrollments, with A being the enrollment master.
ip netns exec a rlite-ctl dif-policy-mod normdif routing link-state-lfa || abort
ip netns exec a rlite-ctl dif-policy-param-mod normdif addralloc nack-wait 500ms
ip netns exec a rlite-ctl ipcp-enroller-enable a.n || abort
for li in ab ac ad; do
    left=${li:0:1}
    right=${li:1:1}
    ip netns exec ${right} rlite-ctl ipcp-enroll ${right}.n normdif ${li}dif ${left}.n || abort
done

ip netns exec a rlite-ctl dif-routing-show normdif || abort

for li in bd cd; do
    left=${li:0:1}
    right=${li:1:1}
    ip netns exec ${right} rlite-ctl ipcp-lower-flow-alloc ${right}.n normdif ${li}dif ${left}.n || abort
done

ip netns exec a rlite-ctl dif-routing-show normdif || abort

cleanup
