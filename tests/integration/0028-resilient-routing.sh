#!/bin/bash -e

source tests/libtest.sh

# Multi-namespace test for link-state-lfa (resilient routing).

# First parameter: link name (e.g. "ab")
# Second parameter: "up" or "down"
link_set() {
    local li=$1
    local status=$2
    left=${li:0:1}
    right=${li:1:1}
    ip netns exec $left ip link set veth.${li}l $status
    ip netns exec $right ip link set veth.${li}r $status
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
    create_namespace ${cont}
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.n normal normdif
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.n flow-del-wait-ms 100
done
for li in ab ac ad bd cd; do
    create_veth_pair veth ${li}l ${li}r
    left=${li:0:1}
    right=${li:1:1}
    ip link set veth.${li}l netns $left
    ip link set veth.${li}r netns $right
    ip netns exec $left ip link set veth.${li}l up
    ip netns exec $right ip link set veth.${li}r up
    # Normal over shim setup in all the namespaces
    ip netns exec $left rlite-ctl ipcp-create ${li}l.eth shim-eth ${li}dif
    ip netns exec $right rlite-ctl ipcp-create ${li}r.eth shim-eth ${li}dif
    ip netns exec ${left} rlite-ctl ipcp-config ${li}l.eth netdev veth.${li}l
    ip netns exec ${right} rlite-ctl ipcp-config ${li}r.eth netdev veth.${li}r
    ip netns exec ${left} rlite-ctl ipcp-config ${li}l.eth flow-del-wait-ms 100
    ip netns exec ${right} rlite-ctl ipcp-config ${li}r.eth flow-del-wait-ms 100
    ip netns exec ${left} rlite-ctl ipcp-register ${left}.n ${li}dif
    ip netns exec ${right} rlite-ctl ipcp-register ${right}.n ${li}dif
done

# Carry out the enrollments, with A being the enrollment master.
ip netns exec a rlite-ctl dif-policy-mod normdif routing link-state-lfa
ip netns exec a rlite-ctl dif-policy-param-mod normdif addralloc nack-wait 500ms
ip netns exec a rlite-ctl ipcp-enroller-enable a.n
for li in ab ac ad; do
    left=${li:0:1}
    right=${li:1:1}
    ip netns exec ${right} rlite-ctl ipcp-enroll ${right}.n normdif ${li}dif ${left}.n
done
ip netns exec a rlite-ctl dif-routing-show normdif
for li in bd cd; do
    left=${li:0:1}
    right=${li:1:1}
    ip netns exec ${right} rlite-ctl ipcp-lower-flow-alloc ${right}.n normdif ${li}dif ${left}.n
done
ip netns exec a rlite-ctl dif-routing-show normdif

# Run a server on D
start_daemon_namespace d rinaperf -lw -z rpinstd
# Check that A can connect to D
ip netns exec a rinaperf -z rpinstd -i 0 -c 1
# Now bring AD down
link_set ad down
# Check that A can still connect to D (through B)
ip netns exec a rinaperf -z rpinstd -i 0 -c 1
# Now bring AB and BD down
link_set ab down
link_set bd down
# Check that A can still connect to D (through C)
ip netns exec a rinaperf -z rpinstd -i 0 -c 1
# Now bring AC down
link_set ac down
# Check that A cannot connect to D
ip netns exec a rinaperf -z rpinstd -i 0 -c 1 && false
# Bring AD back up
link_set ad up
# Check that A can connect to D
ip netns exec a rinaperf -z rpinstd -i 0 -c 1
