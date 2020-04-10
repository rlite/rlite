#!/bin/bash -e

source tests/libtest.sh

# Multi-namespace test for the bw-res policy. This does not test behaviour
# in case of failures.

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
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.n normal bwresdif
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.n flow-del-wait-ms 100
done
for li in ab ac ad bd cd; do
    create_veth_pair veth ${li}l ${li}r
    left=${li:0:1}
    right=${li:1:1}
    add_veth_to_namespace ${left} veth.${li}l
    add_veth_to_namespace ${right} veth.${li}r
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
ip netns exec a rlite-ctl dif-policy-mod bwresdif flowalloc bw-res
ip netns exec a rlite-ctl dif-policy-param-mod bwresdif flowalloc replicas a.n,b.n,c.n
ip netns exec a rlite-ctl dif-policy-param-mod bwresdif flowalloc default-bw 2000000000 # 2 Gbps
ip netns exec a rlite-ctl ipcp-enroller-enable a.n
for li in ab ac ad; do
    left=${li:0:1}
    right=${li:1:1}
    ip netns exec ${right} rlite-ctl ipcp-enroll ${right}.n bwresdif ${li}dif ${left}.n
done

# Check that policy and policy parameters were transferred on enrollment.
for cont in a b c d; do
    ip netns exec ${cont} rlite-ctl dif-policy-list bwresdif flowalloc | grep -q "\<bw-res\>"
    ip netns exec ${cont} rlite-ctl dif-policy-param-list bwresdif flowalloc | grep -q "/mgmt/flowalloc.default-bw = '2000000000'"
    ip netns exec ${cont} rlite-ctl dif-policy-param-list bwresdif flowalloc | grep -q "/mgmt/flowalloc.replicas = 'a.n,b.n,c.n'"
done

sleep 3

start_daemon_namespace a rinaperf -lw -z rpinst1
start_daemon_namespace b rinaperf -lw -z rpinst2
sleep 0.5 # give some time to commit registration to the cluster
ip netns exec c rinaperf -v -z rpinst1 -t ping -D 2 &
sleep 0.5 # give some time to reserve flow
RIB="$(ip netns exec b rlite-ctl dif-rib-show)"
printf "%s" "$RIB" | grep -q -F 'c.na.n1: c.n->a.n (c.n,a.n,) : 2000000000'
printf "%s" "$RIB" | grep -q -F 'Local: c.n, Remote: a.n, Cost: 1, Seqnum: 1, State: 1, Age: 10, Total Bandwidth: 10000000000, Free Bandwidth: 6000000000'
sleep 3 # clean the flows
# use up 9Gbps
ip netns exec c rinaperf -v -z rpinst1 -t ping -D 3 -B 1500000000 &
sleep 0.5
ip netns exec c rinaperf -v -z rpinst1 -t ping -D 3 -B 1500000000 &
sleep 0.5
ip netns exec c rinaperf -v -z rpinst1 -t ping -D 3 -B 1500000000 &
sleep 0.5 # give some time to reserve flow
# try to allocate another 4Gbps -> should fail
if ip netns exec c rinaperf -v -z rpinst1 -t ping -c 1; then
    false
else
    true
fi

sleep 4 # wait for the ping to finish
