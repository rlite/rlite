#!/bin/sh

# Multi-namespace test for the ceft-dft policy. This does not test behaviour
# in case of failures.

cleanup() {
    local ret=0
    pkill rinaperf
    for cont in s1 s2 s3 c; do
        ip netns exec ${cont} rlite-ctl reset || ret=1
        ip netns exec ${cont} rlite-ctl terminate || ret=1
        ip netns delete ${cont} || ret=1
    done
    rm -f /tmp/ceft-dft-*
    # veths are autodeleted once the namespace is deleted
    ip link del vethbr0 type bridge || ret=1
    [ "$ret" != 0 ] && return 1 || return 0
}

abort() {
    cleanup
    exit 1
}

# Create four namespaces, connected on the same LAN through a software
# bridge and veth pairs.
#
#          S2
#          |
#     S1---+---S3
#          |
#          C
#
# C is a client node, while S1, S2 and S3 run a CEFT dft protocol.
ip link add name vethbr0 type bridge
ip link set vethbr0 up
for cont in s1 s2 s3 c; do
    ip link add veth.${cont}h type veth peer name veth.${cont}c || abort
    ip link set veth.${cont}h up || abort
    ip link set veth.${cont}c up || abort
    ip netns add ${cont} || abort
    ip link set veth.${cont}c netns ${cont} || abort
    ip link set veth.${cont}h master vethbr0 || abort
done

# Normal over shim setup in all the namespaces
for cont in s1 s2 s3 c; do
    ip netns exec ${cont} ip link set lo up || abort
    ip netns exec ${cont} rlite-uipcps -d || abort
    ip netns exec ${cont} ip link set veth.${cont}c up || abort
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.eth shim-eth ethdif || abort
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.eth netdev veth.${cont}c || abort
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.n normal ceftdif || abort
    ip netns exec ${cont} rlite-ctl ipcp-register ${cont}.n ethdif || abort
done

# S1 is going to be the enrollment master, the others enroll to it
ip netns exec s1 rlite-ctl dif-policy-param-mod ceftdif addralloc nack-wait 1s || abort
ip netns exec s1 rlite-ctl dif-policy-param-mod ceftdif dft replicas s1.n,s2.n,s3.n || abort
ip netns exec s1 rlite-ctl dif-policy-mod ceftdif dft centralized-fault-tolerant || abort
ip netns exec s1 rlite-ctl dif-policy-mod ceftdif routing link-state-lfa || abort
ip netns exec s1 rlite-ctl ipcp-enroller-enable s1.n || abort
for cont in s2 s3 c; do
    # Carry out the enrollment
    ip netns exec ${cont} rlite-ctl ipcp-enroll ${cont}.n ceftdif ethdif s1.n || abort
    # Check that policy were transferred on enrollment. No need to check policy
    # params, because we check for connectivity (which depends on correct
    # propagation of dft.replicas).
    ip netns exec ${cont} rlite-ctl dif-policy-list ceftdif dft | grep -q "\<centralized-fault-tolerant\>" || abort
    ip netns exec ${cont} rlite-ctl dif-policy-list ceftdif routing | grep -q "\<link-state-lfa\>" || abort
done

sleep 3

ip netns exec s2 rinaperf -lw -z rpinst1 || abort
ip netns exec c rinaperf -lw -z rpinst2 || abort
sleep 0.5 # give some time to commit registration to the cluster
ip netns exec c rinaperf -z rpinst1 -p 1 -c 7 -i 10 || abort
ip netns exec s1 rinaperf -z rpinst2 -p 1 -c 3 -i 10 || abort
pkill rinaperf
# Give some time to commit the unregistrations to the cluster. This
# is not necessary for the test to be successful, but it is useful
# anyway to improve test coverage.
sleep 1
cleanup
