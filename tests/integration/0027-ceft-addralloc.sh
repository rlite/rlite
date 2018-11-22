#!/bin/bash -e

source tests/libtest.sh

# Multi-namespace test for the ceft-aa policy. This does not test behaviour
# in case of failures.

# Create four namespaces, connected on the same LAN through a software
# bridge and veth pairs.
#
#          S2
#          |
#     S1---+-----+----S3
#          |     |
#          C1    C2
#
# C1 and C2 are client nodes, while S1, S2 and S3 run a CEFT addralloc protocol.
create_bridge vethbr1
for cont in s1 s2 s3 c1 c2; do
    create_veth_pair veth ${cont}h ${cont}c
    create_namespace ${cont}
    ip link set veth.${cont}c netns ${cont}
    ip link set veth.${cont}h master vethbr1
done

# Normal over shim setup in all the namespaces
for cont in s1 s2 s3 c1 c2; do
    ip netns exec ${cont} ip link set veth.${cont}c up
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.eth shim-eth ethdif
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.eth netdev veth.${cont}c
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.eth flow-del-wait-ms 100
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.n normal ceftdif
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.n flow-del-wait-ms 100
    ip netns exec ${cont} rlite-ctl ipcp-register ${cont}.n ethdif
done

# S1 is going to be the enrollment master, the others enroll to it
# (except for C2 which enrolls to C1, see below).
ip netns exec s1 rlite-ctl dif-policy-mod ceftdif addralloc centralized-fault-tolerant
ip netns exec s1 rlite-ctl dif-policy-param-mod ceftdif addralloc replicas s1.n,s2.n,s3.n
ip netns exec s1 rlite-ctl ipcp-enroller-enable s1.n
# Carry out the enrollments
for cont in s2 s3 c1 c2; do
    if [ "$cont" == "c1" ]; then
        # Once S1, S2 and S3 have joined the DIF, we wait a little bit to let
        # the cluster elect a leader
        sleep 1.5
    fi
    enroller=s1.n
    if [ "$cont" == "c2" ]; then
        # S1 acts an enroller for S2, S3 and C1. However, we let C2 enroll
        # to C1, so that the test covers the case where the CEFT client (C1)
        # is not a replica.
        enroller=c1.n
    fi
    ip netns exec ${cont} rlite-ctl ipcp-enroll-retry ${cont}.n ceftdif ethdif $enroller
    # Check that policy were transferred on enrollment. No need to check policy
    # params, because we check for connectivity (which depends on correct
    # propagation of addralloc.replicas).
    ip netns exec ${cont} rlite-ctl dif-policy-list ceftdif addralloc | grep -q "\<centralized-fault-tolerant\>"
done

sleep 3

start_daemon_namespace s2 rinaperf -lw -z rpinst1
start_daemon_namespace c1 rinaperf -lw -z rpinst2
sleep 0.5 # give some time to commit registration to the cluster
ip netns exec c1 rinaperf -z rpinst1 -i 0 -c 5
ip netns exec s1 rinaperf -z rpinst2 -i 0 -c 5
ip netns exec c2 rinaperf -z rpinst1 -i 0 -c 5
# Give some time to commit the unregistrations to the cluster. This
# is not necessary for the test to be successful, but it is useful
# anyway to improve test coverage.
sleep 1
