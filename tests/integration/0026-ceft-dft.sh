#!/bin/bash -e

source tests/libtest.sh

# Multi-namespace test for the ceft-dft policy. This does not test behaviour
# in case of failures.

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
create_bridge vethbr0
for cont in s1 s2 s3 c; do
    create_veth_pair veth ${cont}h ${cont}c
    create_namespace ${cont}
    add_veth_to_namespace ${cont} veth.${cont}c
    ip link set veth.${cont}h master vethbr0
done

# Normal over shim setup in all the namespaces
for cont in s1 s2 s3 c; do
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.eth shim-eth ethdif
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.eth netdev veth.${cont}c
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.eth flow-del-wait-ms 100
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.n normal ceftdif
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.n flow-del-wait-ms 100
    ip netns exec ${cont} rlite-ctl ipcp-register ${cont}.n ethdif
done

# S1 is going to be the enrollment master, the others enroll to it
ip netns exec s1 rlite-ctl dif-policy-param-mod ceftdif addralloc nack-wait 1s
ip netns exec s1 rlite-ctl dif-policy-mod ceftdif dft centralized-fault-tolerant
ip netns exec s1 rlite-ctl dif-policy-param-mod ceftdif dft replicas s1.n,s2.n,s3.n
ip netns exec s1 rlite-ctl dif-policy-mod ceftdif routing link-state-lfa
ip netns exec s1 rlite-ctl ipcp-enroller-enable s1.n
for cont in s2 s3 c; do
    # Carry out the enrollment
    ip netns exec ${cont} rlite-ctl ipcp-enroll ${cont}.n ceftdif ethdif s1.n
    # Check that policy were transferred on enrollment. No need to check policy
    # params, because we check for connectivity (which depends on correct
    # propagation of dft.replicas).
    ip netns exec ${cont} rlite-ctl dif-policy-list ceftdif dft | grep -q "\<centralized-fault-tolerant\>"
    ip netns exec ${cont} rlite-ctl dif-policy-list ceftdif routing | grep -q "\<link-state-lfa\>"
done

sleep 3

start_daemon_namespace s2 rinaperf -lw -z rpinst1
start_daemon_namespace c rinaperf -lw -z rpinst2
sleep 0.5 # give some time to commit registration to the cluster
ip netns exec c rinaperf -z rpinst1 -p 1 -c 7 -i 10
ip netns exec s1 rinaperf -z rpinst2 -p 1 -c 3 -i 10
# Give some time to commit the unregistrations to the cluster. This
# is not necessary for the test to be successful, but it is useful
# anyway to improve test coverage.
sleep 1
