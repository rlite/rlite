#!/bin/sh

cleanup() {
    local ret=0
    pkill rinaperf
    for cont in s1 s2 s3 c; do
        ip netns exec ${cont} rlite-ctl reset || ret=1
        ip netns exec ${cont} rlite-ctl terminate || ret=1
        ip netns delete ${cont} || ret=1
    done
    # veths are autodeleted once the namespace is deleted
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

brctl show vethbr0  # TODO remove me

# Normal over shim setup in all the namespaces
for cont in s1 s2 s3 c; do
    ip netns exec ${cont} ip link set lo up || abort
    ip netns exec ${cont} rlite-uipcps -d || abort
    ip netns exec ${cont} ip link set veth.${cont}c up || abort
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.eth shim-eth ethdif || abort
    ip netns exec ${cont} rlite-ctl ipcp-config ${cont}.eth netdev veth.${cont}c || abort
    ip netns exec ${cont} rlite-ctl ipcp-create ${cont}.n normal ceftdif || abort
    ip netns exec ${cont} rlite-ctl ipcp-register ${cont}.n ethdif || abort
    ip netns exec ${cont} rlite-ctl dif-policy-param-mod ceftdif addralloc nack-wait-secs 1 || abort
    ip netns exec ${cont} rlite-ctl dif-policy-mod ceftdif dft centralized-fault-tolerant || abort
    ip netns exec ${cont} rlite-ctl dif-policy-param-mod ceftdif dft replicas s1.n,s2.n,s3.n || abort
done

# S1 is going to be the enrollment master, the others enroll to it
ip netns exec s1 rlite-ctl ipcp-enroller-enable s1.n || abort
for cont in s2 s3 c; do
    ip netns exec ${cont} rlite-ctl ipcp-enroll ${cont}.n ceftdif ethdif s1.n || abort
done

#ip netns exec green rinaperf -lw -z rpinst1 || abort
#ip netns exec red rinaperf -z rpinst1 -p 1 -c 7 -i 20 || abort
cleanup
