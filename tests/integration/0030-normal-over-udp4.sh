#!/bin/bash -e

source tests/libtest.sh

# Create two namespaces, a veth pair, and assign each end of the pair
# to a different namespace.
create_veth_pair veth red green
create_namespace green
create_namespace red
add_veth_to_namespace green veth.green
ip netns exec green ip addr add 10.10.10.52/24 dev veth.green
add_veth_to_namespace red veth.red
ip netns exec red ip addr add 10.10.10.4/24 dev veth.red

cp /etc/hosts /etc/hosts.save
cumulative_trap "cp /etc/hosts.save /etc/hosts" "EXIT"
echo "10.10.10.4      xnorm.IPCP" >> /etc/hosts
echo "10.10.10.52     ynorm.IPCP" >> /etc/hosts
ip netns exec green ping -c 1 -i 0.1 10.10.10.4

# Normal over shim-udp4 setup in the green namespace
ip netns exec green rlite-ctl ipcp-create yipgateway.IPCP shim-udp4 udptunnel.DIF
ip netns exec green rlite-ctl ipcp-config yipgateway.IPCP flow-del-wait-ms 100
ip netns exec green rlite-ctl ipcp-create ynorm.IPCP normal normal.DIF
ip netns exec green rlite-ctl ipcp-config ynorm.IPCP flow-del-wait-ms 900
ip netns exec green rlite-ctl ipcp-register ynorm.IPCP udptunnel.DIF
ip netns exec green rlite-ctl dif-policy-param-mod normal.DIF addralloc nack-wait 1s
ip netns exec green rlite-ctl ipcp-enroller-enable ynorm.IPCP
start_daemon_namespace green rinaperf -lw -z rpinst1

# Normal over shim-udp4 setup in the red namespace
ip netns exec red rlite-ctl ipcp-create xipgateway.IPCP shim-udp4 udptunnel.DIF
ip netns exec red rlite-ctl ipcp-config xipgateway.IPCP flow-del-wait-ms 100
ip netns exec red rlite-ctl ipcp-create xnorm.IPCP normal normal.DIF
ip netns exec red rlite-ctl ipcp-config xnorm.IPCP flow-del-wait-ms 900
ip netns exec red rlite-ctl ipcp-register xnorm.IPCP udptunnel.DIF
ip netns exec red rlite-ctl ipcp-enroll xnorm.IPCP normal.DIF udptunnel.DIF ynorm.IPCP

# Check that policy parameters were transferred
ip netns exec red rlite-ctl dif-policy-param-list normal.DIF addralloc nack-wait | grep "\<1000ms\>"

# Check application connectivity
ip netns exec red rinaperf -a rpinstcli1 -z rpinst1 -p 1 -c 7 -i 20
# Check that flow shows up in RIB dumps.
ip netns exec red rlite-ctl dif-rib-show | grep "rpinst1,ynorm.IPCP,"
ip netns exec red rlite-ctl dif-rib-show | grep "rpinstcli1,xnorm.IPCP,"
ip netns exec green rlite-ctl dif-rib-show | grep "rpinst1,ynorm.IPCP,"
ip netns exec green rlite-ctl dif-rib-show | grep "rpinstcli1,xnorm.IPCP,"

# Check if uipcp-stats-show works
ip netns exec red rlite-ctl uipcp-stats-show
ip netns exec green rlite-ctl uipcp-stats-show
