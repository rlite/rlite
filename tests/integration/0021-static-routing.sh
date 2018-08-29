#!/bin/bash -e

# Create two normal IPCPs and enroll one to the other,
# using a third IPCP as a N-1 DIF.
# Use static address allocation to speed up the test
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-create y normal dd
rlite-ctl ipcp-create z normal zz
rlite-ctl ipcp-config z flow-del-wait-ms 200
rlite-ctl dif-policy-mod dd addralloc static
rlite-ctl dif-policy-mod dd routing static
rlite-ctl ipcp-config x address 76
rlite-ctl ipcp-config y address 77
rlite-ctl ipcp-enroller-enable x
rlite-ctl ipcp-enroller-enable z
rlite-ctl ipcp-register x zz
rlite-ctl ipcp-register y zz
rlite-ctl ipcp-enroll y dd zz x
# Positive tests
rlite-ctl ipcp-route-add x y y
rlite-ctl ipcp-route-add y x x
rlite-ctl ipcp-route-add x w zz,qq
rlite-ctl ipcp-route-del x w
rlite-ctl ipcp-route-add x z y,p
# For the following show commands IPCP 'x' is selected (and not 'y')
rlite-ctl dif-routing-show dd | grep "\<y\>"
rlite-ctl dif-routing-show dd | grep "\<p\>"
# Negative tests
rlite-ctl ipcp-route-add && exit 1
rlite-ctl ipcp-route-add x && exit 1
rlite-ctl ipcp-route-add x ee && exit 1
rlite-ctl ipcp-route-add x ff t,l,ll,e,l && exit 1
rlite-ctl ipcp-route-del x ff && exit 1
true
