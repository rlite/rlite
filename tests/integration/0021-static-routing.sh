#!/bin/bash

# Create two normal IPCPs and enroll one to the other,
# using a third IPCP as a N-1 DIF.
# Use static address allocation to speed up the test
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-create y normal dd || exit 1
rlite-ctl ipcp-create z normal zz || exit 1
rlite-ctl ipcp-config z flow-del-wait-ms 200 || exit 1
rlite-ctl dif-policy-mod dd addralloc static || exit 1
rlite-ctl dif-policy-mod dd routing static || exit 1
rlite-ctl ipcp-config x address 76 || exit 1
rlite-ctl ipcp-config y address 77 || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1
rlite-ctl ipcp-enroller-enable z || exit 1
rlite-ctl ipcp-register x zz || exit 1
rlite-ctl ipcp-register y zz || exit 1
rlite-ctl ipcp-enroll y dd zz x || exit 1
# Positive tests
rlite-ctl ipcp-route-add x y y || exit 1
rlite-ctl ipcp-route-add y x x || exit 1
rlite-ctl ipcp-route-add x w zz,qq || exit 1
rlite-ctl ipcp-route-del x w || exit 1
rlite-ctl ipcp-route-add x z y,p || exit 1
# For the following show commands IPCP 'x' is selected (and not 'y')
rlite-ctl dif-routing-show dd | grep "\<y\>" || exit 1
rlite-ctl dif-routing-show dd | grep "\<p\>" || exit 1
# Negative tests
rlite-ctl ipcp-route-add && exit 1
rlite-ctl ipcp-route-add x && exit 1
rlite-ctl ipcp-route-add x ee && exit 1
rlite-ctl ipcp-route-add x ff t,l,ll,e,l && exit 1
rlite-ctl ipcp-route-del x ff && exit 1
# Reset to wait for all the flows to go away
rlite-ctl reset
