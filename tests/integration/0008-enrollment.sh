#!/bin/sh

# Create two normal IPCPs and enroll one to the other,
# using a third IPCP as a N-1 DIF.
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-create y normal dd || exit 1
rlite-ctl ipcp-create z normal zz || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1
rlite-ctl ipcp-enroller-enable z || exit 1
rlite-ctl ipcp-register x zz || exit 1
rlite-ctl ipcp-register y zz || exit 1
rlite-ctl dif-policy-param-mod dd addralloc nack-wait 1s || exit 1
rlite-ctl ipcp-enroll y dd zz x || exit 1
# Reset to wait for all the flows to go away
rlite-ctl reset
