#!/bin/bash -e

# Create two normal IPCPs and enroll one to the other,
# using a third IPCP as a N-1 DIF.
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-create y normal dd
rlite-ctl ipcp-create z normal zz
rlite-ctl ipcp-enroller-enable x
rlite-ctl ipcp-enroller-enable z
rlite-ctl ipcp-register x zz
rlite-ctl ipcp-register y zz
rlite-ctl dif-policy-param-mod dd addralloc nack-wait 1s
rlite-ctl ipcp-enroll y dd zz x
# Reset to wait for all the flows to go away
rlite-ctl ipcp-config z flow-del-wait-ms 100
rlite-ctl reset
