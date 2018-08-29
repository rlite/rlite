#!/bin/bash -e

# Create two normal IPCPs and enroll one to the other,
# using a third IPCP as a N-1 DIF.
# Use static address allocation to speed up the test
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-create y normal dd
rlite-ctl ipcp-create z normal zz
rlite-ctl ipcp-config z flow-del-wait-ms 200
rlite-ctl dif-policy-mod dd addralloc static
rlite-ctl ipcp-config x address 76
rlite-ctl ipcp-config y address 77
rlite-ctl ipcp-enroller-enable x
rlite-ctl ipcp-enroller-enable z
rlite-ctl ipcp-register x zz
rlite-ctl ipcp-register y zz
rlite-ctl ipcp-enroll y dd zz x
# Disconnect y from x
rlite-ctl ipcp-neigh-disconnect y x
# Enroll again
rlite-ctl ipcp-enroll y dd zz x
