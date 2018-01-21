#!/bin/bash

# Create two normal IPCPs and enroll one to the other,
# using a third IPCP as a N-1 DIF.
# Use manual address allocation to speed up the test
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-create y normal dd || exit 1
rlite-ctl ipcp-create z normal zz || exit 1
rlite-ctl dif-policy-mod dd address-allocator manual || exit 1
rlite-ctl ipcp-config x address 76 || exit 1
rlite-ctl ipcp-config y address 77 || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1
rlite-ctl ipcp-enroller-enable z || exit 1
rlite-ctl ipcp-register x zz || exit 1
rlite-ctl ipcp-register y zz || exit 1
rlite-ctl ipcp-enroll y dd zz x || exit 1
# Disconnect y from x
rlite-ctl ipcp-neigh-disconnect y x || exit 1
# Enroll again
rlite-ctl ipcp-enroll y dd zz x || exit 1
# Reset to wait for all the flows to go away
rlite-ctl reset
