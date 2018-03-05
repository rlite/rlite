#!/bin/sh

# Create two normal IPCPs and enroll one to the other,
# using a third IPCP as a N-1 DIF.
# Use manual address allocation to speed up the test
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-create y normal dd || exit 1
rlite-ctl ipcp-create z normal zz || exit 1
rlite-ctl dif-policy-mod dd addralloc manual || exit 1
rlite-ctl ipcp-config x address 1 || exit 1
rlite-ctl ipcp-config y address 2 || exit 1
rlite-ctl ipcp-enroller-enable z || exit 1
rlite-ctl ipcp-register x zz || exit 1
#rlite-ctl ipcp-register y zz || exit 1
# x is not enabled yet as an enroller, so enrollment should fail
rlite-ctl ipcp-enroll y dd zz x && exit 1
# Now we enable x as an enroller
rlite-ctl ipcp-enroller-enable x || exit 1
# And check enrollment works
rlite-ctl ipcp-enroll y dd zz x || exit 1
# Now disconnect y from x and disable the x as an enroller
rlite-ctl ipcp-neigh-disconnect y x || exit 1
rlite-ctl ipcp-enroller-disable x || exit 1
# Check that enrollment fails again
rlite-ctl ipcp-enroll y dd zz x && exit 1
rlite-ctl reset
