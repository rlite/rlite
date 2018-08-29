#!/bin/bash -e

# Create two normal IPCPs and enroll one to the other,
# using a third IPCP as a N-1 DIF.
# Use static address allocation to speed up the test
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-create y normal dd
rlite-ctl ipcp-create z normal zz
rlite-ctl ipcp-config z flow-del-wait-ms 200
rlite-ctl dif-policy-mod dd addralloc static
rlite-ctl ipcp-config x address 1
rlite-ctl ipcp-config y address 2
rlite-ctl ipcp-enroller-enable z
rlite-ctl ipcp-register x zz
#rlite-ctl ipcp-register y zz
# x is not enabled yet as an enroller, so enrollment should fail
rlite-ctl ipcp-enroll y dd zz x && exit 1
# Now we enable x as an enroller
rlite-ctl ipcp-enroller-enable x
# And check enrollment works
rlite-ctl ipcp-enroll y dd zz x
# Now disconnect y from x and disable the x as an enroller
rlite-ctl ipcp-neigh-disconnect y x
rlite-ctl ipcp-enroller-disable x
# Check that enrollment fails again
rlite-ctl ipcp-enroll y dd zz x && exit 1
true
