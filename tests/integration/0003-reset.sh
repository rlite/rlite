#!/bin/bash -e

# Create some IPCPs
rlite-ctl ipcp-create x normal xx
rlite-ctl ipcp-create y shim-loopback yy
rlite-ctl ipcp-create z normal zz
# Check that they are in kernel
rlite-ctl | grep dif_name | grep "\<x\>" | grep "\<xx\>"
rlite-ctl | grep dif_name | grep "\<y\>" | grep "\<yy\>"
rlite-ctl | grep dif_name | grep "\<z\>" | grep "\<zz\>"
# Reset
rlite-ctl reset
# Check that the IPCPs are gone
rlite-ctl | grep dif_name && exit 1
exit 0
