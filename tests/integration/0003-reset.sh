#!/bin/sh

# Create some IPCPs
rlite-ctl ipcp-create x normal xx || exit 1
rlite-ctl ipcp-create y shim-loopback yy || exit 1
rlite-ctl ipcp-create z normal zz || exit 1
# Check that they are in kernel
rlite-ctl | grep dif_name | grep "\<x\>" | grep "\<xx\>" || exit 1
rlite-ctl | grep dif_name | grep "\<y\>" | grep "\<yy\>" || exit 1
rlite-ctl | grep dif_name | grep "\<z\>" | grep "\<zz\>" || exit 1
# Reset
rlite-ctl reset
# Check that the IPCPs are gone
rlite-ctl | grep dif_name && exit 1
exit 0
