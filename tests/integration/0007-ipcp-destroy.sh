#!/bin/bash -e

# Check that we could not destroy something that does not exist
rlite-ctl ipcp-destroy x && exit 1
# Create a normal IPCP, and also another one
rlite-ctl ipcp-create x normal xx
rlite-ctl ipcp-create z normal zz
# Check that kernel knows x it's there
rlite-ctl | grep dif_name | grep "\<x\>" | grep "\<xx\>"
rlite-ctl | grep dif_name | grep "\<z\>" | grep "\<zz\>"
# Destroy it and check that x it's not there anymore, but z is
rlite-ctl ipcp-destroy x
rlite-ctl | grep dif_name | grep "\<x\>" | grep "\<xx\>" && exit 1
rlite-ctl | grep dif_name | grep "\<z\>" | grep "\<zz\>"
