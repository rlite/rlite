#!/bin/bash

# Create a normal IPCP
rlite-ctl ipcp-create x normal xx || exit 1
# Check that kernel knows it's there
rlite-ctl | grep dif_name | grep "\<x\>" | grep "\<xx\>"
# Check that it responds to RIB queries
rlite-ctl dif-rib-show xx || exit 1
rlite-ctl dif-routing-show xx || exit 1
rlite-ctl dif-rib-paths-show xx || exit 1
