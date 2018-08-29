#!/bin/bash -e

source tests/libtest.sh

# Create two normal IPCPs and register some applications
rlite-ctl ipcp-create x normal xx
rlite-ctl ipcp-create y normal yy
rlite-ctl ipcp-config x flow-del-wait-ms 50
rlite-ctl ipcp-config y flow-del-wait-ms 50
start_daemon rinaperf -lw -z rpinstance9 -d xx
start_daemon rinaperf -lw -z rpinstance10 -d yy
# Check that the RIB reports the two entries in the DFT
rlite-ctl dif-rib-show xx | grep "\<Application\>" | grep "\<Remote node\>" | grep "\<rpinstance9\>"
rlite-ctl dif-rib-show yy | grep "\<Application\>" | grep "\<Remote node\>" | grep "\<rpinstance10\>"
