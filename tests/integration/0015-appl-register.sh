#!/bin/bash

cleanup() {
    pkill rinaperf
}

abort() {
    cleanup
    exit 1
}

# Create two normal IPCPs and register some applications
rlite-ctl ipcp-create x normal xx || abort
rlite-ctl ipcp-create y normal yy || abort
rlite-ctl ipcp-config x flow-del-wait-ms 50 || abort
rlite-ctl ipcp-config y flow-del-wait-ms 50 || abort
rinaperf -lw -z rpinstance9 -d xx || abort
rinaperf -lw -z rpinstance10 -d yy || abort
# Check that the RIB reports the two entries in the DFT
rlite-ctl dif-rib-show xx | grep "\<Application\>" | grep "\<Remote node\>" | grep "\<rpinstance9\>" || abort
rlite-ctl dif-rib-show yy | grep "\<Application\>" | grep "\<Remote node\>" | grep "\<rpinstance10\>" || abort
cleanup
