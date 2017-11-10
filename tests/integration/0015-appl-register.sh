#!/bin/bash

function cleanup() {
    pkill rinaperf
}

function abort() {
    cleanup
    exit 1
}

# Create two normal IPCPs and register some applications
rlite-ctl ipcp-create x normal xx || abort
rlite-ctl ipcp-create y normal yy || abort
rinaperf -lw -z rpinstance9 -d xx || abort
rinaperf -lw -z rpinstance10 -d yy || abort
# Check that the RIB reports the two entries in the DFT
rlite-ctl dif-rib-show xx | grep "\<Application\>" | grep "\<Address\>" | grep "\<rpinstance9\>" || abort
rlite-ctl dif-rib-show yy | grep "\<Application\>" | grep "\<Address\>" | grep "\<rpinstance10\>" || abort
cleanup
