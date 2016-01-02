#!/bin/bash

source tests/prologue.sh
source tests/env.sh

IF=eth0
if [ -n "$1" ]; then
    IF=$1
fi

rlite-config ipcp-create e.IPCP 1 shim-eth e.DIF
rlite-config ipcp-config e.IPCP 1 netdev $IF

source tests/epilogue.sh
