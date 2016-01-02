#!/bin/bash

source tests/prologue.sh
source tests/env.sh

IF=eth0
if [ -n "$1" ]; then
    IF=$1
fi

$RINACONF ipcp-create e.IPCP 1 shim-eth e.DIF
$RINACONF ipcp-config e.IPCP 1 netdev $IF

source tests/epilogue.sh
