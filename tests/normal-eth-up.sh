#!/bin/bash

source tests/prologue.sh
source tests/env.sh

ID=1
if [ -n "$1" ]; then
    ID=$1
fi

shift

IF=eth0
if [ -n "$1" ]; then
    IF=$1
fi

$RINACONF ipcp-create shim-eth e.IPCP 1
$RINACONF ipcp-config e.IPCP 1 netdev $IF
$RINACONF ipcp-config e.IPCP 1 dif e.DIF

$RINACONF ipcp-create normal n.IPCP ${ID}
$RINACONF ipcp-config n.IPCP ${ID} dif n.DIF
$RINACONF ipcp-config n.IPCP ${ID} address $ID
$RINACONF ipcp-register e.DIF n.IPCP ${ID}

source tests/epilogue.sh
