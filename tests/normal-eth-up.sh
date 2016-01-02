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

sudo rlite-config ipcp-create e.IPCP 1 shim-eth e.DIF
sudo rlite-config ipcp-config e.IPCP 1 netdev $IF

sudo rlite-config ipcp-create n.IPCP ${ID} normal n.DIF
sudo rlite-config ipcp-config n.IPCP ${ID} address $ID
sudo rlite-config ipcp-register e.DIF n.IPCP ${ID}

source tests/epilogue.sh
