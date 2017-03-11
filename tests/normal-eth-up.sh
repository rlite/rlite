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

sudo rlite-ctl ipcp-create e.IPCP:1 shim-eth e.DIF
sudo rlite-ctl ipcp-config e.IPCP:1 netdev $IF

sudo rlite-ctl ipcp-create n.IPCP:${ID} normal n.DIF
sudo rlite-ctl ipcp-config n.IPCP:${ID} address $ID
sudo rlite-ctl ipcp-register n.IPCP:${ID} e.DIF

source tests/epilogue.sh
