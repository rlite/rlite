#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-ctl ipcp-create d.IPCP/1// shim-loopback d.DIF
sudo rlite-ctl ipcp-config d.IPCP/1// queued 1

NM1DIF="d.DIF"

for i in $(seq 1 30); do
    sudo rlite-ctl ipcp-create n.1.IPCP/$i// normal n.${i}.DIF
    sudo rlite-ctl ipcp-create n.2.IPCP/$i// normal n.${i}.DIF
    sudo rlite-ctl ipcp-config n.1.IPCP/$i// address 21
    sudo rlite-ctl ipcp-config n.2.IPCP/$i// address 22
    sudo rlite-ctl ipcp-register $NM1DIF n.1.IPCP/$i//
    sudo rlite-ctl ipcp-register $NM1DIF n.2.IPCP/$i//
    sudo rlite-ctl ipcp-enroll n.${i}.DIF n.1.IPCP/$i// n.2.IPCP/$i// $NM1DIF
    NM1DIF="n.${i}.DIF"
done

#user/rinaperf -p n.1.IPCP -P $LEVEL -l &
#user/rinaperf -p n.2.IPCP -P $LEVEL

source tests/epilogue.sh
