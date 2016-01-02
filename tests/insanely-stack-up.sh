#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rlite-config ipcp-create d.IPCP 1 shim-loopback d.DIF
rlite-config ipcp-config d.IPCP 1 queued 1

NM1DIF="d.DIF"

for i in $(seq 1 30); do
    rlite-config ipcp-create n.1.IPCP $i normal n.${i}.DIF
    rlite-config ipcp-create n.2.IPCP $i normal n.${i}.DIF
    rlite-config ipcp-config n.1.IPCP $i address 21
    rlite-config ipcp-config n.2.IPCP $i address 22
    rlite-config ipcp-register $NM1DIF n.1.IPCP $i
    rlite-config ipcp-register $NM1DIF n.2.IPCP $i
    rlite-config ipcp-enroll n.${i}.DIF n.1.IPCP $i n.2.IPCP $i $NM1DIF
    NM1DIF="n.${i}.DIF"
done

#user/rinaperf -p n.1.IPCP -P $LEVEL -l &
#user/rinaperf -p n.2.IPCP -P $LEVEL

source tests/epilogue.sh
