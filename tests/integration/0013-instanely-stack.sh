#!/bin/bash -e

rlite-ctl ipcp-create d.IPCP normal d.DIF

NM1DIF="d.DIF"

for i in $(seq 1 10); do
    rlite-ctl ipcp-create n.1.$i normal n.${i}.DIF
    rlite-ctl ipcp-create n.2.$i normal n.${i}.DIF
    rlite-ctl ipcp-config n.1.$i address 21
    rlite-ctl ipcp-config n.2.$i address 22
    rlite-ctl ipcp-register n.1.$i $NM1DIF
    rlite-ctl ipcp-register n.2.$i $NM1DIF
    rlite-ctl ipcp-enroller-enable n.2.$i
    #rlite-ctl ipcp-enroll n.1.$i n.${i}.DIF $NM1DIF n.2.$i
    NM1DIF="n.${i}.DIF"
done
