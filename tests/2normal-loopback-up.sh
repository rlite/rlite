#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rina-config ipcp-create d.IPCP 1 shim-loopback d.DIF
rina-config ipcp-config d.IPCP 1 queued 1
rina-config ipcp-create n.IPCP 1 normal n.DIF
rina-config ipcp-create n.IPCP 2 normal n.DIF
rina-config ipcp-config n.IPCP 1 address 21
rina-config ipcp-config n.IPCP 2 address 22
rina-config ipcp-register d.DIF n.IPCP 1
rina-config ipcp-register d.DIF n.IPCP 2
rina-config ipcp-enroll n.DIF n.IPCP 1 n.IPCP 2 d.DIF
#rina-config ipcp-dft-set n.IPCP 2 rinaperf-data server 21

#user/rinaperf -p n.IPCP -P 1 -l &
#user/rinaperf -p n.IPCP -P 2

source tests/epilogue.sh
