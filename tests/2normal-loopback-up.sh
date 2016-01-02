#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-config ipcp-create d.IPCP 1 shim-loopback d.DIF
sudo rlite-config ipcp-config d.IPCP 1 queued 1
sudo rlite-config ipcp-create n.IPCP 1 normal n.DIF
sudo rlite-config ipcp-create n.IPCP 2 normal n.DIF
sudo rlite-config ipcp-config n.IPCP 1 address 21
sudo rlite-config ipcp-config n.IPCP 2 address 22
sudo rlite-config ipcp-register d.DIF n.IPCP 1
sudo rlite-config ipcp-register d.DIF n.IPCP 2
sudo rlite-config ipcp-enroll n.DIF n.IPCP 1 n.IPCP 2 d.DIF
#sudo rlite-config ipcp-dft-set n.IPCP 2 rinaperf-data server 21

#user/rinaperf -p n.IPCP -P 1 -l &
#user/rinaperf -p n.IPCP -P 2

source tests/epilogue.sh
