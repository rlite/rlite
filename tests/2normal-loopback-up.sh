#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create d.IPCP 1 shim-loopback d.DIF
$RINACONF ipcp-config d.IPCP 1 queued 1
$RINACONF ipcp-create n.IPCP 1 normal n.DIF
$RINACONF ipcp-create n.IPCP 2 normal n.DIF
$RINACONF ipcp-config n.IPCP 1 address 21
$RINACONF ipcp-config n.IPCP 2 address 22
$RINACONF ipcp-register d.DIF n.IPCP 1
$RINACONF ipcp-register d.DIF n.IPCP 2
$RINACONF ipcp-enroll n.DIF n.IPCP 1 n.IPCP 2 d.DIF
$RINACONF ipcp-dft-set n.IPCP 2 rinaperf-data server 21

#user/rinaperf -p n.IPCP -P 1 -l &
#user/rinaperf -p n.IPCP -P 2

source tests/epilogue.sh
