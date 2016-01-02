#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create shim-loopback d.IPCP 1
$RINACONF ipcp-config d.IPCP 1 queued 1
$RINACONF ipcp-config d.IPCP 1 dif d.DIF
$RINACONF ipcp-create normal n.IPCP 1
$RINACONF ipcp-create normal n.IPCP 2
$RINACONF ipcp-config n.IPCP 1 dif n.DIF
$RINACONF ipcp-config n.IPCP 2 dif n.DIF
$RINACONF ipcp-config n.IPCP 1 address 21
$RINACONF ipcp-config n.IPCP 2 address 22
$RINACONF ipcp-register d.DIF n.IPCP 1
$RINACONF ipcp-register d.DIF n.IPCP 2
$RINACONF ipcp-enroll n.DIF n.IPCP 1 n.IPCP 2 d.DIF
$RINACONF ipcp-dft-set n.IPCP 2 rinaperf-data server 21

#user/rinaperf -p n.IPCP -P 1 -l &
#user/rinaperf -p n.IPCP -P 2

source tests/epilogue.sh
