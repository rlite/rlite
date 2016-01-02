#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create shim-loopback d.IPCP 1
$RINACONF ipcp-config d.IPCP 1 dif d.DIF
$RINACONF ipcp-create normal n.IPCP 1
$RINACONF ipcp-config n.IPCP 1 dif n.DIF
$RINACONF ipcp-config n.IPCP 1 address 67
$RINACONF ipcp-register d.DIF n.IPCP 1

#user/rinaperf -l &
#user/rinaperf

source tests/epilogue.sh
