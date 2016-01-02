#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create shim-dummy d.IPCP 1
$RINACONF assign-to-dif d.DIF d.IPCP 1
$RINACONF ipcp-create normal n.IPCP 1
$RINACONF assign-to-dif n.DIF n.IPCP 1
$RINACONF ipcp-config n.IPCP 1 address 67
$RINACONF ipcp-register d.DIF n.IPCP 1

#user/rinaperf -l &
#user/rinaperf

source tests/epilogue.sh
