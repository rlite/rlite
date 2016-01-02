#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create d.IPCP 1 shim-loopback d.DIF
$RINACONF ipcp-create n.IPCP 1 normal n.DIF
$RINACONF ipcp-config n.IPCP 1 address 67
$RINACONF ipcp-register d.DIF n.IPCP 1

#user/rinaperf -l &
#user/rinaperf

source tests/epilogue.sh
