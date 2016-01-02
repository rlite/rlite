#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create shim-dummy d.IPCP 1
$RINACONF assign-to-dif d.DIF d.IPCP 1
$RINACONF ipcp-create normal n.IPCP 1
$RINACONF ipcp-create normal n.IPCP 2
$RINACONF assign-to-dif n.DIF n.IPCP 1
$RINACONF assign-to-dif n.DIF n.IPCP 2
$RINACONF ipcp-config n.IPCP 1 address 21
$RINACONF ipcp-config n.IPCP 2 address 22
$RINACONF ipcp-register d.DIF n.IPCP 1
$RINACONF ipcp-register d.DIF n.IPCP 2
$RINACONF ipcp-enroll n.DIF n.IPCP 1 n.IPCP 2 d.DIF

source tests/epilogue.sh
