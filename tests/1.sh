#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create shim-loopback du.IPCP 1 || exit 1
$RINACONF ipcp-create shim-loopback du.IPCP 2 || exit 1
$RINACONF ipcp-create shim-loopback dudu.IPCP 5 || exit 1

$RINACONF ipcp-config du.IPCP 1 dif loopback.DIF || exit 1
$RINACONF ipcp-config du.IPCP 2 dif loopback.DIF || exit 1

$RINACONF ipcp-destroy du.IPCP 1 || exit 1
$RINACONF ipcp-destroy du.IPCP 2 || exit 1
$RINACONF ipcp-destroy dudu.IPCP 5 || exit 1

source tests/epilogue.sh
