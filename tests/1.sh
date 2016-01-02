#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create du.IPCP 1 shim-loopback loopback.DIF || exit 1
$RINACONF ipcp-create du.IPCP 2 shim-loopback loopback.DIF || exit 1
$RINACONF ipcp-create dudu.IPCP 5 shim-loopback loopback.DIF || exit 1

$RINACONF ipcp-destroy du.IPCP 1 || exit 1
$RINACONF ipcp-destroy du.IPCP 2 || exit 1
$RINACONF ipcp-destroy dudu.IPCP 5 || exit 1

source tests/epilogue.sh
