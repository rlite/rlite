#!/bin/bash

source tests/prologue.sh
source tests/env.sh

if [ -z "$1" ]; then
    echo "First argument required"
    exit
fi

# Try to extract the last vmpi-id from the kernel log
vmpi_id=$(dmesg | grep -o "Provider [01]:[0-9]\+" | tail -n1 | grep -o "[0-9]\+$")
if [ -z ${vmpi_id} ]; then
    echo "No registered provider"
fi

$RINACONF ipcp-create shim-hv ${1}.IPCP 1
$RINACONF ipcp-config ${1}.IPCP 1 dif d.DIF
$RINACONF ipcp-config ${1}.IPCP 1 vmpi-id ${vmpi_id}

source tests/epilogue.sh
