#!/bin/bash

source tests/prologue.sh
source tests/env.sh

if [ -z "$1" ]; then
    echo "First argument required"
    exit
fi

$RINACONF ipcp-create shim-hv ${1}.IPCP 1
$RINACONF assign-to-dif d.DIF ${1}.IPCP 1

source tests/epilogue.sh
