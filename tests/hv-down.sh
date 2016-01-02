#!/bin/bash

source tests/env.sh

if [ -z "$1" ]; then
    echo "First argument required"
    exit 1
fi

$RINACONF ipcp-destroy ${1}.IPCP 1
