#!/bin/bash

if [ -z "$1" ]; then
    echo "First argument required"
    exit 1
fi

sudo rlite-ctl ipcp-destroy ${1}.IPCP:1
