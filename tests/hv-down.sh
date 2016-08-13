#!/bin/bash

source tests/prologue.sh
source tests/env.sh

if [ -z "$1" ]; then
    echo "First argument required"
    exit 1
fi

sudo rlite-ctl ipcp-destroy ${1}.IPCP/1//

source tests/epilogue.sh
