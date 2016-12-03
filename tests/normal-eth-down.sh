#!/bin/bash

source tests/prologue.sh
source tests/env.sh

ID=1
if [ -n "$1" ]; then
    ID=$1
fi

sudo rlite-ctl ipcp-destroy n.IPCP:${ID}
sudo rlite-ctl ipcp-destroy e.IPCP:1

source tests/epilogue.sh
