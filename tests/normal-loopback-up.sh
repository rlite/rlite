#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-ctl ipcp-create d.IPCP 1 shim-loopback d.DIF
sudo rlite-ctl ipcp-create n.IPCP 1 normal n.DIF
sudo rlite-ctl ipcp-config n.IPCP 1 address 67
sudo rlite-ctl ipcp-register d.DIF n.IPCP 1

#user/rinaperf -l &
#user/rinaperf

source tests/epilogue.sh
