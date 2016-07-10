#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-ctl ipcp-create i.IPCP 1 shim-tcp4 i.DIF
sudo rlite-ctl ipcp-create i.IPCP 2 shim-tcp4 i.DIF

source tests/epilogue.sh
