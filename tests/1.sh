#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-ctl ipcp-create du.IPCP:1 shim-loopback loopback.DIF || exit 1
sudo rlite-ctl ipcp-create du.IPCP:2 shim-loopback loopback.DIF || exit 1
sudo rlite-ctl ipcp-create dudu.IPCP:5 shim-loopback loopback.DIF || exit 1

sudo rlite-ctl ipcp-destroy du.IPCP:1 || exit 1
sudo rlite-ctl ipcp-destroy du.IPCP:2 || exit 1
sudo rlite-ctl ipcp-destroy dudu.IPCP:5 || exit 1

source tests/epilogue.sh
