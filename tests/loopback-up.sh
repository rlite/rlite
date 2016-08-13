#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-ctl ipcp-create d.IPCP/1// shim-loopback d.DIF
sudo rlite-ctl ipcp-config d.IPCP/1// queued 1

source tests/epilogue.sh
