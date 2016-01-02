#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-config ipcp-create i.IPCP 1 shim-inet4 i.DIF
sudo rlite-config ipcp-create i.IPCP 2 shim-inet4 i.DIF

source tests/epilogue.sh
