#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rlite-config ipcp-create du.IPCP 1 shim-loopback loopback.DIF || exit 1
rlite-config ipcp-create du.IPCP 2 shim-loopback loopback.DIF || exit 1
rlite-config ipcp-create dudu.IPCP 5 shim-loopback loopback.DIF || exit 1

rlite-config ipcp-destroy du.IPCP 1 || exit 1
rlite-config ipcp-destroy du.IPCP 2 || exit 1
rlite-config ipcp-destroy dudu.IPCP 5 || exit 1

source tests/epilogue.sh
