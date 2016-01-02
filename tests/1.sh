#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rina-config ipcp-create du.IPCP 1 shim-loopback loopback.DIF || exit 1
rina-config ipcp-create du.IPCP 2 shim-loopback loopback.DIF || exit 1
rina-config ipcp-create dudu.IPCP 5 shim-loopback loopback.DIF || exit 1

rina-config ipcp-destroy du.IPCP 1 || exit 1
rina-config ipcp-destroy du.IPCP 2 || exit 1
rina-config ipcp-destroy dudu.IPCP 5 || exit 1

source tests/epilogue.sh
