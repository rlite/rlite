#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rina-config ipcp-create d.IPCP 1 shim-loopback d.DIF
rina-config ipcp-create n.IPCP 1 normal n.DIF
rina-config ipcp-config n.IPCP 1 address 67
rina-config ipcp-register d.DIF n.IPCP 1

#user/rinaperf -l &
#user/rinaperf

source tests/epilogue.sh
