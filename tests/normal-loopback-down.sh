#!/bin/bash

source tests/prologue.sh
source tests/env.sh

# it's not necessary to unregister, we can rely on
# auto-unregistration
#rlite-config ipcp-unregister d.DIF n.IPCP 1
rlite-config ipcp-destroy n.IPCP 1
rlite-config ipcp-destroy d.IPCP 1

source tests/epilogue.sh
