#!/bin/bash

source tests/prologue.sh
source tests/env.sh

# it's not necessary to unregister, we can rely on
# auto-unregistration

for i in $(seq 30 -1 1); do
    rlite-config ipcp-destroy n.1.IPCP $i
    rlite-config ipcp-destroy n.2.IPCP $i
done

rlite-config ipcp-destroy d.IPCP 1

source tests/epilogue.sh
