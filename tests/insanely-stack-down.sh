#!/bin/bash

source tests/prologue.sh
source tests/env.sh

# it's not necessary to unregister, we can rely on
# auto-unregistration

for i in $(seq 3 -1 1); do
    rina-config ipcp-destroy n.1.IPCP $i
    rina-config ipcp-destroy n.2.IPCP $i
done

rina-config ipcp-destroy d.IPCP 1

source tests/epilogue.sh
