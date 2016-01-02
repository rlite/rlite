#!/bin/bash

source tests/prologue.sh
source tests/env.sh

# it's not necessary to unregister, we can rely on
# auto-unregistration
#sudo rlite-config ipcp-unregister d.DIF n.IPCP 1
sudo rlite-config ipcp-destroy n.IPCP 1
sudo rlite-config ipcp-destroy d.IPCP 1

source tests/epilogue.sh
