#!/bin/bash

source tests/prologue.sh
source tests/env.sh

# it's not necessary to unregister, we can rely on
# auto-unregistration
#sudo rlite-ctl ipcp-unregister n.IPCP:1 d.DIF
sudo rlite-ctl ipcp-destroy n.IPCP:1
sudo rlite-ctl ipcp-destroy d.IPCP:1

source tests/epilogue.sh
