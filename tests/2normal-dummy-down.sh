#!/bin/bash

source tests/prologue.sh
source tests/env.sh

# it's not necessary to unregister, we can rely on
# auto-unregistration
$RINACONF ipcp-destroy n.IPCP 1
$RINACONF ipcp-destroy n.IPCP 2
$RINACONF ipcp-destroy d.IPCP 1

source tests/epilogue.sh
