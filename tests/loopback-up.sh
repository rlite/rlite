#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rlite-config ipcp-create d.IPCP 1 shim-loopback d.DIF
rlite-config ipcp-config d.IPCP 1 queued 1

source tests/epilogue.sh
