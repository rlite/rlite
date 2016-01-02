#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create d.IPCP 1 shim-loopback d.DIF
$RINACONF ipcp-config d.IPCP 1 queued 1

source tests/epilogue.sh
