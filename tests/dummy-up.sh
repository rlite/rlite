#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create shim-dummy d.IPCP 1
$RINACONF ipcp-config d.IPCP 1 queued 1
$RINACONF assign-to-dif d.DIF d.IPCP 1

source tests/epilogue.sh
