#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create shim-loopback d.IPCP 1
$RINACONF ipcp-config d.IPCP 1 queued 1
$RINACONF ipcp-config d.IPCP 1 dif d.DIF

source tests/epilogue.sh
