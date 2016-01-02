#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-create shim-eth e.IPCP 1
$RINACONF ipcp-config e.IPCP 1 netdev eth0
$RINACONF ipcp-config e.IPCP 1 dif e.DIF

source tests/epilogue.sh
