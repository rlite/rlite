#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-unregister n.DIF n.IPCP 1
$RINACONF ipcp-destroy n.IPCP 1
$RINACONF ipcp-destroy d.IPCP 1

source tests/epilogue.sh
