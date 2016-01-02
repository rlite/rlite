#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rina-config ipcp-create i.IPCP 1 shim-inet4 i.DIF

source tests/epilogue.sh
