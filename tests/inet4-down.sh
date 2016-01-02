#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rina-config ipcp-destroy i.IPCP 1
rina-config ipcp-destroy i.IPCP 2

source tests/epilogue.sh
