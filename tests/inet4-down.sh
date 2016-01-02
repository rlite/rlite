#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rlite-config ipcp-destroy i.IPCP 1
rlite-config ipcp-destroy i.IPCP 2

source tests/epilogue.sh
