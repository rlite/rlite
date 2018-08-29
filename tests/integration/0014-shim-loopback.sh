#!/bin/bash -e

source tests/libtest.sh

rlite-ctl ipcp-create sl shim-loopback dd
rlite-ctl ipcp-config sl queued 1
rlite-ctl ipcp-config sl flow-del-wait-ms 100
start_daemon rinaperf -lw -z rpinstance7
rinaperf -z rpinstance7 -p2 -c 4 -i 0
start_daemon rinaperf -lw -z rpinstance8
rinaperf -z rpinstance8  -c 2 -i 0
rinaperf -z rpinstance7  -c 2 -i 0
rlite-ctl ipcp-destroy sl
