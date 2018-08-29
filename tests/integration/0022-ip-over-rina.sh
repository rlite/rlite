#!/bin/bash -e

source tests/libtest.sh

rlite-ctl ipcp-create xyz.IPCP normal dd.DIF
rlite-ctl ipcp-config xyz.IPCP flow-del-wait-ms 100
cat > iporinad1.conf << EOF
local       ipor1        dd.DIF
remote      ipor2        dd.DIF       192.168.203.0/30
route       10.9.10.0/24
route       10.9.11.0/24
EOF
cat > iporinad2.conf << EOF
local       ipor2        dd.DIF
remote      ipor1        dd.DIF       192.168.203.0/30
route       10.9.12.0/24
route       10.9.13.0/24
EOF
cumulative_trap "rm -f iporinad1.conf iporinad2.conf" "EXIT"

start_daemon iporinad -wv -c iporinad1.conf
start_daemon iporinad -wv -c iporinad2.conf
sleep 1
