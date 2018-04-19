#!/bin/sh

rlite-ctl ipcp-create xyz.IPCP normal dd.DIF || exit 1
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

iporinad -w -c iporinad1.conf || exit 1
iporinad -w -c iporinad2.conf || exit 1
sleep 2
pkill iporinad || exit 1

# Reset to wait for all the flows to go away
rlite-ctl reset
