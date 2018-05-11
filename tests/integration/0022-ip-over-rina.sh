#!/bin/sh

cleanup() {
    local ret=0
    pkill iporinad || ret=1
    rm -f iporinad1.conf iporinad2.conf
    rlite-ctl reset || ret=1
    [ "$ret" != 0 ] && return 1 || return 0
}

abort() {
  cleanup
  exit 1
}

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

iporinad -wv -c iporinad1.conf || abort
iporinad -wv -c iporinad2.conf || abort
sleep 2
cleanup
