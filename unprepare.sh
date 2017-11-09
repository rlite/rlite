#!/bin/bash

set -x

which systemctl > /dev/null
if [ $? == "0" ]; then
    sudo systemctl stop rlite
fi

sudo rm -rf /run/rlite

sudo rmmod rlite-shim-udp4.ko
sudo rmmod rlite-shim-tcp4.ko
sudo rmmod rlite-normal.ko
sudo rmmod rlite-shim-loopback.ko
sudo rmmod rlite-shim-eth.ko
sudo rmmod rlite
