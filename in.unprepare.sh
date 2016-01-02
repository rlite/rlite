#!/bin/bash

set -x

which systemctl > /dev/null
if [ $? == "0" ]; then
    sudo systemctl stop rlite
fi

sudo rm -rf /var/rlite

sudo rmmod rlite-shim-inet4.ko
sudo rmmod rlite-normal.ko
sudo rmmod rlite-shim-loopback.ko
if [ HAVE_VMPI == "y" ]; then
    sudo rmmod rlite-shim-hv.ko
fi
sudo rmmod rlite-shim-eth.ko
sudo rmmod rlite

if [ HAVE_VMPI == "y" ]; then
    # unprepare VMPI-KVM
    pushd .
    cd kernel/vmpi
    ./unprepare-host-kvm.sh
    ./unprepare-guest-kvm.sh
    popd
fi
