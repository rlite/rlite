#!/bin/bash

set -x

which systemctl > /dev/null
if [ $? == "0" ]; then
    sudo systemctl stop rlite
fi

sudo rm -rf /var/rlite

if [ HAVE_VMPI == "y" ]; then
    sudo rmmod rlite-shim-hv.ko
fi

if [ HAVE_VMPI == "y" ]; then
    # unprepare VMPI-KVM
    pushd .
    cd kernel/vmpi
    ./unprepare-host-kvm.sh
    ./unprepare-guest-kvm.sh
    popd
fi

sudo rmmod rlite-shim-tcp4.ko
sudo rmmod rlite-normal.ko
sudo rmmod rlite-shim-loopback.ko
sudo rmmod rlite-shim-eth.ko
sudo rmmod rlite
