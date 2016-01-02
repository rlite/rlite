#!/bin/bash

set -x

sudo rm -rf /var/rlite

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
