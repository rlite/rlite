#!/bin/bash

set -x

sudo rm -rf /var/rinalite

sudo rmmod rinalite-normal.ko
sudo rmmod rinalite-shim-loopback.ko
if [ HAVE_VMPI == "y" ]; then
    sudo rmmod rinalite-shim-hv.ko
fi
sudo rmmod rinalite-shim-eth.ko
sudo rmmod rinalite

if [ HAVE_VMPI == "y" ]; then
    # unprepare VMPI-KVM
    pushd .
    cd kernel/vmpi
    ./unprepare-host-kvm.sh
    ./unprepare-guest-kvm.sh
    popd
fi
