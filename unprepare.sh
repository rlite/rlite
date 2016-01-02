#!/bin/bash

set -x

sudo rm -rf /var/rina

sudo rmmod rina-normal.ko
sudo rmmod rina-shim-loopback.ko
sudo rmmod rina-shim-hv.ko
sudo rmmod rina-ctrl

# unprepare VMPI-KVM
pushd .
cd kernel/vmpi
./unprepare-host-kvm.sh
./unprepare-guest-kvm.sh
popd
