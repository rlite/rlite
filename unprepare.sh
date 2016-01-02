#!/bin/bash

set -x

sudo rm -rf /var/rinalite

sudo rmmod rinalite-normal.ko
sudo rmmod rinalite-shim-loopback.ko
sudo rmmod rinalite-shim-hv.ko
sudo rmmod rinalite-shim-eth.ko
sudo rmmod rinalite

# unprepare VMPI-KVM
pushd .
cd kernel/vmpi
./unprepare-host-kvm.sh
./unprepare-guest-kvm.sh
popd
