#!/bin/bash

set -x

sudo rmmod rina-normal.ko
sudo rmmod rina-shim-dummy.ko
sudo rmmod rina-shim-hv.ko
sudo rmmod rina-ctrl

# unprepare VMPI-KVM
pushd .
cd ../vmpi
./unprepare-host-kvm.sh
./unprepare-guest-kvm.sh
popd
