#!/bin/bash

set -x

# prepare VMPI-KVM
pushd .
cd ../vmpi
./prepare-host-kvm.sh
./prepare-guest-kvm.sh
popd

sudo insmod kernel/rina-ctrl.ko
sudo insmod kernel/rina-shim-dummy.ko
sudo insmod kernel/rina-shim-hv.ko
sudo chmod a+rwx /dev/rina-ipcm-ctrl
sudo chmod a+rwx /dev/rina-app-ctrl
sudo chmod a+rwx /dev/rina-io
