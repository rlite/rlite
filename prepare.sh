#!/bin/bash

set -x

# prepare VMPI-KVM
pushd .
cd kernel/vmpi
./prepare-host-kvm.sh
./prepare-guest-kvm.sh
popd

sudo insmod kernel/rinalite.ko
sudo insmod kernel/rina-shim-loopback.ko
sudo insmod kernel/rina-shim-hv.ko
sudo insmod kernel/rina-shim-eth.ko
sudo insmod kernel/rina-normal.ko
sudo chmod a+rwx /dev/rinalite
sudo chmod a+rwx /dev/rina-io

sudo mkdir -p /var/rinalite
sudo chmod -R a+rwx /var/rinalite
