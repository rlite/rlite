#!/bin/bash

set -x

sudo insmod kernel/rlite.ko
sudo insmod kernel/rlite-shim-loopback.ko
sudo insmod kernel/rlite-shim-eth.ko
sudo insmod kernel/rlite-normal.ko
sudo insmod kernel/rlite-shim-tcp4.ko
sudo insmod kernel/rlite-shim-udp4.ko

if [ WITH_VMPI == "y" ]; then
    # prepare VMPI-KVM
    pushd .
    cd kernel/vmpi
    ./prepare-host-kvm.sh
    ./prepare-guest-kvm.sh
    popd
fi

if [ WITH_VMPI == "y" ]; then
    sudo insmod kernel/rlite-shim-hv.ko
fi

sudo chmod a+rwx /dev/rlite
sudo chmod a+rwx /dev/rlite-io

sudo mkdir -p /run/rlite
sudo chmod -R a+rwx /run/rlite

which systemctl > /dev/null
if [ $? == "0" ]; then
    sudo systemctl start rlite
fi
