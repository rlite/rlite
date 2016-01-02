#!/bin/bash

set -x

sudo brctl addbr rbr0
sudo ip link set rbr0 up
sudo ip addr add 10.11.12.1/24 dev rbr0

sudo ip tuntap add mode tap name r.1
sudo ip tuntap add mode tap name r.2

sudo ip link set r.1 up
sudo ip link set r.2 up

sudo brctl addif rbr0 r.1
sudo brctl addif rbr0 r.2

qemu-system-x86_64 "/home/vmaffione/git/vm/arch.qcow2"          \
    -snapshot                                                   \
    --enable-kvm                                                \
    -smp 2                                                      \
    -m 1G                                                       \
    -device e1000,mac=00:0a:0a:0a:0a:99,netdev=mgmt             \
    -netdev user,id=mgmt,hostfwd=tcp::2222-:22                  \
    -device virtio-net-pci,mac=00:0a:0a:0a:0a:01,netdev=data    \
    -netdev tap,ifname=r.1,id=data,script=no,downscript=no      \
    -vga std                                                    \
    -pidfile rina-1.pid                                         \
    -display none &


qemu-system-x86_64 "/home/vmaffione/git/vm/arch.qcow2"          \
    -snapshot                                                   \
    --enable-kvm                                                \
    -smp 2                                                      \
    -m 1G                                                       \
    -device e1000,mac=00:0b:0b:0b:0b:99,netdev=mgmt             \
    -netdev user,id=mgmt,hostfwd=tcp::2223-:22                  \
    -device virtio-net-pci,mac=00:0b:0b:0b:0b:01,netdev=data    \
    -netdev tap,ifname=r.2,id=data,script=no,downscript=no      \
    -vga std                                                    \
    -pidfile rina-2.pid                                         \
    -display none &
