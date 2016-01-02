#!/bin/bash

set -x

qemu-system-x86_64 "/home/vmaffione/git/vm/arch.qcow2"          \
    --enable-kvm                                                \
    -smp 2                                                      \
    -m 1G                                                       \
    -device e1000,mac=00:0a:0a:0a:0a:99,netdev=mgmt             \
    -netdev user,id=mgmt,hostfwd=tcp::2222-:22                  \
    -vga std  &
