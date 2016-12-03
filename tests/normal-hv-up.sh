#!/bin/bash

source tests/prologue.sh
source tests/env.sh

if [ "$1" != "g" -a "$1" != "h" ]; then
    echo "First argument required ('h' or 'g')"
    exit
fi

# Try to extract the last vmpi-id from the kernel log
vmpi_id=$(dmesg | grep -o "Provider \(HOST\|GUEST\):[0-9]\+" | tail -n1 | grep -o "[0-9]\+$")
if [ -z ${vmpi_id} ]; then
    echo "No registered provider"
fi

if [ "$1" == "h" ]; then
    SHIPCP="h.IPCP"
    NORMIPCP="nh.IPCP"
    ADDR=21
else
    SHIPCP="g.IPCP"
    NORMIPCP="ng.IPCP"
    ADDR=22
fi

sudo rlite-ctl ipcp-create $SHIPCP:1 shim-hv d.DIF
sudo rlite-ctl ipcp-config $SHIPCP:1 vmpi-id ${vmpi_id}
sudo rlite-ctl ipcp-create $NORMIPCP:1 normal n.DIF
sudo rlite-ctl ipcp-config $NORMIPCP:1 address $ADDR
sudo rlite-ctl ipcp-register d.DIF $NORMIPCP:1
if [ "$1" == "h" ]; then
    # Host enroll to the guest --> guest up script must be run first
    sudo rlite-ctl ipcp-enroll n.DIF $NORMIPCP:1 ng.IPCP:1 d.DIF
fi

source tests/epilogue.sh
