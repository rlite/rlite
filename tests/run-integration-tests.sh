#!/bin/bash

function abort_prepare() {
    echo "${RED}>>> FAILED TO PREPARE TEST ENVIRONMENT${NOC}"
    exit 1
}

function abort_cleanup() {
    echo "${RED}>>> FAILED TO CLEANUP TEST ENVIRONMENT${NOC}"
    exit 1
}

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
NOC='\033[0m' # No Color

modules="rlite-normal rlite-shim-loopback rlite-shim-eth rlite-shim-udp4 rlite-shim-tcp4"
# Start from a clean state
sudo pkill rlite-uipcps > /dev/null 2>&1
for m in ${modules}; do
    sudo rmmod ${m} > /dev/null 2>&1
done
sudo rmmod rlite

for t in $(ls tests/integration/*); do
    echo -e "${ORANGE}>>> Running integration test ${CYAN}\"${t}\"${NOC}"
    # Prepare test environment
    for m in ${modules}; do
        sudo modprobe ${m} || abort_prepare
    done
    sudo rlite-uipcps -d || abort_prepare
    sudo ${t}
    retcode="$?"
    sudo kill $(cat /run/rlite/uipcps.pid) || abort_cleanup
    for m in ${modules}; do
        sudo rmmod ${m} || abort_cleanup
    done
    sudo rmmod rlite || abort_cleanup
    if [ "$retcode" != "0" ]; then
        echo -e "${RED}>>> TEST FAILED${NOC}"
        exit 1
    fi
    echo -e "${GREEN}>>> TEST PASSED${NOC}"
done
