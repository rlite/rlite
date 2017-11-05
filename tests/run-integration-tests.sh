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

for t in $(ls tests/integration/*); do
    echo -e "${ORANGE}>>> Running integration test ${CYAN}\"${t}\"${NOC}"
    # Prepare test environment
    sudo modprobe rlite || abort_prepare
    sudo modprobe rlite-normal || abort_prepare
    sudo modprobe rlite-shim-loopback || abort_prepare
    sudo rlite-uipcps -d || abort_prepare
    sudo ${t}
    retcode="$?"
    sudo kill $(cat /run/rlite/uipcps.pid) || abort_cleanup
    sudo rmmod rlite-normal || abort_cleanup
    sudo rmmod rlite-shim-loopback || abort_cleanup
    sudo rmmod rlite || abort_cleanup
    if [ "$retcode" != "0" ]; then
        echo -e "${RED}>>> TEST FAILED${NOC}"
        exit 1
    fi
    echo -e "${GREEN}>>> TEST PASSED${NOC}"
done
