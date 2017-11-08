#!/bin/bash

################################################
# Usage to run all the tests:
#   $ tests/run-integration-tests.sh
#
# Usage to run only a specific test:
#   $ tests/run-integration-tests.sh 3
#
################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
NOC='\033[0m' # No Color

function abort_prepare() {
    echo -e "${RED}>>> FAILED TO PREPARE TEST ENVIRONMENT${NOC}"
    exit 1
}

function abort_cleanup() {
    echo -e "${RED}>>> FAILED TO CLEANUP TEST ENVIRONMENT${NOC}"
    exit 1
}

TESTSEL="0"
if [ -n "$1" ]; then
    TESTSEL="$1"
fi

modules="rlite-normal rlite-shim-loopback rlite-shim-eth rlite-shim-udp4 rlite-shim-tcp4"
# Start from a clean state
sudo pkill rlite-uipcps > /dev/null 2>&1
for m in ${modules}; do
    sudo rmmod ${m} > /dev/null 2>&1
done
sudo rmmod rlite > /dev/null 2>&1

testcnt="0"
for t in $(ls tests/integration/*); do
    testcnt=$((${testcnt} + 1))
    if [ $TESTSEL -ne "0" -a $TESTSEL -ne $testcnt ]; then
        continue
    fi
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
