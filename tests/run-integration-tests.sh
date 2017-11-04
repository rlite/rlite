#!/bin/bash

function abort_prepare() {
    echo ">>> FAILED TO PREPARE TEST ENVIRONMENT"
    exit 1
}

function abort_cleanup() {
    echo ">>> FAILED TO CLEANUP TEST ENVIRONMENT"
    exit 1
}

for t in $(ls tests/integration/*); do
    echo ">>> Running integration test \"${t}\""
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
        echo ">>> FAILED"
        exit 1
    fi
    echo ">>> OK"
done
