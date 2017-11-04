#!/bin/bash

for t in $(ls tests/integration/*); do
    echo ">>> Running integration test \"${t}\""
    sudo rlite-uipcps -d
    sudo ${t}
    retcode="$?"
    sudo kill $(cat /run/rlite/uipcps.pid)
    if [ "$retcode" != "0" ]; then
        echo ">>> FAILED"
        exit 1
    fi
    echo ">>> OK"
done
