#!/bin/sh

# Expect that no IPCPs are in the system
count=$(rlite-ctl | grep dif_type | grep dif_name | wc -l)
if [ $count != "0" ]; then
    exit 1
fi
