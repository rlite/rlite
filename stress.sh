#!/bin/bash

for i in $(seq 1 5 4092); do
    for j in $(seq 1 5); do
        thr=$(user/rinaperf -t perf -c 100000 -s $i | grep "Mbps" | awk '{printf "%s\n", $4}')
        echo "$i $thr"
    done
done
