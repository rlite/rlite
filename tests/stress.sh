#!/bin/bash

for i in $(seq 2 5 4092); do
    for j in $(seq 1 5); do
        thr=$(rinaperf -t perf -c 100000 -f -s $i)
        echo "$i $thr"
    done
done
