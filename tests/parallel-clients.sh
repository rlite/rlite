#!/bin/bash

# Run multiple client instances
for i in $(seq 1 100); do
    rinaperf -z rinaperf-server:$i -t perf -c 1000 -i 10000 &
done
