#!/bin/bash

# Run multiple server instances
for i in $(seq 1 100); do
    rinaperf -l -Z $i &
done
