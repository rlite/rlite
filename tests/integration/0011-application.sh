#!/bin/bash

# Create an IPCP and register three applications
rlite-ctl ipcp-create x normal dd || exit 1
rinaperf -lw -z rpinstance1 || exit 1
rinaperf -lw -z rpinstance2 || exit 1
rinaperf -lw -z rpinstance3 || exit 1
# Run some clients towards the instances, with various QoS
rinaperf -z rpinstance1 -p 2 -c 6 -i 1 || exit 1
rinaperf -z rpinstance3 -p 3 -c 3 -i 0 -g 0 || exit 1
# Run some clients towards non-existing instances
rinaperf -z fake1 -c 1 && exit 1
rinaperf -z fake2 -p 2 -c 1 && exit 1
pkill rinaperf
rlite-ctl reset
