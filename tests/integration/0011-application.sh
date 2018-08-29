#!/bin/bash -e

source tests/libtest.sh

# Create an IPCP and register three applications
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-config x flow-del-wait-ms 100
start_daemon rinaperf -lw -z rpinstance1
start_daemon rinaperf -lw -z rpinstance2
start_daemon rinaperf -lw -z rpinstance3
# Run some clients towards the instances, with various QoS
rinaperf -z rpinstance1 -p 2 -c 6 -i 1
rinaperf -z rpinstance3 -p 3 -c 3 -i 0 -g 0
# Also test flows-show and ipcp-stats
rlite-ctl flows-show
rlite-ctl ipcp-stats x
# Run some clients towards non-existing instances
rinaperf -z fake1 -c 1 && exit 1
rinaperf -z fake2 -p 2 -c 1 && exit 1
true
