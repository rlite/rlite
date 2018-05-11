#!/bin/bash

# Create a normal IPCP
rlite-ctl ipcp-create pippo normal dd || exit 1
rlite-ctl ipcp-config pippo flow-del-wait-ms 250 || exit 1

# Check that we fail on a wrong scheduler name
rlite-ctl ipcp-config pippo sched nonexistent && exit 1

# Check that we can set the WRR scheduler and configure it
rlite-ctl ipcp-config pippo sched wrr || exit 1
rlite-ctl ipcp-sched-config pippo wrr quantum 1600 && exit 1
rlite-ctl ipcp-sched-config pippo wrr weights 2,4,10 && exit 1
rlite-ctl ipcp-sched-config pippo wrr quantum 1600 weights "" && exit 1
rlite-ctl ipcp-sched-config pippo wrr quantum xyz weights 2,4,10 && exit 1
rlite-ctl ipcp-sched-config pippo wrr quantum 1600 weights 2,4,10 || exit 1
rlite-ctl ipcp-config-get pippo sched | grep "\<wrr\>" || exit 1

# Check that we can set the FIFO scheduler and remove it
rlite-ctl ipcp-config pippo sched fifo || exit 1
rlite-ctl ipcp-config pippo sched none || exit 1
rlite-ctl ipcp-sched-config pippo wrr quantum 1600 weights 1 && exit 1
rlite-ctl ipcp-config-get pippo sched | grep "\<none\>" || exit 1
rlite-ctl ipcp-config pippo sched fifo || exit 1
rlite-ctl ipcp-config-get pippo sched | grep "\<fifo\>" || exit 1
rlite-ctl ipcp-sched-config pippo wrr quantum 1600 weights 1 && exit 1
rinaperf -lw -z rpi || exit 1
rinaperf -z rpi -c 6 -i 1 || exit 1
# Check that we cannot change the scheduler while the IPCP
# is still supporting flows
rlite-ctl ipcp-config pippo sched none && exit 1
pkill rinaperf
rlite-ctl reset
