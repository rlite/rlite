#!/bin/bash

rlite-ctl ipcp-create pippo normal dd || exit 1
rlite-ctl ipcp-config pippo flow-del-wait-ms 250 || exit 1
# Check that we fail on a wrong scheduler namee
rlite-ctl ipcp-config pippo sched nonexistent && exit 1
# Check that we can set the FIFO scheduler and remove it
rlite-ctl ipcp-config pippo sched fifo || exit 1
rlite-ctl ipcp-config pippo sched none || exit 1
rlite-ctl ipcp-config-get pippo sched | grep "\<none\>" || exit 1
rlite-ctl ipcp-config pippo sched fifo || exit 1
rlite-ctl ipcp-config-get pippo sched | grep "\<fifo\>" || exit 1
rinaperf -lw -z rpi || exit 1
rinaperf -z rpi -c 6 -i 1 || exit 1
# Check that we cannot change the scheduler while the IPCP
# is still supporting flows
rlite-ctl ipcp-config pippo sched none && exit 1
pkill rinaperf
rlite-ctl reset
