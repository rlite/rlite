#!/bin/bash -e

source tests/libtest.sh

# Create a normal IPCP
rlite-ctl ipcp-create pippo normal dd
rlite-ctl ipcp-config pippo flow-del-wait-ms 250

# Check that we fail on a wrong scheduler name
rlite-ctl ipcp-config pippo sched nonexistent && false

# Check that we can set the WRR scheduler and configure it
rlite-ctl ipcp-config pippo sched wrr
rlite-ctl ipcp-sched-config pippo wrr && false
rlite-ctl ipcp-sched-config pippo wrr qsize 65535 quantum 1600 && false
rlite-ctl ipcp-sched-config pippo wrr weights 2,4,10 && false
rlite-ctl ipcp-sched-config pippo wrr qsize 65535 quantum 1600 weights "" && false
rlite-ctl ipcp-sched-config pippo wrr qsize 65535 quantum xyz weights 2,4,10 && false
rlite-ctl ipcp-sched-config pippo wrr qsize 65535 quantum 1600 weights 2,4,10
rlite-ctl ipcp-sched-config pippo wrr qsize 65535 quantum 1600 weights 2,4,9,5
rlite-ctl ipcp-config-get pippo sched | grep "\<wrr\>"

# Check that we can set the PFIFO scheduler, configure and remove it
rlite-ctl ipcp-config pippo sched pfifo
rlite-ctl ipcp-config pippo sched none
rlite-ctl ipcp-sched-config pippo wrr qsize 65535 quantum 1600 weights 1 && false
rlite-ctl ipcp-config-get pippo sched | grep "\<none\>"
rlite-ctl ipcp-config pippo sched pfifo
rlite-ctl ipcp-config-get pippo sched | grep "\<pfifo\>"
rlite-ctl ipcp-sched-config pippo pfifo qsize 0 levels 3 && false
rlite-ctl ipcp-sched-config pippo pfifo qsize 65535 levels 3
rlite-ctl ipcp-sched-config pippo wrr qsize 65535 quantum 1600 weights 1 && false
start_daemon rinaperf -lw -z rpi
rinaperf -z rpi -c 6 -i 1
# Check that we cannot change the scheduler while the IPCP
# is still supporting flows
rlite-ctl ipcp-config pippo sched none && false
true
