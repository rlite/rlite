#!/bin/bash

# Create a normal IPCP and test the dif-policy-param-mod command
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1

# Expect success on the following ones
rlite-ctl dif-policy-mod dd addralloc distributed || exit 1
rlite-ctl dif-policy-param-mod dd addralloc nack-wait 4s || exit 1
rlite-ctl dif-policy-mod dd addralloc centralized-fault-tolerant || exit 1
rlite-ctl dif-policy-param-mod dd addralloc replicas a,b,c || exit 1
rlite-ctl dif-policy-param-mod dd addralloc cli-timeout 1000ms || exit 1
rlite-ctl dif-policy-param-mod dd addralloc raft-election-timeout 200ms || exit 1
rlite-ctl dif-policy-param-mod dd addralloc raft-heartbeat-timeout 10ms || exit 1
rlite-ctl dif-policy-param-mod dd addralloc raft-rtx-timeout 10s || exit 1

rlite-ctl dif-policy-mod dd dft centralized-fault-tolerant || exit 1
rlite-ctl dif-policy-param-mod dd dft replicas a,b,c || exit 1
rlite-ctl dif-policy-param-mod dd dft cli-timeout 2040ms || exit 1
rlite-ctl dif-policy-param-mod dd dft raft-election-timeout 40ms || exit 1
rlite-ctl dif-policy-param-mod dd dft raft-heartbeat-timeout 2040ms || exit 1
rlite-ctl dif-policy-param-mod dd dft raft-rtx-timeout 3s || exit 1

rlite-ctl dif-policy-param-mod dd enrollment timeout 300ms || exit 1
rlite-ctl dif-policy-param-mod dd enrollment keepalive 4s || exit 1
rlite-ctl dif-policy-param-mod dd enrollment keepalive-thresh 2 || exit 1

rlite-ctl dif-policy-param-mod dd flowalloc force-flow-control true || exit 1

rlite-ctl dif-policy-param-mod dd resalloc reliable-flows true || exit 1
rlite-ctl dif-policy-param-mod dd resalloc reliable-n-flows true || exit 1
rlite-ctl dif-policy-param-mod dd resalloc broadcast-enroller true || exit 1

rlite-ctl dif-policy-param-mod dd ribd refresh-intval 10s || exit 1

rlite-ctl dif-policy-mod dd routing link-state || exit 1
rlite-ctl dif-policy-param-mod dd routing age-incr-intval 10s || exit 1
rlite-ctl dif-policy-param-mod dd routing age-max 199s || exit 1

# Expect failure on the following ones
rlite-ctl dif-policy-param-mod dd wrong-component timeout 300ms && exit 1
rlite-ctl dif-policy-param-mod dd enrollment wrong-parameter 300 && exit 1
rlite-ctl dif-policy-param-mod dd enrollment timeout wrong-value && exit 1
rlite-ctl dif-policy-param-mod dd resalloc reliable-flows 1023 && exit 1
rlite-ctl dif-policy-param-mod dd ribd refresh-intval 7 && exit 1
rlite-ctl dif-policy-param-mod dd enrollment keepalive 10 && exit 1
exit 0
