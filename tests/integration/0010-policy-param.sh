#!/bin/bash -e

# Create a normal IPCP and test the dif-policy-param-mod command
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-enroller-enable x

# Expect success on the following ones
rlite-ctl dif-policy-mod dd addralloc distributed
rlite-ctl dif-policy-param-mod dd addralloc nack-wait 4s
rlite-ctl dif-policy-mod dd addralloc centralized-fault-tolerant
rlite-ctl dif-policy-param-mod dd addralloc replicas a,b,c
rlite-ctl dif-policy-param-mod dd addralloc cli-timeout 1000ms
rlite-ctl dif-policy-param-mod dd addralloc raft-election-timeout 200ms
rlite-ctl dif-policy-param-mod dd addralloc raft-heartbeat-timeout 10ms
rlite-ctl dif-policy-param-mod dd addralloc raft-rtx-timeout 10s

rlite-ctl dif-policy-mod dd dft centralized-fault-tolerant
rlite-ctl dif-policy-param-mod dd dft replicas a,b,c
rlite-ctl dif-policy-param-mod dd dft cli-timeout 2040ms
rlite-ctl dif-policy-param-mod dd dft raft-election-timeout 40ms
rlite-ctl dif-policy-param-mod dd dft raft-heartbeat-timeout 2040ms
rlite-ctl dif-policy-param-mod dd dft raft-rtx-timeout 3s

rlite-ctl dif-policy-param-mod dd enrollment timeout 300ms
rlite-ctl dif-policy-param-mod dd enrollment keepalive 4s
rlite-ctl dif-policy-param-mod dd enrollment keepalive-thresh 2

rlite-ctl dif-policy-param-mod dd flowalloc force-flow-control true

rlite-ctl dif-policy-param-mod dd resalloc reliable-flows true
rlite-ctl dif-policy-param-mod dd resalloc reliable-n-flows true
rlite-ctl dif-policy-param-mod dd resalloc broadcast-enroller true

rlite-ctl dif-policy-param-mod dd ribd refresh-intval 10s

rlite-ctl dif-policy-mod dd routing link-state
rlite-ctl dif-policy-param-mod dd routing age-incr-intval 10s
rlite-ctl dif-policy-param-mod dd routing age-max 199s

# Expect failure on the following ones
rlite-ctl dif-policy-param-mod dd wrong-component timeout 300ms && exit 1
rlite-ctl dif-policy-param-mod dd enrollment wrong-parameter 300 && exit 1
rlite-ctl dif-policy-param-mod dd enrollment timeout wrong-value && exit 1
rlite-ctl dif-policy-param-mod dd resalloc reliable-flows 1023 && exit 1
rlite-ctl dif-policy-param-mod dd ribd refresh-intval 7 && exit 1
rlite-ctl dif-policy-param-mod dd enrollment keepalive 10 && exit 1
exit 0
