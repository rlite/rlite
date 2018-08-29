#!/bin/bash -e

# Create a normal IPCP and test the dif-policy-param-list command
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-enroller-enable x

# List per-component parameters, checking that the number of lines is correct
rlite-ctl dif-policy-param-list dd
rlite-ctl dif-policy-param-list dd enrollment | wc -l | grep -q "\<4\>"
rlite-ctl dif-policy-param-list dd flowalloc | wc -l | grep -q "\<6\>"
rlite-ctl dif-policy-param-list dd resalloc | wc -l | grep -q "\<3\>"
rlite-ctl dif-policy-param-list dd routing | wc -l | grep -q "\<2\>"
rlite-ctl dif-policy-param-list dd ribd | wc -l | grep -q "\<1\>"

# Run a list of set operations followed by a correspondent get, checking
# that the value got stored in the RIB.
rlite-ctl dif-policy-mod dd addralloc distributed
rlite-ctl dif-policy-param-mod dd addralloc nack-wait 2s
rlite-ctl dif-policy-param-list dd addralloc nack-wait | grep "\<2000ms\>"
rlite-ctl dif-policy-mod dd addralloc centralized-fault-tolerant
rlite-ctl dif-policy-param-mod dd addralloc replicas a1,b2,c3,d,e
rlite-ctl dif-policy-param-list dd addralloc replicas | grep "a1,b2,c3,d,e"
rlite-ctl dif-policy-param-mod dd addralloc cli-timeout 1234ms
rlite-ctl dif-policy-param-list dd addralloc cli-timeout | grep "\<1234ms\>"
rlite-ctl dif-policy-param-mod dd addralloc raft-election-timeout 123ms
rlite-ctl dif-policy-param-list dd addralloc raft-election-timeout | grep "\<123ms\>"
rlite-ctl dif-policy-param-mod dd addralloc raft-heartbeat-timeout 321ms
rlite-ctl dif-policy-param-list dd addralloc raft-heartbeat-timeout | grep "\<321ms\>"
rlite-ctl dif-policy-param-mod dd addralloc raft-rtx-timeout 456ms
rlite-ctl dif-policy-param-list dd addralloc raft-rtx-timeout | grep "\<456ms\>"

rlite-ctl dif-policy-mod dd dft centralized-fault-tolerant
rlite-ctl dif-policy-param-mod dd dft replicas r1,r2,r3,r4,r5
rlite-ctl dif-policy-param-list dd dft replicas | grep "r1,r2,r3,r4,r5"
rlite-ctl dif-policy-param-mod dd dft cli-timeout 4321ms
rlite-ctl dif-policy-param-list dd dft cli-timeout | grep "\<4321ms\>"
rlite-ctl dif-policy-param-mod dd dft raft-election-timeout 123ms
rlite-ctl dif-policy-param-list dd dft raft-election-timeout | grep "\<123ms\>"
rlite-ctl dif-policy-param-mod dd dft raft-heartbeat-timeout 321ms
rlite-ctl dif-policy-param-list dd dft raft-heartbeat-timeout | grep "\<321ms\>"
rlite-ctl dif-policy-param-mod dd dft raft-rtx-timeout 426ms
rlite-ctl dif-policy-param-list dd dft raft-rtx-timeout | grep "\<426ms\>"

rlite-ctl dif-policy-param-mod dd enrollment timeout 3000ms
rlite-ctl dif-policy-param-list dd enrollment timeout | grep 3000ms
rlite-ctl dif-policy-param-mod dd enrollment keepalive 478s
rlite-ctl dif-policy-param-list dd enrollment keepalive | grep 478000ms
rlite-ctl dif-policy-param-mod dd enrollment keepalive-thresh 21
rlite-ctl dif-policy-param-list dd enrollment keepalive-thresh | grep 21
rlite-ctl dif-policy-param-mod dd enrollment auto-reconnect false
rlite-ctl dif-policy-param-list dd enrollment auto-reconnect | grep false

rlite-ctl dif-policy-param-mod dd flowalloc force-flow-control true
rlite-ctl dif-policy-param-list dd flowalloc force-flow-control | grep true
rlite-ctl dif-policy-param-mod dd flowalloc initial-a 41ms
rlite-ctl dif-policy-param-list dd flowalloc initial-a | grep 41ms
rlite-ctl dif-policy-param-mod dd flowalloc initial-credit 184
rlite-ctl dif-policy-param-list dd flowalloc initial-credit | grep 184
rlite-ctl dif-policy-param-mod dd flowalloc initial-rtx-timeout 1791ms
rlite-ctl dif-policy-param-list dd flowalloc initial-rtx-timeout | grep 1791ms
rlite-ctl dif-policy-param-mod dd flowalloc max-cwq-len 2961
rlite-ctl dif-policy-param-mod dd flowalloc max-rtxq-len 915
rlite-ctl dif-policy-param-list dd flowalloc max-cwq-len | grep 2961
rlite-ctl dif-policy-param-list dd flowalloc max-rtxq-len | grep 915

rlite-ctl dif-policy-param-mod dd resalloc reliable-flows true
rlite-ctl dif-policy-param-list dd resalloc reliable-flows | grep true
rlite-ctl dif-policy-param-mod dd resalloc reliable-n-flows true
rlite-ctl dif-policy-param-list dd resalloc reliable-n-flows | grep true
rlite-ctl dif-policy-param-mod dd resalloc broadcast-enroller true
rlite-ctl dif-policy-param-list dd resalloc broadcast-enroller | grep true

rlite-ctl dif-policy-param-mod dd ribd refresh-intval 916s
rlite-ctl dif-policy-param-list dd ribd refresh-intval | grep 916000ms

rlite-ctl dif-policy-mod dd routing link-state
rlite-ctl dif-policy-param-mod dd routing age-incr-intval 107s
rlite-ctl dif-policy-param-mod dd routing age-max 771s
rlite-ctl dif-policy-param-list dd routing age-incr-intval | grep 107000ms
rlite-ctl dif-policy-param-list dd routing age-max | grep 771000ms

# Expect failure on the following ones
rlite-ctl dif-policy-param-list dd wrong-component timeout 4004ms && exit 1
rlite-ctl dif-policy-param-list dd enrollment wrong-parameter 4003 && exit 1
true
