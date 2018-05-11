#!/bin/sh

# Create a normal IPCP and test the dif-policy-param-list command
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1

# List per-component parameters, checking that the number of lines is correct
rlite-ctl dif-policy-param-list dd
rlite-ctl dif-policy-param-list dd enrollment | wc -l | grep -q "\<4\>" || exit 1
rlite-ctl dif-policy-param-list dd flowalloc | wc -l | grep -q "\<6\>" || exit 1
rlite-ctl dif-policy-param-list dd resalloc | wc -l | grep -q "\<3\>" || exit 1
rlite-ctl dif-policy-param-list dd routing | wc -l | grep -q "\<2\>" || exit 1
rlite-ctl dif-policy-param-list dd ribd | wc -l | grep -q "\<1\>" || exit 1

# Run a list of set operations followed by a correspondent get, checking
# that the value got stored in the RIB.
rlite-ctl dif-policy-mod dd addralloc distributed || exit 1
rlite-ctl dif-policy-param-mod dd addralloc nack-wait 2s || exit 1
rlite-ctl dif-policy-param-list dd addralloc nack-wait | grep "\<2000ms\>" || exit 1
rlite-ctl dif-policy-mod dd addralloc centralized-fault-tolerant || exit 1
rlite-ctl dif-policy-param-mod dd addralloc replicas a1,b2,c3,d,e || exit 1
rlite-ctl dif-policy-param-list dd addralloc replicas | grep "a1,b2,c3,d,e" || exit 1

rlite-ctl dif-policy-mod dd dft centralized-fault-tolerant || exit 1
rlite-ctl dif-policy-param-mod dd dft replicas r1,r2,r3,r4,r5 || exit 1
rlite-ctl dif-policy-param-list dd dft replicas | grep "r1,r2,r3,r4,r5" || exit 1

rlite-ctl dif-policy-param-mod dd enrollment timeout 3000ms || exit 1
rlite-ctl dif-policy-param-list dd enrollment timeout | grep 3000ms || exit 1
rlite-ctl dif-policy-param-mod dd enrollment keepalive 478s || exit 1
rlite-ctl dif-policy-param-list dd enrollment keepalive | grep 478000ms || exit 1
rlite-ctl dif-policy-param-mod dd enrollment keepalive-thresh 21 || exit 1
rlite-ctl dif-policy-param-list dd enrollment keepalive-thresh | grep 21 || exit 1
rlite-ctl dif-policy-param-mod dd enrollment auto-reconnect false || exit 1
rlite-ctl dif-policy-param-list dd enrollment auto-reconnect | grep false || exit 1

rlite-ctl dif-policy-param-mod dd flowalloc force-flow-control true || exit 1
rlite-ctl dif-policy-param-list dd flowalloc force-flow-control | grep true || exit 1
rlite-ctl dif-policy-param-mod dd flowalloc initial-a 41ms || exit 1
rlite-ctl dif-policy-param-list dd flowalloc initial-a | grep 41ms || exit 1
rlite-ctl dif-policy-param-mod dd flowalloc initial-credit 184 || exit 1
rlite-ctl dif-policy-param-list dd flowalloc initial-credit | grep 184 || exit 1
rlite-ctl dif-policy-param-mod dd flowalloc initial-rtx-timeout 1791ms || exit 1
rlite-ctl dif-policy-param-list dd flowalloc initial-rtx-timeout | grep 1791ms || exit 1
rlite-ctl dif-policy-param-mod dd flowalloc max-cwq-len 2961 || exit 1
rlite-ctl dif-policy-param-mod dd flowalloc max-rtxq-len 915 || exit 1
rlite-ctl dif-policy-param-list dd flowalloc max-cwq-len | grep 2961 || exit 1
rlite-ctl dif-policy-param-list dd flowalloc max-rtxq-len | grep 915 || exit 1

rlite-ctl dif-policy-param-mod dd resalloc reliable-flows true || exit 1
rlite-ctl dif-policy-param-list dd resalloc reliable-flows | grep true || exit 1
rlite-ctl dif-policy-param-mod dd resalloc reliable-n-flows true || exit 1
rlite-ctl dif-policy-param-list dd resalloc reliable-n-flows | grep true || exit 1
rlite-ctl dif-policy-param-mod dd resalloc broadcast-enroller true || exit 1
rlite-ctl dif-policy-param-list dd resalloc broadcast-enroller | grep true || exit 1

rlite-ctl dif-policy-param-mod dd ribd refresh-intval 916s || exit 1
rlite-ctl dif-policy-param-list dd ribd refresh-intval | grep 916000ms || exit 1

rlite-ctl dif-policy-mod dd routing link-state || exit 1
rlite-ctl dif-policy-param-mod dd routing age-incr-intval 107s || exit 1
rlite-ctl dif-policy-param-mod dd routing age-max 771s || exit 1
rlite-ctl dif-policy-param-list dd routing age-incr-intval | grep 107000ms || exit 1
rlite-ctl dif-policy-param-list dd routing age-max | grep 771000ms || exit 1

# Expect failure on the following ones
rlite-ctl dif-policy-param-list dd wrong-component timeout 4004ms && exit 1
rlite-ctl dif-policy-param-list dd enrollment wrong-parameter 4003 && exit 1
exit 0
