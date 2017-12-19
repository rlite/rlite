#!/bin/bash

# Create a normal IPCP and test the dif-policy-param-list command
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1

# List per-component parameters, checking that the number of lines is correct
rlite-ctl dif-policy-param-list dd
rlite-ctl dif-policy-param-list dd | wc -l | grep -q "\<17\>" || exit 1
rlite-ctl dif-policy-param-list dd address-allocator | wc -l | grep -q "\<1\>" || exit 1
rlite-ctl dif-policy-param-list dd dft | wc -l | grep -q "\<1\>" || exit 1
rlite-ctl dif-policy-param-list dd enrollment | wc -l | grep -q "\<3\>" || exit 1
rlite-ctl dif-policy-param-list dd flow-allocator | wc -l | grep -q "\<6\>" || exit 1
rlite-ctl dif-policy-param-list dd resource-allocator | wc -l | grep -q "\<3\>" || exit 1
rlite-ctl dif-policy-param-list dd routing | wc -l | grep -q "\<2\>" || exit 1
rlite-ctl dif-policy-param-list dd rib-daemon | wc -l | grep -q "\<1\>" || exit 1

# Run a list of set operations followed by a correspondent get, checking
# that the value got stored in the RIB.
rlite-ctl dif-policy-param-mod dd address-allocator nack-wait-secs 76 || exit 1
rlite-ctl dif-policy-param-list dd address-allocator nack-wait-secs | grep 76 || exit 1
rlite-ctl dif-policy-param-mod dd dft replicas r1,r2,r3,r4,r5 || exit 1
rlite-ctl dif-policy-param-list dd dft replicas | grep "r1,r2,r3,r4,r5" || exit 1
rlite-ctl dif-policy-param-mod dd enrollment timeout 300 || exit 1
rlite-ctl dif-policy-param-list dd enrollment timeout | grep 300 || exit 1
rlite-ctl dif-policy-param-mod dd enrollment keepalive 478 || exit 1
rlite-ctl dif-policy-param-list dd enrollment keepalive | grep 478 || exit 1
rlite-ctl dif-policy-param-mod dd enrollment keepalive-thresh 21 || exit 1
rlite-ctl dif-policy-param-list dd enrollment keepalive-thresh | grep 21 || exit 1
rlite-ctl dif-policy-param-mod dd flow-allocator force-flow-control true || exit 1
rlite-ctl dif-policy-param-list dd flow-allocator force-flow-control | grep true || exit 1
rlite-ctl dif-policy-param-mod dd flow-allocator initial-a 41 || exit 1
rlite-ctl dif-policy-param-list dd flow-allocator initial-a | grep 41 || exit 1
rlite-ctl dif-policy-param-mod dd flow-allocator initial-credit 184 || exit 1
rlite-ctl dif-policy-param-list dd flow-allocator initial-credit | grep 184 || exit 1
rlite-ctl dif-policy-param-mod dd flow-allocator initial-tr 1791 || exit 1
rlite-ctl dif-policy-param-list dd flow-allocator initial-tr | grep 1791 || exit 1
rlite-ctl dif-policy-param-mod dd flow-allocator max-cwq-len 2961 || exit 1
rlite-ctl dif-policy-param-mod dd flow-allocator max-rtxq-len 915 || exit 1
rlite-ctl dif-policy-param-list dd flow-allocator max-cwq-len | grep 2961 || exit 1
rlite-ctl dif-policy-param-list dd flow-allocator max-rtxq-len | grep 915 || exit 1
rlite-ctl dif-policy-param-mod dd resource-allocator reliable-flows true || exit 1
rlite-ctl dif-policy-param-list dd resource-allocator reliable-flows | grep true || exit 1
rlite-ctl dif-policy-param-mod dd resource-allocator reliable-n-flows true || exit 1
rlite-ctl dif-policy-param-list dd resource-allocator reliable-n-flows | grep true || exit 1
rlite-ctl dif-policy-param-mod dd resource-allocator broadcast-enroller true || exit 1
rlite-ctl dif-policy-param-list dd resource-allocator broadcast-enroller | grep true || exit 1
rlite-ctl dif-policy-param-mod dd rib-daemon refresh-intval 916 || exit 1
rlite-ctl dif-policy-param-list dd rib-daemon refresh-intval | grep 916 || exit 1
rlite-ctl dif-policy-param-mod dd routing age-incr-intval 107 || exit 1
rlite-ctl dif-policy-param-mod dd routing age-max 771 || exit 1
rlite-ctl dif-policy-param-list dd routing age-incr-intval | grep 107 || exit 1
rlite-ctl dif-policy-param-list dd routing age-max | grep 771 || exit 1

# Expect failure on the following ones
rlite-ctl dif-policy-param-list dd wrong-component timeout 300 && exit 1
rlite-ctl dif-policy-param-list dd enrollment wrong-parameter 300 && exit 1
exit 0
