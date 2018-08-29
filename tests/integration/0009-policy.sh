#!/bin/bash -e

# Create a normal IPCP and test the dif-policy-mod command
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-enroller-enable x

# Expect success on the following ones
rlite-ctl dif-policy-mod dd addralloc static
rlite-ctl dif-policy-mod dd addralloc distributed
rlite-ctl dif-policy-mod dd addralloc centralized-fault-tolerant
rlite-ctl dif-policy-mod dd dft centralized-fault-tolerant
rlite-ctl dif-policy-mod dd dft fully-replicated
rlite-ctl dif-policy-mod dd enrollment default
rlite-ctl dif-policy-mod dd flowalloc local
rlite-ctl dif-policy-mod dd resalloc default
rlite-ctl dif-policy-mod dd routing link-state
rlite-ctl dif-policy-mod dd routing link-state-lfa

# Expect failure on the following ones
rlite-ctl dif-policy-mod dd wrong-component static && exit 1
rlite-ctl dif-policy-mod dd addralloc wrong-policy && exit 1
rlite-ctl dif-policy-mod dd flowalloc wrong-policy && exit 1
exit 0
