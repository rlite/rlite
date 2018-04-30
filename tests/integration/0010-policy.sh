#!/bin/sh

# Create a normal IPCP and test the dif-policy-mod command
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1

# Expect success on the following ones
rlite-ctl dif-policy-mod dd addralloc static || exit 1
rlite-ctl dif-policy-mod dd addralloc distributed || exit 1
rlite-ctl dif-policy-mod dd dft centralized-fault-tolerant || exit 1
rlite-ctl dif-policy-mod dd dft fully-replicated || exit 1
rlite-ctl dif-policy-mod dd enrollment default || exit 1
rlite-ctl dif-policy-mod dd flowalloc local || exit 1
rlite-ctl dif-policy-mod dd resalloc default || exit 1
rlite-ctl dif-policy-mod dd routing link-state || exit 1
rlite-ctl dif-policy-mod dd routing link-state-lfa || exit 1

# Expect failure on the following ones
rlite-ctl dif-policy-mod dd wrong-component static && exit 1
rlite-ctl dif-policy-mod dd addralloc wrong-policy && exit 1
rlite-ctl dif-policy-mod dd flowalloc wrong-policy && exit 1
exit 0
