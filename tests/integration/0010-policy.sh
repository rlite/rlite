#!/bin/bash

# Create a normal IPCP and test the dif-policy-mod command
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1

# Expect success on the following ones
rlite-ctl dif-policy-mod dd address-allocator manual || exit 1
rlite-ctl dif-policy-mod dd address-allocator distributed || exit 1
rlite-ctl dif-policy-mod dd dft centralized-fault-tolerant || exit 1
rlite-ctl dif-policy-mod dd dft fully-replicated || exit 1
rlite-ctl dif-policy-mod dd enrollment default || exit 1
rlite-ctl dif-policy-mod dd flow-allocator local || exit 1
rlite-ctl dif-policy-mod dd resource-allocator default || exit 1
rlite-ctl dif-policy-mod dd routing link-state || exit 1
rlite-ctl dif-policy-mod dd routing link-state-lfa || exit 1

# Expect failure on the following ones
rlite-ctl dif-policy-mod dd wrong-component manual && exit 1
rlite-ctl dif-policy-mod dd address-allocator wrong-policy && exit 1
rlite-ctl dif-policy-mod dd flow-allocator wrong-policy && exit 1
exit 0
