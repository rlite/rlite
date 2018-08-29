#!/bin/bash -e

# Create a normal IPCP and test the dif-policy-param-list command
rlite-ctl ipcp-create x normal dd
rlite-ctl ipcp-enroller-enable x

rlite-ctl dif-policy-list dd
# Set and get per-component policies, checking for consistent results
rlite-ctl dif-policy-list dd addralloc | grep -q "\<distributed\>"
rlite-ctl dif-policy-mod dd addralloc static
rlite-ctl dif-policy-list dd addralloc | grep -q "\<static\>"
rlite-ctl dif-policy-mod dd addralloc centralized-fault-tolerant
rlite-ctl dif-policy-list dd addralloc | grep -q "\<centralized-fault-tolerant\>"

rlite-ctl dif-policy-list dd dft | grep -q "\<fully-replicated\>"
rlite-ctl dif-policy-mod dd dft centralized-fault-tolerant
rlite-ctl dif-policy-list dd dft | grep -q "\<centralized-fault-tolerant\>"

rlite-ctl dif-policy-list dd enrollment | grep -q "\<default\>"
rlite-ctl dif-policy-list dd flowalloc | grep -q "\<local\>"
rlite-ctl dif-policy-list dd resalloc | grep -q "\<default\>"

rlite-ctl dif-policy-list dd routing | grep -q "\<link-state\>"
rlite-ctl dif-policy-mod dd routing link-state-lfa
rlite-ctl dif-policy-list dd routing | grep -q "\<link-state-lfa\>"
rlite-ctl dif-policy-mod dd routing static
rlite-ctl dif-policy-list dd routing | grep -q "\<static\>"

# Expect failure on the following ones
rlite-ctl dif-policy-list dd wrong-component && exit 1
rlite-ctl dif-policy-list dd ribd && exit 1
true
