#!/bin/sh

# Create a normal IPCP and test the dif-policy-param-list command
rlite-ctl ipcp-create x normal dd || exit 1
rlite-ctl ipcp-enroller-enable x || exit 1

rlite-ctl dif-policy-list dd || exit 1
# Set and get per-component policies, checking for consistent results
rlite-ctl dif-policy-list dd address-allocator | grep -q "\<distributed\>" || exit 1
rlite-ctl dif-policy-mod dd address-allocator manual || exit 1
rlite-ctl dif-policy-list dd address-allocator | grep -q "\<manual\>" || exit 1
rlite-ctl dif-policy-list dd enrollment | grep -q "\<default\>"|| exit 1
rlite-ctl dif-policy-list dd flow-allocator | grep -q "\<local\>"|| exit 1
rlite-ctl dif-policy-list dd resource-allocator | grep -q "\<default\>" || exit 1
rlite-ctl dif-policy-list dd routing | grep -q "\<link-state\>" || exit 1
rlite-ctl dif-policy-mod dd routing link-state-lfa || exit 1
rlite-ctl dif-policy-list dd routing | grep -q "\<link-state-lfa\>" || exit 1

# Expect failure on the following ones
rlite-ctl dif-policy-list dd wrong-component && exit 1
rlite-ctl dif-policy-list dd rib-daemon && exit 1
exit 0
