#!/bin/bash

# Create two normal IPCPs
rlite-ctl ipcp-create x normal xx || exit 1
rlite-ctl ipcp-create y normal yy || exit 1
# Enable a normal IPCP as enroller and register it into the other
rlite-ctl ipcp-enroller-enable x || exit 1
rlite-ctl ipcp-register x yy || exit 1
# Check that the registration is known by the kernel
rlite-ctl regs-show | grep "\<name\>" | grep "\<x\>" || exit 1
