#!/bin/bash -e

# Create two normal IPCPs
rlite-ctl ipcp-create x normal xx
rlite-ctl ipcp-create y normal yy
# Enable a normal IPCP as enroller and register it into the other
rlite-ctl ipcp-enroller-enable x
rlite-ctl ipcp-register x yy
# Check that the registration is known by the kernel
rlite-ctl regs-show | grep "\<name\>" | grep "\<x\>"
# Try to register again and check that operation has no effect
rlite-ctl ipcp-register x yy
rlite-ctl regs-show | grep "\<name\>" | grep "\<x\>"
# Now unregister
rlite-ctl ipcp-unregister x yy
# Check that registration is gone
rlite-ctl regs-show | grep "\<name\>" | grep "\<x\>" && exit 1
# Unregister again, and check that command fails
rlite-ctl ipcp-unregister x yy && exit 1
true
