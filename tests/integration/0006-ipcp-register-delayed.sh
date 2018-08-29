#!/bin/bash -e

# Create two normal IPCPs
rlite-ctl ipcp-create x normal xx
rlite-ctl ipcp-create y normal yy
# Register the one into the other
rlite-ctl ipcp-register x yy
# Check that registration gets deferred
rlite-ctl regs-show | grep "\<name\>" | grep "\<x\>" && exit 1
# Enable the first one as an enroller
rlite-ctl ipcp-enroller-enable x
# Check that the pending registration happened now
rlite-ctl regs-show | grep "\<name\>" | grep "\<x\>"
