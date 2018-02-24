#!/bin/sh

# Create two normal IPCPs
rlite-ctl ipcp-create x normal xx || exit 1
rlite-ctl ipcp-create y normal yy || exit 1
# Register the one into the other
rlite-ctl ipcp-register x yy || exit 1
# Check that registration gets deferred
rlite-ctl regs-show | grep "\<name\>" | grep "\<x\>" && exit 1
# Enable the first one as an enroller
rlite-ctl ipcp-enroller-enable x || exit 1
# Check that the pending registration happened now
rlite-ctl regs-show | grep "\<name\>" | grep "\<x\>" || exit 1
