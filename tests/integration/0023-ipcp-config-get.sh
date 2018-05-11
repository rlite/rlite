#!/bin/sh

rlite-ctl ipcp-create mio normal perks || exit 1
# Positive tests
rlite-ctl ipcp-config mio txhdroom 120 || exit 1
rlite-ctl ipcp-config mio rxhdroom 35 || exit 1
rlite-ctl ipcp-config mio mss 1800 || exit 1
rlite-ctl ipcp-config-get mio txhdroom | grep "\<120\>" || exit 1
rlite-ctl ipcp-config-get mio rxhdroom | grep "\<35\>" || exit 1
rlite-ctl ipcp-config-get mio mss | grep "\<1800\>" || exit 1
# Negative tests
rlite-ctl ipcp-config-get mio fakeparam && exit 1
# Reset to wait for all the flows to go away
rlite-ctl reset
