#!/bin/bash

rlite-ctl ipcp-create mio normal perks || exit 1
# Positive tests
rlite-ctl ipcp-config mio txhdroom 120 || exit 1
rlite-ctl ipcp-config mio rxhdroom 35 || exit 1
rlite-ctl ipcp-config mio mss 1800 || exit 1
rlite-ctl ipcp-config mio address 71 || exit 1
rlite-ctl ipcp-config mio ttl 10 || exit 1
rlite-ctl ipcp-config-get mio txhdroom | grep "\<120\>" || exit 1
rlite-ctl ipcp-config-get mio rxhdroom | grep "\<35\>" || exit 1
rlite-ctl ipcp-config-get mio mss | grep "\<1800\>" || exit 1
rlite-ctl ipcp-config-get mio address | grep "\<71\>" || exit 1
rlite-ctl ipcp-config-get mio ttl | grep "\<10\>" || exit 1
rlite-ctl ipcp-config mio csum inet || exit 1
rlite-ctl ipcp-config-get mio csum | grep "\<inet\>" || exit 1
rlite-ctl ipcp-config mio csum none || exit 1
rlite-ctl ipcp-config-get mio csum | grep "\<none\>" || exit 1
rlite-ctl ipcp-config mio flow-del-wait-ms 381 || exit 1
rlite-ctl ipcp-config-get mio flow-del-wait-ms | grep "\<381\>" || exit 1
# Negative tests
rlite-ctl ipcp-config-get mio fakeparam && exit 1
rlite-ctl ipcp-config mio csum wrong && exit 1
# Reset to wait for all the flows to go away
rlite-ctl reset
