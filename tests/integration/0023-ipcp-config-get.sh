#!/bin/bash -e

rlite-ctl ipcp-create mio normal perks
# Positive tests
rlite-ctl ipcp-config mio txhdroom 120
rlite-ctl ipcp-config mio rxhdroom 35
rlite-ctl ipcp-config mio mss 1800
rlite-ctl ipcp-config mio address 71
rlite-ctl ipcp-config mio ttl 10
rlite-ctl ipcp-config-get mio txhdroom | grep "\<120\>"
rlite-ctl ipcp-config-get mio rxhdroom | grep "\<35\>"
rlite-ctl ipcp-config-get mio mss | grep "\<1800\>"
rlite-ctl ipcp-config-get mio address | grep "\<71\>"
rlite-ctl ipcp-config-get mio ttl | grep "\<10\>"
rlite-ctl ipcp-config mio csum inet
rlite-ctl ipcp-config-get mio csum | grep "\<inet\>"
rlite-ctl ipcp-config mio csum none
rlite-ctl ipcp-config-get mio csum | grep "\<none\>"
rlite-ctl ipcp-config mio flow-del-wait-ms 381
rlite-ctl ipcp-config-get mio flow-del-wait-ms | grep "\<381\>"
# Negative tests
rlite-ctl ipcp-config-get mio fakeparam && exit 1
rlite-ctl ipcp-config mio csum wrong && exit 1
true
