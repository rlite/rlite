#!/bin/sh

cleanup() {
	pkill rinaperf
	return 0
}

abort() {
	cleanup
	exit 1
}

rlite-ctl ipcp-create sl shim-loopback dd || abort
rlite-ctl ipcp-config sl queued 1 || abort
rinaperf -lw -z rpinstance7 || abort
rinaperf -z rpinstance7 -p2 -c 4 -i 0 || abort
rinaperf -lw -z rpinstance8 || abort
rinaperf -z rpinstance8  -c 2 -i 0 || abort
rinaperf -z rpinstance7  -c 2 -i 0 || abort
rlite-ctl ipcp-destroy sl || abort
cleanup
