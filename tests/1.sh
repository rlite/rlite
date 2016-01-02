#!/bin/bash

source env.sh

$RINACONF ipcp-create shim-dummy du.IPCP 1
$RINACONF ipcp-create shim-dummy du.IPCP 2
$RINACONF ipcp-create shim-dummy dudu.IPCP 5

$RINACONF assign-to-dif dummy.DIF du.IPCP 1
$RINACONF assign-to-dif dummylo.DIF du.IPCP 2

$RINACONF ipcp-destroy du.IPCP 1
$RINACONF ipcp-destroy du.IPCP 2
$RINACONF ipcp-destroy dudu.IPCP 5
