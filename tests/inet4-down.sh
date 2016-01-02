#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rina-config ipcp-destroy i.IPCP 1

source tests/epilogue.sh
