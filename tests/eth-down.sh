#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rlite-config ipcp-destroy e.IPCP 1

source tests/epilogue.sh
