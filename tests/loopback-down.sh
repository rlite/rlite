#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-ctl ipcp-destroy d.IPCP 1

source tests/epilogue.sh
