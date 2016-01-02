#!/bin/bash

source tests/prologue.sh
source tests/env.sh

$RINACONF ipcp-destroy e.IPCP 1

source tests/epilogue.sh
