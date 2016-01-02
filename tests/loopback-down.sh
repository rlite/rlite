#!/bin/bash

source tests/prologue.sh
source tests/env.sh

rina-config ipcp-destroy d.IPCP 1

source tests/epilogue.sh
