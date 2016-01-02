#!/bin/bash

source tests/prologue.sh
source tests/env.sh

sudo rlite-config ipcp-destroy i.IPCP 1
sudo rlite-config ipcp-destroy i.IPCP 2

source tests/epilogue.sh
