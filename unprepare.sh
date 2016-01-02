#!/bin/bash

set -x

sudo rmmod rina-shim-dummy.ko
sudo rmmod rina-shim-hv.ko
sudo rmmod rina-ctrl
