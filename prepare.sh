#!/bin/bash

set -x

sudo insmod kernel/rina-ctrl.ko
sudo insmod kernel/rina-shim-dummy.ko
sudo chmod a+rwx /dev/rina-ipcm-ctrl
sudo chmod a+rwx /dev/rina-app-ctrl
