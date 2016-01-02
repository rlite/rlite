#!/bin/bash

set -x

sudo insmod kernel/rina-ctrl.ko
sudo chmod a+rwx /dev/rina-ctrl
