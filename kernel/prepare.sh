#!/bin/bash

set -x

sudo insmod rina-ctrl.ko
sudo chmod a+rwx /dev/rina-ctrl
