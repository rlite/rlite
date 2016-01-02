#!/bin/bash

set -x

kill_qemu() {
    PIDFILE=$1
    PID=$(cat $PIDFILE)
    if [ -n $PID ]; then
        kill $PID
        while [ -n "$(ps -p $PID -o comm=)" ]; do
            sleep 1
        done
    fi

    rm $PIDFILE
}

kill_qemu rina-1.pid
kill_qemu rina-2.pid

sudo brctl delif rbr0 r.1
sudo brctl delif rbr0 r.2

sudo ip link set r.1 down
sudo ip link set r.2 down

sudo ip tuntap del mode tap name r.1
sudo ip tuntap del mode tap name r.2

sudo ip addr del 10.11.12.1/24 dev rbr0
sudo ip link set rbr0 down
sudo brctl delbr rbr0


