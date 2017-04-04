#!/bin/bash

function usage {
    echo "$0 [ -n NUM_SERVERS ]"
}

N=100

# Option parsing
while [[ $# > 0 ]]
do
    key="$1"
    case $key in
        "-n")
        if [ -n "$2" ]; then
            N="$2"
            shift
        else
            echo "-n requires a numeric argument"
            exit 255
        fi
        ;;

        "-h")
            usage
            exit 0
        ;;

        *)
        echo "Unknown option '$key'"
        exit 255
        ;;
    esac
    shift
done

# Run multiple server instances
pkill rinaperf
for i in $(seq 1 $N); do
    rinaperf -l -z rinaperf-server:$i &
done
