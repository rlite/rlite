#!/bin/bash

function usage {
    echo "$0 [ -n NUM_CLIENTS ] [ -p PER_CLIENT_FLOWS ]"
}

N=100
P=1

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

        "-p")
        if [ -n "$2" ]; then
            P="$2"
            shift
        else
            echo "-p requires a numeric argument"
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

# Run multiple client instances
for i in $(seq 1 $N); do
    rinaperf -z rinaperf-server:$i -p $P -t perf -c 1000 -i 10000 &
done
