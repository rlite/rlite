#!/bin/bash

function usage {
    echo "$0 [-n NUM_CLIENTS] [-p PER_CLIENT_FLOWS] [-c PER_FLOW_PACKETS] [-t TEST_TYPE]"
}

N=100
P=1
C=1000
T=perf

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

        "-c")
        if [ -n "$2" ]; then
            C="$2"
            shift
        else
            echo "-c requires a numeric argument"
            exit 255
        fi
        ;;

        "-t")
        if [ -n "$2" ]; then
            T="$2"
            shift
        else
            echo "-t requires a test type (perf, ping, rr)"
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
    rinaperf -z rinaperf-server:$i -p $P -t $T -c $C -i 10000 &
done
