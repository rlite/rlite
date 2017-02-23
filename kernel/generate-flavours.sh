#!/bin/bash

# $1 is the flavours.conf file

# Read the file line by line
while read -r line || [[ -n "$line" ]]; do
    # Parse the line to get space separated items
    read -ra ITEMS <<< "$line"

    CCMACROS=""

    # Scan the items
    for asstr in "${ITEMS[@]}"; do
        # For each item, try to parse it in the form "field=size"
        IFS='=' read -ra ASSIGN <<< "$asstr"
        if [ ${#ASSIGN[@]} == "2" ]; then
            # It is in the form "field=size"
            FIELD=${ASSIGN[0]}
            SIZE=${ASSIGN[1]}

            # make sure size makes sense
            case $SIZE in
                "1"|"2"|"4"|"8")
                    # ok
                    BITSIZE=$((SIZE * 8))
                    ;;
                *)
                    echo "Invalid field size <$SIZE>"
                    continue
                    ;;
            esac
            case ${FIELD} in
                "addr"|"seq"|"pdulen"|"cepid"|"qosid")
                    CCMACROS=$CCMACROS"-Drl_${FIELD}_t=uint${BITSIZE}_t "
                    ;;
                *)
                    echo "Unknown EFCP field <$FIELD>"
                    continue
                    ;;
            esac
        fi
    done
    echo "$CCMACROS"
done < "$1"
