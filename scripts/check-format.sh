#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
NOC='\033[0m' # No Color

diffsize=$(git diff | wc -l)
if [ "$diffsize" != "0" ]; then
    echo -e "${RED}>>> Cannot check format: working tree is not clean${NOC}"
    exit 1
fi

make format
diffsize=$(git diff | wc -l)
if [ "$diffsize" != "0" ]; then
    echo -e "${RED}>>> Code not formatted: run 'make format' ${NOC}"
    exit 1
fi

echo -e "${GREEN}>>> Code is correctly formatted${NOC}"
