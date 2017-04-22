#!/bin/sh

USER=$(cat user)
SSHOPTS=$(cat sshopts)

MACHINE_ID=$1
if [ "$MACHINE_ID" == "" ]; then
	echo "usage: $0 NODE_NAME"
	exit 255
fi

SSH_PORT=$(grep "\<${MACHINE_ID}\>" demo.map | awk '{print $2}')
if [ "$SSH_PORT" == "" ]; then
	echo "Error: Node ${MACHINE_ID} unknown"
	exit 255
fi

echo "Accessing buildroot VM ${MACHINE_ID}"
ssh $SSHOPTS -p ${SSH_PORT} $USER@localhost
