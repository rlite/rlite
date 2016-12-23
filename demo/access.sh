#!/bin/sh

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
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=buildroot/buildroot_rsa -p ${SSH_PORT} root@localhost
