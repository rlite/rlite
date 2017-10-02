if [ -z "$batch" ]; then
    batch=0
fi

if [ "$batch" != "0" ]; then
    rlite-uipcps &
    while [ ! -e "/var/rina/uipcps-server" ] ; do
        true
    done
fi
