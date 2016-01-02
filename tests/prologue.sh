if [ -z "$batch" ]; then
    batch=0
fi

if [ "$batch" != "0" ]; then
    user/uipcp-server &
    while [ ! -e "/var/rina/uipcp-server" ] ; do
        true
    done
fi
