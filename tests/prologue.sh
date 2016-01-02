if [ -z "$batch" ]; then
    batch=0
fi

if [ "$batch" != "0" ]; then
    user/ipcm &
    while [ ! -e "/tmp/rina-ipcm" ] ; do
        true
    done
fi
