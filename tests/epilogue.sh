if [ "$batch" != "0" ]; then
    kill -SIGINT $(pgrep ipcm)
fi
