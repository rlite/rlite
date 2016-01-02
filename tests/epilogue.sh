if [ "$batch" != "0" ]; then
    kill -SIGINT $(pgrep uipcp-server)
fi
