if [ "$batch" != "0" ]; then
    kill -SIGINT $(pgrep rlite-uipcps)
fi
