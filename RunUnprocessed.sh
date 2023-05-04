#!/bin/bash

function pwait() {
    while [ $(jobs -p | wc -l) -ge $1 ]; do
        sleep 1
    done
}

chmod +x RunUnprocessedSingle.sh

FILES="$DESTPATH_CONTAINERS"
rm /mnt/output/container-output/*
mkdir -p /mnt/output/container-output
mkdir -p "$DESTPATH_OUTPUT_LOG"
rm $DESTPATH_OUTPUT_LOG/*
echo "Starting"
find  $FILES -maxdepth 1 -mindepth 1 | parallel -j $CORES_EVAL "/bin/sh RunUnprocessedSingle-Start.sh"
if [ -f "failed" ]; then
    echo "Failed."
    exit 20
fi

echo "Done"
