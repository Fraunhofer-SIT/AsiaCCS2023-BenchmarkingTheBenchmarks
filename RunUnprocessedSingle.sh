#!/bin/bash

DOCKERTAG_BASE=$(basename "$1")
DOCKERTAG=eval-$(echo -n "$DOCKERTAG_BASE"  | tr '[:upper:]' '[:lower:]' | cut -c -115)
#DOCKERTAG=eval-$(cat /proc/sys/kernel/random/uuid)
echo Building docker "$DOCKERTAG"
docker build -t $DOCKERTAG "$1" || { echo "Could not create $DOCKERTAG"; exit 2000; }
# Run the docker image
echo Run docker "$DOCKERTAG"
# -v "$DESTPATH_UNPROCESSED:/mnt/output"
timeout -s KILL 600 docker run --rm --log-driver=none -a stdin -a stdout -a stderr --cap-add NET_ADMIN "$DOCKERTAG" || { docker ps --no-trunc --format '{{.Names}} {{.Image}}' | grep "$DOCKERTAG" | awk '{ print $1 }' | xargs -t docker kill; docker rmi -f "$DOCKERTAG"; exit 2000; }  
#cat "$DESTPATH_OUTPUT_LOG/$DOCKERTAG_BASE" | grep "[EXPLOIT]"
echo Remove dockertag "$DOCKERTAG"
docker rmi -f "$DOCKERTAG"
echo Done "$DOCKERTAG"
