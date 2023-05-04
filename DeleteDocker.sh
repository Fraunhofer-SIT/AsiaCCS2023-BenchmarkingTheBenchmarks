#!/bin/bash
echo Docker ps before
docker ps
docker ps --no-trunc --format '{{.Names}} {{.Image}}' | grep "eval-" | awk '{ print $1 }' | xargs -t docker kill || echo Nothing was running
docker images --no-trunc --format '{{.ID}} {{.Repository}}' | grep "eval-" | awk '{ print $1 }' | xargs -t docker rmi -f || echo Nothing has to be removed
echo Docker after before
docker ps