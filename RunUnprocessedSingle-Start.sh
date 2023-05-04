#!/bin/bash
echo "Running in parallel: $@" 
DOCKERTAG_BASE=$(basename "$@")

/bin/sh RunUnprocessedSingle.sh "$@" > "$DESTPATH_OUTPUT_LOG/$DOCKERTAG_BASE" 2> "$DESTPATH_OUTPUT_LOG/$DOCKERTAG_BASE" || touch failed
