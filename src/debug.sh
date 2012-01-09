#!/bin/bash
set -ux
gdb --args ./mount.thinfs -d -s "$DEV" "$DIR" "$@"
sleep 1
fusermount -u "$DIR"
