#!/bin/bash

set -eux

A='pjd-fstest-20080816'
DATADIR=$(readlink -m "$(dirname "$0")")

pushd "$DATADIR"
if [ ! -d "$A" ]; then
    if [ ! -e "${A}.tgz" ]; then
        wget "http://tuxera.com/sw/qa/${A}.tgz"
    fi
    tar -xzf "${A}.tgz"
    echo 'fs="cpfs"' >> "${A}/tests/conf"
fi
make -C "$A"
popd

function run_tests() {
    sudo prove -rfo --count "${DATADIR}/${A}/tests/${1:-}" || true
}

ARGS=$(getopt -o d: -- "$@")
FSDIR=dir
eval set -- "$ARGS"
while true; do
    case "$1" in
        -d) FSDIR="$2"; shift 2;;
        --) shift; break;;
        *) echo "Error parsing arguments"; exit 2;;
    esac
done

pushd "$FSDIR"
if [ $# -eq 0 ]
then
    run_tests
else
    for t; do
        run_tests "$1"
    done
fi
popd

echo Note that errors in link/00.t are expected if -o attr_timeout=0 is not passed to mount
echo Some errors may occur in other filesystems if ${A}/tests/conf is not set correctly
