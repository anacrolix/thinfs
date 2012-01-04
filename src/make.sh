set -eu

CFLAGS='-Werror-implicit-function-declaration -Wall -g -std=gnu1x -fplan9-extensions'

rm -f mount.thinfs

gcc \
    -o mount.thinfs \
    `pkg-config fuse --cflags` \
    -I../include -D_GNU_SOURCE -DFUSE_USE_VERSION=28  \
    $CFLAGS \
    mount.thinfs.c thinfs_fuse.c thinfs.c \
    `pkg-config fuse --libs`

rm -f mkfs.thinfs

gcc \
    -o mkfs.thinfs \
    -I../include -D_GNU_SOURCE \
    $CFLAGS \
    mkfs.thinfs.c thinfs.c -lrt
