set -eu

CFLAGS='-Werror-implicit-function-declaration -Wall -g -std=gnu1x -fplan9-extensions'

rm -f thinfs.o
rm -f mount.thinfs
rm -f mkfs.thinfs

gcc -c thinfs.c `pkg-config --cflags glib-2.0` -I../include -D_GNU_SOURCE $CFLAGS

gcc \
    -o mount.thinfs \
    `pkg-config fuse --cflags` \
    -I../include -D_GNU_SOURCE -DFUSE_USE_VERSION=28  \
    $CFLAGS \
    mount.thinfs.c thinfs_fuse.c thinfs.o \
    `pkg-config --libs fuse glib-2.0`

rm -f mkfs.thinfs

gcc \
    -o mkfs.thinfs \
    -I../include -D_GNU_SOURCE \
    $CFLAGS \
    mkfs.thinfs.c thinfs.o \
    -lrt `pkg-config --libs glib-2.0`

