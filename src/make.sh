set -e

CC="${CC:-gcc}"
CFLAGS="-Werror-implicit-function-declaration -Wall -std=c99 -D_GNU_SOURCE $CFLAGS"

rm -f thinfs.o mount.thinfs mkfs.thinfs

"$CC" -c thinfs.c -I../include $CFLAGS

"$CC" \
    -o mount.thinfs \
    `pkg-config --cflags fuse` \
    -I../include -DFUSE_USE_VERSION=28 \
    $CFLAGS \
    mount.thinfs.c thinfs_fuse.c thinfs.o \
    `pkg-config --libs fuse`

"$CC" \
    -o mkfs.thinfs \
    -I../include \
    $CFLAGS \
    mkfs.thinfs.c thinfs.o \
    -lrt

