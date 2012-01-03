#include "thinfs.h"
#include "types.h"
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_FDS 0x1000

typedef Thinfs Fs;
typedef ThinfsCtx Ctx;

struct Thinfs {
    void *devbuf;
    int devfd;
    Geometry *geo;
    MBR *mbr;
    int fds[MAX_FDS];
};

struct ThinfsCtx {
    Thinfs *fs;
    ThinfsErrno eno;
};

bool thinfs_mkfs(int fd)
{
    struct stat stat[1];
    if (fstat(fd, stat)) {
        perror("fstat");
        return false;
    }
    size_t pagesize = sysconf(_SC_PAGESIZE);
    MBR *mbr = mmap(NULL, pagesize, PROT_WRITE, MAP_SHARED, fd, 0);
    mbr->block_size = pagesize;
    mbr->block_count = stat->st_size / pagesize;
    munmap(mbr, pagesize);
    return true;
}

Thinfs *thinfs_mount(char const *path)
{
    Thinfs *fs = malloc(sizeof *fs);
    fs->devfd = open(path, O_RDWR|O_LARGEFILE);
    if (fs->devfd == -1) {
        perror("open");
        goto failed;
    }
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize == -1) {
        perror("sysconf");
        goto failed;
    }
    fs->devbuf = mmap(NULL, pagesize, PROT_READ|PROT_WRITE, MAP_SHARED, fs->devfd, 0);
    if (fs->devbuf == MAP_FAILED) {
        perror("mmap");
        goto failed;
    }
    MBR *mbr = fs->devbuf;
    if (MAP_FAILED == mremap(fs->devbuf, pagesize, mbr->block_count * mbr->block_size, MREMAP_MAYMOVE)) {
        perror("mremap");
        goto failed;
    }
    //~ fs->geo = (Geometry) {
    //~ };

    return fs;
failed:
    thinfs_unmount(fs);
    return NULL;
}

void thinfs_unmount(Thinfs *fs)
{
    munmap(fs->devbuf, fs->geo->block_count * fs->geo->block_size);
    close(fs->devfd);
    free(fs);
}

Ctx *thinfs_ctx_new(Fs *fs)
{
    Ctx *ctx = malloc(sizeof *ctx);
    *ctx = (Ctx) {
        .fs = fs,
        .eno = 0,
    };
    return ctx;
}

ThinfsErrno thinfs_open(ThinfsCtx *ctx, char const *path, ThinfsFd *fd)
{
    return EOPNOTSUPP;
}

ThinfsErrno thinfs_close(ThinfsCtx *ctx, ThinfsFd fd)
{
    return EOPNOTSUPP;
}

ThinfsErrno thinfs_fstat(ThinfsCtx *ctx, ThinfsFd fd, struct stat *buf)
{
    return EOPNOTSUPP;
}
