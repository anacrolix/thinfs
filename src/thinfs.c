#include "thinfs.h"
#include "types.h"
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_FDS 0x1000
#define THINFS_IFDIR S_IFDIR

typedef Thinfs Fs;
typedef ThinfsCtx Ctx;
typedef ThinfsFd Fd;
typedef off_t Off;

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

static void set_ctx_errno(Ctx *ctx, int eno)
{
    ctx->eno = eno;
}

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

ThinfsErrno thinfs_ctx_commit(Ctx *ctx)
{
    return ctx->eno;
}

Fd thinfs_open(Ctx *ctx, char const *path)
{
    return -1;
}

ThinfsErrno thinfs_close(Ctx *ctx, Fd fd)
{
    return EOPNOTSUPP;
}

ThinfsErrno thinfs_fstat(Ctx *ctx, ThinfsFd fd, struct stat *buf)
{
    return EOPNOTSUPP;
}

static Off data_read_recurse(Ctx *ctx,

static Off data_read(Ctx *ctx, Data *data, void *buf, size_t count, Off off)
{
}

static Off dir_read(Ctx *ctx, Inode *inode, Off off, Dentry *de)
{
    ssize_t got = data_read(ctx, data, sizeof *de, *off);
    switch (got) {
        case -1: return -1;
        case 0: return 0;
        default: return off + got;
    }
}

static bool inode_is_dir(Inode *inode)
{
    return inode->type == THINFS_IFDIR;
}

static void *get_block(Ctx *ctx, Blkno blkno)
{
    return ctx->fs->devbuf + blkno * ctx->fs->geo->block_size;
}

static Inode *get_inode(Ctx *ctx, Ino ino)
{
    Inode *inode = get_block(ctx, ino);
    if (inode->ino != ino) {
        set_ctx_errno(ctx, EIO);
        return NULL;
    }
    return inode;
}

static Ino find_entry(Ctx *ctx, Ino ino, char const *name, size_t size)
{
    Inode *inode = get_inode(ctx, ino);
    if (!inode) return -1;
    Off off = 0;
    while (true) {
        Entry de[1];
        off = dir_read(ctx, inode, off, de);
        if (off == -1) return -1;
        if (off == 0) {
            ctx_set_errno(ENOENT);
            return -1;
        }
        if (!ino_valid(ctx, de->ino) || !*de->name) {
            ctx_set_errno(EIO);
            return -1;
        }
        if (strnlen(de->name, NAME_MAX) != size)
            continue;
        if (!memcmp(de->name, name, size))
            return de->ino;
    }
}

static Ino root_ino(Ctx *ctx)
{
    return ctx->fs->geo->data_start;
}

typedef struct {
    char const *name;
    size_t size;
} PathIter;

static PathIter path_iter_next(PathIter pi)
{
    pi.name += size;
    pi.size = 0;
    switch (*pi.name) {
        case '/':
        pi.name += 1;
        pi.size = strchrnul(pi.name, '/') - pi.name;
        break;
        case '\0':
        pi.name = NULL;
        break;
    }
    return pi;
}

static PathIter iter_path(char const *path)
{
    return (PathIter) {
        .name = *path == '/' ? path : NULL;
        .size = 0;
    }
}

static Ino path_to_ino(Ctx *ctx, char const *path)
{
    PathIter pi = iter_path(path);
    if (!pi.name) {
        set_ctx_errno(EINVAL);
        return -1;
    }
    Ino ino = root_ino();
    while (true) {
        pi = path_iter_next(pi);
        if (!pi.name) break;
        ino = find_entry(ctx, ino, pi.name, pi.size);
        if (ino == -1) return -1;
    }
    return ino;
}

ssize_t thinfs_readlink(Ctx *ctx, char const *path, char *buf, size_t bufsize)
{

}
