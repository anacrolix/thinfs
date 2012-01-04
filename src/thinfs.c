#include "thinfs.h"
#include "types.h"
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_FDS 0x1000
#define THINFS_IFDIR S_IFDIR

#define MAX(a,b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a > _b ? _a : _b; })

#define MIN(a,b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a < _b ? _a : _b; })

typedef Thinfs Fs;
typedef ThinfsFd Fd;
typedef off_t Off;
typedef ThinfsErrno Errno;

struct Thinfs {
    void *devbuf;
    Geometry geo[1];
    int devfd;
    int fds[MAX_FDS];
};

typedef struct {
    Thinfs *fs;
    ThinfsErrno eno;
} Ctx;

static void set_ctx_errno(Ctx *ctx, int eno)
{
    ctx->eno = eno;
}

static void const *get_block(Ctx *ctx, Blkno blkno)
{
    if (!(0 <= blkno && blkno < ctx->fs->geo->block_count)) {
        set_ctx_errno(ctx, EIO);
        return NULL;
    }
    return ctx->fs->devbuf + blkno * ctx->fs->geo->block_size;
}

Geometry geometry_from_mbr(MBR const *mbr)
{
    Geometry geo = {
        .bitmap_start = 1,
        .block_size = mbr->block_size,
        .bitmap_density = mbr->block_size * CHAR_BIT,
        .block_count = mbr->block_count,
        .page_size = sysconf(_SC_PAGESIZE),
    };
    Blkno full_bitmaps = (geo.block_count - geo.bitmap_start) / (geo.bitmap_density + 1);
    geo.bitmap_blocks = full_bitmaps;
    geo.data_blocks = full_bitmaps * geo.bitmap_density;
    Blkno spare_blocks = geo.block_count - geo.bitmap_start - geo.bitmap_blocks - geo.data_blocks;
    if (spare_blocks) {
        geo.bitmap_blocks++;
        geo.data_blocks += spare_blocks - 1;
    }
    geo.data_start = geo.bitmap_start + geo.bitmap_blocks;
    return geo;
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
    MBR *mbr = mmap(NULL, pagesize, PROT_READ|PROT_WRITE, MAP_SHARED, fs->devfd, 0);
    *fs->geo = geometry_from_mbr(mbr);
    munmap(mbr, pagesize);
    fs->devbuf = mmap(NULL, fs->geo->block_size * fs->geo->block_count, PROT_READ|PROT_WRITE, MAP_SHARED, fs->devfd, 0);
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

static Inode const *inode_get(Ctx *ctx, Ino ino)
{
    Inode const *inode = get_block(ctx, ino);
    if (!inode) return NULL;
    if (inode->ino != ino) {
        fprintf(stderr, "inode %" PRIINO " is corrupted\n", ino);
        set_ctx_errno(ctx, EIO);
        return NULL;
    }
    return inode;
}

Ctx ctx_open(Fs *fs)
{
    return (Ctx) {
        .fs = fs,
    };
}

Errno ctx_close(Ctx *ctx)
{
    return ctx->eno;
}

static blkcnt_t data_blocks(Ctx *ctx, Data const *data)
{
    blkcnt_t recurse(Blkno blkno, Depth depth) {
        if (blkno == -1)
            return 0;
        if (depth == 0)
            return 1;
        Blkno const *indirect = get_block(ctx, blkno);
        blkcnt_t blocks = 1;
        for (int i = 0; i < ctx->fs->geo->bitmap_density; ++i)
            blocks += recurse(indirect[i], depth - 1);
        return blocks;
    }
    if (data->root == -1)
        return 0;
    if (data->depth == 1)
        return 1;
    return recurse(data->root, data->depth - 1);
}

static blkcnt_t inode_blocks(Ctx *ctx, Inode const *inode)
{
    return data_blocks(ctx, inode->file_data);
}

struct timespec timespec_from_thinfs_time(Time time)
{
    return (struct timespec) {
        .tv_sec = time.secs,
        .tv_nsec = time.nanos,
    };
}

static Time time_from_timespec(struct timespec ts)
{
    return (Time) {
        .secs = ts.tv_sec,
        .nanos = ts.tv_nsec,
    };
}

static uint64_t depth_capacity(Ctx *ctx, Depth depth)
{
    uint64_t cap = ctx->fs->geo->block_size;
    while (--depth > 0) cap *= ctx->fs->geo->bitmap_density;
    return cap;
}

static bool read_block(Ctx *ctx, Blkno blkno, void *buf, size_t count, Off off)
{
    void const *block = get_block(ctx, blkno);
    memcpy(buf, block + off, count);
    return true;
}

static bool data_read_recurse(Ctx *ctx, Blkno blkno, Depth depth, void *buf, size_t count, Off off)
{
    if (blkno == -1) {
        memset(buf, 0, count);
        return true;
    }
    if (depth == 0) {
        return read_block(ctx, blkno, buf, count, off);
    }
    Blkno const *indirect = get_block(ctx, blkno);
    uint64_t childcap = depth_capacity(ctx, depth);
    indirect += off / childcap;
    off %= childcap;
    while (count != 0) {
        size_t subcount = MIN(count, childcap - off);
        if (!data_read_recurse(ctx, *indirect, depth-1, buf, subcount, off))
            return false;
        count -= subcount;
        off = 0;
    }
    return true;
}

// return number of bytes read, or -1 on error
static ssize_t data_read(Ctx *ctx, Data const *data, void *buf, size_t count, Off off)
{
    count = MIN(count, MAX(data->size - off, 0));
    uint64_t tree_cap = depth_capacity(ctx, data->depth);
    uint64_t tree_count = MIN(count, MAX(tree_cap - off, 0));
    if (!data_read_recurse(ctx, data->root, data->depth, buf, tree_count, off))
        return -1;
    if (count > tree_count)
        memset(buf + tree_count, 0, count - tree_count);
    return count;
}

static bool inode_is_dir(Inode const *inode)
{
    return inode->type == THINFS_IFDIR;
}

static ssize_t inode_read(Ctx *ctx, Inode const *inode, void *buf, size_t count, Off off)
{
    return data_read(ctx, inode->file_data, buf, count, off);
}

static Off dir_read(Ctx *ctx, Inode const *inode, Off off, Entry *de)
{
    if (!inode_is_dir(inode)) {
        set_ctx_errno(ctx, ENOTDIR);
        return -1;
    }
    ssize_t got = data_read(ctx, inode->file_data, de, sizeof *de, off);
    switch (got) {
        case -1: return -1;
        case 0: return 0;
        default: return off + got;
    }
}

static Ino root_ino(Ctx *ctx)
{
    return ctx->fs->geo->data_start;
}

static bool ino_valid(Ctx *ctx, Ino ino)
{
    ino -= ctx->fs->geo->data_start;
    return ino < ctx->fs->geo->data_blocks;
}

static Ino find_entry(Ctx *ctx, Ino ino, char const *name, size_t size)
{
    Inode const *inode = inode_get(ctx, ino);
    if (!inode) return -1;
    Off off = 0;
    while (true) {
        Entry de[1];
        off = dir_read(ctx, inode, off, de);
        if (off == -1) return -1;
        if (off == 0) {
            set_ctx_errno(ctx, ENOENT);
            return -1;
        }
        if (!ino_valid(ctx, de->ino) || !*de->name) {
            set_ctx_errno(ctx, EIO);
            return -1;
        }
        if (strnlen(de->name, NAME_MAX) != size)
            continue;
        if (!memcmp(de->name, name, size))
            return de->ino;
    }
}

static Ino ino_from_path(Ctx *ctx, char const *path)
{
    if (*path != '/') {
        set_ctx_errno(ctx, EINVAL);
        return -1;
    }
    Ino ino = root_ino(ctx);
    while (*++path) {
        size_t name_size = strchrnul(path, '/') - path;
        if (!name_size) {
            set_ctx_errno(ctx, EINVAL);
            return -1;
        }
        ino = find_entry(ctx, ino, path, name_size);
        if (ino == -1) return -1;
        path += name_size;
    }
    return ino;
}

static Fd fd_new(Ctx *ctx, Ino ino)
{
    for (Fd fd = 0; fd < MAX_FDS; ++fd) {
        if (ctx->fs->fds[fd] == -1) {
            ctx->fs->fds[fd] = ino;
            return fd;
        }
    }
    set_ctx_errno(ctx, ENFILE);
    return -1;
}

ssize_t thinfs_readlink(Fs *fs, char const *path, char *buf, size_t bufsize)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode const *inode = inode_get(ctx, ino_from_path(ctx, path));
    if (!inode) goto fail;
    ssize_t actual = inode_read(ctx, inode, buf, bufsize, 0);
    if (actual == -1) goto fail;
    return -ctx_close(ctx) || actual;
fail:
    return -ctx_close(ctx);
}

Fd thinfs_open(Fs *fs, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Ino ino = ino_from_path(ctx, path);
    if (ino == -1)
        return -ctx_close(ctx);
    Fd fd = fd_new(ctx, ino);
    return -ctx_close(ctx) || fd;
}

ThinfsErrno thinfs_close(Fs *fs, Fd fd)
{
    return EOPNOTSUPP;
}

static struct stat inode_to_stat(Ctx *ctx, Inode const *inode)
{
    return (struct stat) {
        .st_ino = inode->ino,
        .st_nlink = inode->nlink,
        .st_mode = inode->perms | inode->type << 12,
        .st_uid = inode->uid,
        .st_gid = inode->gid,
        .st_rdev = inode->rdev,
        .st_size = inode->file_data->size,
        .st_blksize = ctx->fs->geo->block_size,
        .st_blocks = inode_blocks(ctx, inode),
        .st_atim = timespec_from_thinfs_time(inode->atime),
        .st_mtim = timespec_from_thinfs_time(inode->mtime),
        .st_ctim = timespec_from_thinfs_time(inode->ctime),
    };
}

ThinfsErrno thinfs_fstat(Fs *fs, ThinfsFd fd, struct stat *buf)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode const *inode = inode_get(ctx, ctx->fs->fds[fd]);
    if (!inode) goto done;
    *buf = inode_to_stat(ctx, inode);
done:
    return ctx_close(ctx);
}

ThinfsErrno thinfs_stat(Fs *fs, char const *path, struct stat *buf)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode const *inode = inode_get(ctx, ino_from_path(ctx, path));
    if (!inode) goto done;
    *buf = inode_to_stat(ctx, inode);
done:
    return ctx_close(ctx);
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
    Geometry geo = geometry_from_mbr(mbr);
    // map from bitmap start, to root inode block
    char *buf = mmap(NULL, geo.block_size * geo.data_start + 1, PROT_WRITE, MAP_SHARED, fd, pagesize);
    *buf = 1; // allocate the first inode
    memset(buf + 1, 0, geo.block_size * geo.bitmap_blocks - 1);
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts)) {
        perror("clock_gettime");
        return false;
    }
    Time time = time_from_timespec(ts);
    *(Inode *)(buf + geo.block_size * geo.bitmap_blocks) = (Inode) {
        .ino = geo.data_start,
        .nlink = 2,
        .type = THINFS_IFDIR,
        .perms = 0755,
        .file_data = {{.root = -1}},
        .atime = time,
        .mtime = time,
        .ctime = time,
    };
    munmap(buf, geo.block_size * geo.data_start);
    munmap(mbr, pagesize);
    return true;
}

