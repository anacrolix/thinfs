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
typedef Blkno *Indirect;

struct Thinfs {
    void *devbuf;
    Geo geo[1];
    int devfd;
    Ino fds[MAX_FDS];
};

typedef struct {
    Thinfs *fs;
    ThinfsErrno eno;
    Time time;
} Ctx;


typedef struct {
    char const *s;
    size_t n;
} Path;

static bool path_split(Path path, Path *dir, Path *base)
{
    char *p = memrchr(path.s, '/', path.n);
    *dir = (Path) {
        .s = path.s,
        .n = p - path.s
    };
    *base = (Path) {
        .s = p + 1,
        .n = path.n - dir->n - 1
    };
    if (p == path.s) dir->s = NULL;
    return true;
}

static Path path_from_cstr(char const *path)
{
    return (Path) {
        .s = path,
        .n = strlen(path),
    };
}

/*
Returns the next name in the path. If it's the end of the path, Path.s is set to NULL.
*/
static Path path_next_name(Path full, Path last)
{
    Path next = { .s = last.s + last.n };
    next.n = full.s + full.n - next.s;
    if (next.n == 0) {
        return (Path) {
            .s = NULL,
            .n = -1,
        };
    }
    if (*next.s == '/') {
        next.s++;
        next.n--;
    }
    char *end = memchr(next.s, '/', next.n);
    if (end) next.n = end - next.s;
    return next;
}

// return the first name in the path
static Path path_first_name(Path path)
{
    if (path.s[0] != '/' || path.n == 0) {
        return (Path) {
            .s = path.s,
            .n = 0,
        };
    }
    Path last = {
        .s = path.s,
        .n = 1,
    };
    return path_next_name(path, last);
}

static Data *inode_file_data(Inode *inode)
{
    return inode->file_data;
}

static Time time_from_timespec(struct timespec ts)
{
    return (Time) {
        .secs = ts.tv_sec,
        .nanos = ts.tv_nsec,
    };
}

static Time ctx_time(Ctx *ctx)
{
    if (ctx->time.secs == -1) {
        struct timespec ts[1];
        clock_gettime(CLOCK_REALTIME, ts);
        ctx->time = time_from_timespec(*ts);
    }
    return ctx->time;
}

static void ctx_set_errno(Ctx *ctx, int eno)
{
    ctx->eno = eno;
}

static Errno ctx_get_errno(Ctx *ctx)
{
    return ctx->eno;
}

static void ctx_clear_errno(Ctx *ctx)
{
    ctx->eno = 0;
}

static void *block_get(Ctx *ctx, Blkno blkno)
{
    if (!(0 <= blkno && blkno < ctx->fs->geo->block_count)) {
        ctx_set_errno(ctx, EIO);
        return NULL;
    }
    return ctx->fs->devbuf + blkno * ctx->fs->geo->block_size;
}

Geo geo_from_mbr(MBR const *mbr)
{
    Geo geo = {
        .bitmap_start = 1,
        .block_size = mbr->block_size,
        .bitmap_density = mbr->block_size * CHAR_BIT,
        .block_count = mbr->block_count,
        .page_size = sysconf(_SC_PAGESIZE),
        .entry_size = 512,
        .entries_per_block = mbr->block_size / 512,
        .indirect_density = mbr->block_size / sizeof(Blkno),
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
    memset(fs->fds, -1, sizeof fs->fds);
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
    *fs->geo = geo_from_mbr(mbr);
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

static Inode *inode_get(Ctx *ctx, Ino ino)
{
    Inode *inode = block_get(ctx, ino);
    if (!inode) return NULL;
    if (inode->ino != ino) {
        fprintf(stderr, "inode %" PRIINO " is corrupted\n", ino);
        ctx_set_errno(ctx, EIO);
        return NULL;
    }
    return inode;
}

static Blkno block_alloc(Ctx *ctx)
{
    for (size_t i = 0; i < ctx->fs->geo->data_blocks / CHAR_BIT; ++i) {
        char *byte = ctx->fs->devbuf + ctx->fs->geo->block_size * ctx->fs->geo->bitmap_start + i;
        if (*byte == -1) continue;
        for (int j = 0; j < CHAR_BIT; ++j) {
            if (!((*byte >> j) & 1)) {
                *byte |= 1 << j;
                return ctx->fs->geo->data_start + i * CHAR_BIT + j;
            }
        }
        abort();
        return -1;
    }
    ctx_set_errno(ctx, ENOSPC);
    return -1;
}

static Inode *inode_new(Ctx *ctx, mode_t mode, dev_t rdev, uid_t uid, gid_t gid)
{
    Ino ino = block_alloc(ctx);
    if (ino == -1) return NULL;
    Inode *inode = block_get(ctx, ino);
    *inode = (Inode) {
        .ino = ino,
        .nlink = 1 ? S_ISDIR(mode) : 0,
        .mode = mode,
        .uid = uid,
        .gid = gid,
        .rdev = rdev,
        .file_data = {{.root = -1}},
        .atime = ctx_time(ctx),
        .mtime = ctx_time(ctx),
        .ctime = ctx_time(ctx),
    };
    return inode;
}

Ctx ctx_open(Fs *fs)
{
    return (Ctx) {
        .fs = fs,
        .time = {
            .secs = -1,
            .nanos = -1,
        },
    };
}

Geo const *ctx_geo(Ctx *ctx)
{
    return ctx->fs->geo;
}

Errno ctx_close(Ctx *ctx)
{
    return ctx->eno;
}

static bool block_free(Ctx *ctx, Blkno blkno)
{
    Blkno data_offset = blkno - ctx_geo(ctx)->data_start;
    Blkno bitmap_blkno = ctx_geo(ctx)->bitmap_start + data_offset / ctx_geo(ctx)->bitmap_density;
    Blkno bitmap_offset = data_offset % ctx_geo(ctx)->bitmap_density;
    size_t byte_index = bitmap_offset / CHAR_BIT;
    size_t bit_index = bitmap_offset % CHAR_BIT;
    char *bitmap_block = block_get(ctx, bitmap_blkno);
    if (!bitmap_block) return false;
    if (!((bitmap_block[byte_index] >> bit_index) & 1)) {
        fprintf(stderr, "tried to free unallocated block\n");
        ctx_set_errno(ctx, EIO);
        return false;
    }
    bitmap_block[byte_index] &= ~(1 << bit_index);
    return true;
}

Errno ctx_abandon(Ctx *ctx)
{
    Errno eno = ctx_close(ctx);
    if (!eno) {
        fprintf(stderr, "an operation failed but no error code was given\n");
        abort();
    }
    return eno;
}

Errno ctx_commit(Ctx *ctx)
{
    if (ctx->eno) {
        fprintf(stderr, "tried to commit a failed operation\n");
        abort();
    }
    return ctx_close(ctx);
}

static blkcnt_t data_blocks(Ctx *ctx, Data const *data)
{
    blkcnt_t recurse(Blkno blkno, Depth depth) {
        if (blkno == -1)
            return 0;
        if (depth == 0)
            return 1;
        Blkno const *indirect = block_get(ctx, blkno);
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

static __attribute__((pure)) Blkno depth_capacity_blocks(Ctx *ctx, Depth depth)
{
    if (depth <= 0) return 0;
    Blkno cap = 1;
    while (--depth > 0) cap *= ctx->fs->geo->bitmap_density;
    return cap;
}

static __attribute__((pure)) uint64_t depth_capacity_bytes(Ctx *ctx, Depth depth)
{
    return depth_capacity_blocks(ctx, depth) * ctx->fs->geo->block_size;
}

static bool read_block(Ctx *ctx, Blkno blkno, void *buf, size_t count, Off off)
{
    void const *block = block_get(ctx, blkno);
    memcpy(buf, block + off, count);
    return true;
}

static Blkno data_bmap(Ctx *ctx, Data *data, Blkno index)
{
    Blkno recurse(Blkno blkno, Depth depth, Blkno index) {
        if (depth == 0 && index == 0) return blkno;
        Blkno cap = depth_capacity_blocks(ctx, depth);
        Indirect indirect = block_get(ctx, blkno);
        return recurse(indirect[index / cap], depth - 1, index % cap);
    }
    if (index >= depth_capacity_blocks(ctx, data->depth)) return -1;
    return recurse(data->root, data->depth - 1, index);
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
    Blkno const *indirect = block_get(ctx, blkno);
    uint64_t childcap = depth_capacity_bytes(ctx, depth);
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
    uint64_t tree_cap = depth_capacity_bytes(ctx, data->depth);
    uint64_t tree_count = MIN(count, MAX(tree_cap - off, 0));
    if (!data_read_recurse(ctx, data->root, data->depth, buf, tree_count, off))
        return -1;
    if (count > tree_count)
        memset(buf + tree_count, 0, count - tree_count);
    return count;
}

static Off data_lengthen(Ctx *ctx, Data *data, Off len)
{
    while (depth_capacity_bytes(ctx, data->depth) < len) {
        Blkno new_root = block_alloc(ctx);
        if (new_root == -1) return -1;
        Blkno *indirect = block_get(ctx, new_root);
        memset(indirect, -1, ctx_geo(ctx)->block_size);
        *indirect = data->root;
        data->root = new_root;
        data->depth++;
    }
    return len;
}

static bool data_shorten(Ctx *ctx, Data *data, Off len)
{
    bool recurse(Blkno blkno, Depth depth, Off len) {
        Blkno *indirect = block_get(ctx, blkno);
        if (!indirect) return false;
        Blkno *indirect_end = indirect + ctx_geo(ctx)->indirect_density;
        indirect += len / depth_capacity_bytes(ctx, depth - 1);
        len %= depth_capacity_bytes(ctx, depth - 1);
        for (; indirect < indirect_end; indirect++) {
            if (!recurse(*indirect, depth - 1, len))
                return false;
            if (len == 0) *indirect = -1;
            len = 0;
        }
        return true;
    }
    if (!recurse(data->root, data->depth, len))
        return false;
    while (data->depth > 1 && depth_capacity_bytes(ctx, data->depth - 1) >= len) {
        Blkno *indirect = block_get(ctx, data->root);
        Blkno new_root = indirect[0];
        block_free(ctx, data->root);
        data->root = new_root;
        data->depth--;
    }
    if (len == 0) {
        if (!block_free(ctx, data->root)) return false;
        data->root = -1;
        data->depth = 0;
    }
    data->size = len;
    return true;
}

static bool data_truncate(Ctx *ctx, Data *data, Off len)
{
    if (len < data->size) return data_shorten(ctx, data, len);
    else if (len > data->size) return data_lengthen(ctx, data, len);
    return true;
}

static ssize_t data_write(Ctx *ctx, Data *data, void const *buf, size_t count, Off off)
{
    if (-1 == data_lengthen(ctx, data, off + count)) return -1;
    bool recurse(Blkno blkno, Depth depth, void const *buf, size_t count, Off off) {
        if (depth == 0) {
            void *block = block_get(ctx, blkno);
            memcpy(block + off, buf, count);
            return true;
        }
        Blkno *indirect = block_get(ctx, blkno);
        Off childcap = depth_capacity_bytes(ctx, depth - 1);
        indirect += off / childcap;
        off %= childcap;
        while (count != 0) {
            if (*indirect == -1) {
                *indirect = block_alloc(ctx);
                if (*indirect == -1) return false;
            }
            Off subcount = MIN(count, childcap - off);
            if (subcount != recurse(*indirect, depth - 1, buf, subcount, off)) return -1;
            count -= subcount;
            off = 0;
            indirect++;
        }
        return true;
    }
    if (!recurse(data->root, data->depth - 1, buf, count, off))
        return -1;
    data->size = MAX(data->size, off + count);
    return count;
}

static bool inode_is_dir(Inode const *inode)
{
    return S_ISDIR(inode->mode);
}

static ssize_t inode_read(Ctx *ctx, Inode const *inode, void *buf, size_t count, Off off)
{
    return data_read(ctx, inode->file_data, buf, count, off);
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

static Off dir_entry_count(Ctx *ctx, Inode *dir)
{
    Off size = inode_file_data(dir)->size;
    Off entry_size = ctx_geo(ctx)->entry_size;
    if (size % entry_size) {
        fprintf(stderr, "directory has invalid size\n");
        ctx_set_errno(ctx, EIO);
        return -1;
    }
    return size / entry_size;
}

static Entry *dir_get_entry(Ctx *ctx, Inode *inode, Off off)
{
    Blkno blkidx = off / ctx_geo(ctx)->entries_per_block;
    Blkno blkno = data_bmap(ctx, inode_file_data(inode), blkidx);
    void *block = block_get(ctx, blkno);
    return block + (ctx_geo(ctx)->entry_size * (off % ctx_geo(ctx)->entries_per_block));
}

static Ino dir_find_off(Ctx *ctx, Inode *inode, Path name, Off *off)
{
    for (*off = 0; *off < dir_entry_count(ctx, inode); ++*off) {
        Entry *entry = dir_get_entry(ctx, inode, *off);
        if (!entry) return -1;
        if (entry->namelen != name.n) continue;
        if (memcmp(name.s, entry->name, name.n)) continue;
        return entry->ino;
    }
    ctx_set_errno(ctx, ENOENT);
    return -1;
}

static Ino dir_find(Ctx *ctx, Inode *inode, Path name)
{
    Off off;
    return dir_find_off(ctx, inode, name, &off);
}

static Off dir_add(Ctx *ctx, Inode *dir, Path name, Inode *inode)
{
    Ino exists = dir_find(ctx, dir, name);
    if (exists != -1) {
        ctx_set_errno(ctx, EEXIST);
        return -1;
    }
    if (ctx_get_errno(ctx) != ENOENT) return -1;
    ctx_clear_errno(ctx);
    Off entries = dir_entry_count(ctx, dir);
    Entry entry;
    entry.ino = inode->ino;
    entry.namelen = name.n;
    memcpy(entry.name, name.s, name.n);
    entry.name[name.n] = '\0';
    size_t entry_size = ctx_geo(ctx)->entry_size;
    ssize_t written = data_write(ctx, inode_file_data(dir), &entry, entry_size, entries * entry_size);
    if (written == -1) return -1;
    if (written != entry_size) {
        fprintf(stderr, "partial directory write\n");
        ctx_set_errno(ctx, EIO);
        return -1;
    }
    inode->nlink++;
    if (inode_is_dir(inode)) dir->nlink++;
    return entries;
}

static bool dir_remove(Ctx *ctx, Inode *dir, Path name)
{
    Off off;
    Ino ino = dir_find_off(ctx, dir, name, &off);
    if (ino == -1) return false;
    if (off != dir_entry_count(ctx, dir) - 1) {
        // move the entry down if it's not the last one
        Entry *dest = dir_get_entry(ctx, dir, off);
        Entry *src = dir_get_entry(ctx, dir, dir_entry_count(ctx, dir) - 1);
        memcpy(dest, src, ctx_geo(ctx)->entry_size);
    }
    // drop the last entry
    if (!data_truncate(ctx, inode_file_data(dir), inode_file_data(dir)->size - ctx_geo(ctx)->entry_size))
        return false;
    Inode *inode = inode_get(ctx, ino);
    if (!inode) return false;
    if (inode_is_dir(inode))
        dir->nlink--;
    inode->nlink--;
    return true;
}

static Ino ino_from_path(Ctx *ctx, Path path)
{
    Ino ino = root_ino(ctx);
    Path name = path_first_name(path);
    while (name.s) {
        if (name.n == 0) {
            ctx_set_errno(ctx, EINVAL);
            return -1;
        }
        Inode *inode = inode_get(ctx, ino);
        ino = dir_find(ctx, inode, name);
        if (ino == -1 && ctx_get_errno(ctx))
            return -1;
        name = path_next_name(path, name);
    }
    return ino;
}

static Inode *inode_from_path(Ctx *ctx, Path path)
{
    Ino ino = ino_from_path(ctx, path);
    if (ino == -1) return NULL;
    return inode_get(ctx, ino);
}

static Fd fd_new(Ctx *ctx, Ino ino)
{
    for (Fd fd = 0; fd < MAX_FDS; ++fd) {
        if (ctx->fs->fds[fd] == -1) {
            ctx->fs->fds[fd] = ino;
            return fd;
        }
    }
    ctx_set_errno(ctx, ENFILE);
    return -1;
}

static Ino fd_lookup(Ctx *ctx, Fd fd)
{
    return ctx->fs->fds[fd];
}

static bool fd_valid(Ctx *ctx, Fd fd)
{
    return 0 <= fd && fd < MAX_FDS && ctx->fs->fds[fd] != -1;
}

static bool fd_free(Ctx *ctx, Fd fd)
{
    if (!fd_valid(ctx, fd)) {
        ctx_set_errno(ctx, EBADF);
        return false;
    }
    ctx->fs->fds[fd] = -1;
    return true;
}

ssize_t thinfs_readlink(Fs *fs, char const *path, char *buf, size_t bufsize)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode const *inode = inode_get(ctx, ino_from_path(ctx, path_from_cstr(path)));
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
    Ino ino = ino_from_path(ctx, path_from_cstr(path));
    if (ino == -1)
        return -ctx_close(ctx);
    Fd fd = fd_new(ctx, ino);
    return -ctx_close(ctx) || fd;
}

static struct stat stat_from_inode(Ctx *ctx, Inode const *inode)
{
    return (struct stat) {
        .st_ino = inode->ino,
        .st_nlink = inode->nlink,
        .st_mode = inode->mode,
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
    *buf = stat_from_inode(ctx, inode);
done:
    return ctx_close(ctx);
}

ThinfsErrno thinfs_stat(Fs *fs, char const *path, struct stat *buf)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode const *inode = inode_from_path(ctx, path_from_cstr(path));
    if (!inode) goto done;
    *buf = stat_from_inode(ctx, inode);
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
    Geo geo = geo_from_mbr(mbr);
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
        .mode = S_IFDIR|0755,
        .file_data = {{.root = -1}},
        .atime = time,
        .mtime = time,
        .ctime = time,
    };
    munmap(buf, geo.block_size * geo.data_start);
    munmap(mbr, pagesize);
    return true;
}

ThinfsErrno thinfs_chmod(Thinfs *fs, char const *path, mode_t mode)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_get(ctx, ino_from_path(ctx, path_from_cstr(path)));
    if (!inode) goto done;
    inode->mode &= ~07777;
    inode->mode |= mode & 07777;
    inode->ctime = ctx_time(ctx);
done:
    return ctx_close(ctx);
}

ThinfsErrno thinfs_chown(Thinfs *fs, char const *path, uid_t uid, gid_t gid)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_get(ctx, ino_from_path(ctx, path_from_cstr(path)));
    if (!inode) goto done;
    if (uid == -1 && gid == -1) goto done;
    if (uid != -1) inode->uid = uid;
    if (gid != -1) inode->gid = gid;
    inode->ctime = ctx_time(ctx);
done:
    return ctx_close(ctx);
}

ThinfsErrno thinfs_close(Thinfs *fs, ThinfsFd fd)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (fd_free(ctx, fd))
        return ctx_commit(ctx);
    else
        return ctx_abandon(ctx);
}

static Inode *inode_create(Ctx *ctx, char const *path, mode_t mode, dev_t rdev, uid_t uid, gid_t gid)
{
    Inode *inode = inode_new(ctx, mode, 0, uid, gid);
    if (!inode) return NULL;
    Path dirname, basename;
    if (!path_split(path_from_cstr(path), &dirname, &basename)) return NULL;
    Inode *dir = inode_from_path(ctx, dirname);
    if (-1 == dir_add(ctx, dir, basename, inode)) return NULL;
    return inode;
}

ThinfsFd thinfs_create(Thinfs *fs, char const *path, mode_t mode, uid_t uid, gid_t gid)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_create(ctx, path, mode, 0, uid, gid);
    Fd fd = fd_new(ctx, inode->ino);
    if (fd == -1) goto fail;
    return -ctx_commit(ctx) || fd;
fail:
    return -ctx_abandon(ctx);
}

ThinfsErrno thinfs_fsyncdir(Thinfs *fs, ThinfsFd fd, int dataonly)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (!fd_valid(ctx, fd)) ctx_set_errno(ctx, EBADF);
    return ctx_close(ctx);
}

ThinfsErrno thinfs_link(Thinfs *fs, char const *target, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return ctx_close(ctx);
}

ThinfsErrno thinfs_mkdir(Thinfs *fs, char const *path, mode_t mode, uid_t uid, gid_t gid)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (inode_create(ctx, path, mode | S_IFDIR, 0, uid, gid))
        return ctx_commit(ctx);
    return ctx_abandon(ctx);
}

ThinfsErrno thinfs_mknod(Thinfs *fs, char const *path, mode_t mode, dev_t dev, uid_t uid, gid_t gid)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_create(ctx, path, mode, dev, uid, gid);
    if (!inode) return ctx_abandon(ctx);
    return ctx_commit(ctx);
}

ssize_t thinfs_pread(Thinfs *fs, ThinfsFd fd, void *buf, size_t count, off_t off)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return -ctx_abandon(ctx) || -EOPNOTSUPP;
}

ssize_t thinfs_pwrite(Thinfs *fs, ThinfsFd fd, void const *buf, size_t count, off_t off)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return -ctx_abandon(ctx) || -EOPNOTSUPP;
}

ThinfsErrno thinfs_unlink(Thinfs *fs, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Path dirname, basename;
    path_split(path_from_cstr(path), &dirname, &basename);
    Inode *parent = inode_from_path(ctx, dirname);
    if (!parent) goto fail;
    if (!dir_remove(ctx, parent, basename)) goto fail;
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
}

ThinfsErrno thinfs_rename(Thinfs *fs, char const *oldpath, char const *newpath)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return ctx_abandon(ctx) || EOPNOTSUPP;
}

ThinfsErrno thinfs_rmdir(Thinfs *fs, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return ctx_abandon(ctx) || EOPNOTSUPP;
}

ThinfsErrno thinfs_symlink(Thinfs *fs, char const *target, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return ctx_abandon(ctx) || EOPNOTSUPP;
}

ThinfsErrno thinfs_truncate(Thinfs *fs, char const *path, off_t size)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return ctx_abandon(ctx) || EOPNOTSUPP;
}

ThinfsErrno thinfs_statvfs(Thinfs *fs, struct statvfs *buf)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return ctx_abandon(ctx) || EOPNOTSUPP;
}

ThinfsErrno thinfs_flush(Thinfs *fs, ThinfsFd fd)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (fd_valid(ctx, fd))
        return ctx_commit(ctx);
    return ctx_abandon(ctx);
}

ThinfsErrno thinfs_fsync(Thinfs *fs, ThinfsFd fd, int dataonly)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (!fd_valid(ctx, fd)) {
        ctx_set_errno(ctx, EBADF);
        return ctx_abandon(ctx);
    }
    return ctx_commit(ctx);
}
//~
//~ ThinfsErrno thinfs_setxattr(Thinfs *fs, char const *path, char const *name, char const *value, size_t size, int flags)
//~ {
    //~ Ctx ctx[1] = {ctx_open(fs)};
    //~ return ctx_close(ctx);
//~ }
//~
//~ ssize_t thinfs_getxattr(Thinfs *fs, char const *path, char const *name, char *value, size_t size)
//~ {
    //~ Ctx ctx[1] = {ctx_open(fs)};
    //~ return ctx_close(ctx);
//~ }
//~
//~ ssize_t thinfs_listxattr(Thinfs *fs, char const *path, char *list, size_t size)
//~ {
    //~ Ctx ctx[1] = {ctx_open(fs)};
    //~ return ctx_close(ctx);
//~ }
//~
//~ ThinfsErrno thinfs_removexattr(Thinfs *fs, char const *path, char const *name)
//~ {
    //~ Ctx ctx[1] = {ctx_open(fs)};
    //~ return ctx_close(ctx);
//~ }

ThinfsFd thinfs_opendir(Thinfs *fs, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_from_path(ctx, path_from_cstr(path));
    if (!inode) goto fail;
    Fd fd = fd_new(ctx, inode->ino);
    if (fd == -1) goto fail;
    if (!inode_is_dir(inode)) {
        ctx_set_errno(ctx, ENOTDIR);
        goto fail;
    }
    return -ctx_commit(ctx) || fd;
fail:
    return -ctx_abandon(ctx);
}

ThinfsErrno thinfs_readdir(Thinfs *fs, ThinfsFd fd, void *data, ThinfsFillDir filler, off_t off)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Ino ino = fd_lookup(ctx, fd);
    if (ino == -1) goto fail;
    Inode *dir = inode_get(ctx, ino);
    if (!dir) goto fail;
    Off nentries = dir_entry_count(ctx, dir);
    do {
        struct stat stbuf;
        char const *name;
        switch (off) {
            case 0:
            off = -1;
            stbuf = stat_from_inode(ctx, dir);
            name = ".";
            break;
            case -1:
            off = -2;
            name = "..";
            break;
            case -2:
            off = 0;
            default:
            if (off >= nentries) goto done;
            Entry *entry = dir_get_entry(ctx, dir, off);
            Inode const *inode = inode_get(ctx, entry->ino);
            if (!inode) goto fail;
            off++;
            stbuf = stat_from_inode(ctx, inode);
            name = entry->name;
        }
        if (filler(data, name, &stbuf, off)) break;
    } while (off != 0);
done:
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
}

ThinfsErrno thinfs_releasedir(Thinfs *fs, ThinfsFd fd)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (fd_free(ctx, fd))
        return ctx_commit(ctx);
    else
        return ctx_abandon(ctx);
}

ThinfsErrno thinfs_ftruncate(Thinfs *fs, ThinfsFd fd, off_t len)
{
    Ctx ctx[1] = {ctx_open(fs)};
    return ctx_abandon(ctx) || EOPNOTSUPP;
}

ThinfsErrno thinfs_utimens(Thinfs *fs, char const *path, const struct timespec times[2])
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_from_path(ctx, path_from_cstr(path));
    if (!inode) goto fail;
    if (times) {
        inode->atime = time_from_timespec(times[0]);
        inode->mtime = time_from_timespec(times[1]);
    } else {
        inode->atime = ctx_time(ctx);
        inode->mtime = ctx_time(ctx);
    }
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
}

