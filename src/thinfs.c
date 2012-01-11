#include "thinfs.h"
#include "types.h"
#include <assert.h>
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

#undef MAX
#define MAX(a,b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a > _b ? _a : _b; })

#undef MIN
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
    size_t lastbit;
    Fd last_fd;
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

static Geo const *ctx_geo(Ctx *ctx)
{
    return ctx->fs->geo;
}

static bool ino_valid(Ctx *ctx, Ino ino)
{
    ino -= ctx_geo(ctx)->data_start;
    return 0 <= ino && ino < ctx_geo(ctx)->data_blocks;
}

static void path_split(Path path, Path *dir, Path *base)
{
    char *p = memrchr(path.s, '/', path.n);
    if (p) {
        if (p == path.s) {
            *dir = (Path) {
                .s = p,
                .n = 1,
            };
        } else {
            *dir = (Path) {
                .s = path.s,
                .n = p - path.s,
            };
        }
        *base = (Path) {
            .s = p + 1,
            .n = path.s + path.n - (p + 1),
        };
    } else {
        *dir = (Path) {};
        *base = path;
    }
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
    Path next = { .s = last.s + last.n + 1 };
    next.n = full.s + full.n - next.s;
    if (next.n == -1) return (Path) {};
    char *end = memchr(next.s, '/', next.n);
    if (end) next.n = end - next.s;
    return next;
}

// return the first name in the path
static Path path_first_name(Path path)
{
    char *end = memchr(path.s, '/', path.n);
    if (end) {
        return (Path) {
            .s = path.s,
            .n = end - path.s,
        };
    }
    if (path.n == 0) path.s = NULL;
    return path;
}

static bool inode_is_dir(Inode const *inode)
{
    return S_ISDIR(inode->mode);
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

static bool blkno_valid(Ctx *ctx, Blkno blkno)
{
    return 0 <= blkno && blkno < ctx_geo(ctx)->block_count;
}

static void *bitmap_get(Ctx *ctx)
{
    return ctx->fs->devbuf + ctx_geo(ctx)->bitmap_start * ctx_geo(ctx)->block_size;
}

static bool bitmap_isset(Ctx *ctx, Blkno blkno)
{
    blkno -= ctx_geo(ctx)->data_start;
    if (!(0 <= blkno && blkno < ctx_geo(ctx)->data_blocks)) abort();
    return (((char *)bitmap_get(ctx))[blkno / CHAR_BIT] >> (blkno % CHAR_BIT)) & 1;
}

static void *block_get(Ctx *ctx, Blkno blkno)
{
    if (blkno == -1) return NULL;
    if (!bitmap_isset(ctx, blkno)) abort();
    return ctx->fs->devbuf + blkno * ctx_geo(ctx)->block_size;
}

static ssize_t block_read(Ctx *ctx, Blkno blkno, void *buf, size_t count, Off off)
{
    count = MAX(0, MIN(count, ctx_geo(ctx)->block_size - off));
    void const *block = block_get(ctx, blkno);
    memcpy(buf, block + off, count);
    return count;
}

static Geo geo_from_mbr(MBR const *mbr)
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
    MBR *mbr = mmap(NULL, pagesize, PROT_READ, MAP_SHARED, fs->devfd, 0);
    *fs->geo = geo_from_mbr(mbr);
    munmap(mbr, pagesize);
    fs->devbuf = mmap(NULL, fs->geo->block_size * fs->geo->block_count, PROT_READ|PROT_WRITE, MAP_SHARED, fs->devfd, 0);
    return fs;
failed:
    thinfs_unmount(fs);
    return NULL;
}

static bool inode_valid(Ctx *ctx, Inode const *inode, Ino ino)
{
    if (inode->ino != ino) return false;
    return true;
}

static Inode *inode_get(Ctx *ctx, Ino ino)
{
    if (ino == -1) return NULL;
    Inode *inode = block_get(ctx, ino);
    if (!inode) return NULL;
    if (!inode_valid(ctx, inode, ino)) abort();
    return inode;
}

static Blkno block_alloc(Ctx *ctx)
{
    char *bitmap = bitmap_get(ctx);
    size_t startbit = ctx->fs->lastbit + 1;
    for (size_t index = 0; index < ctx_geo(ctx)->data_blocks; ++index) {
        size_t bit = (startbit + index) % ctx_geo(ctx)->data_blocks;
        if (!((bitmap[bit / CHAR_BIT] >> (bit % CHAR_BIT)) & 1)) {
            bitmap[bit / CHAR_BIT] |= 1 << (bit % CHAR_BIT);
            ctx->fs->lastbit = bit;
            return ctx_geo(ctx)->data_start + bit;
        }
    }
    ctx_set_errno(ctx, ENOSPC);
    return -1;
}

static int inode_nlink_min(Inode *inode)
{
    return inode_is_dir(inode) ? 1 : 0;
}

static void inode_ref(Ctx *ctx, Inode *inode)
{
    inode->nlink++;
}

static Inode *inode_new(Ctx *ctx, mode_t mode, dev_t rdev, uid_t uid, gid_t gid)
{
    Ino ino = block_alloc(ctx);
    if (ino == -1) return NULL;
    if (!ino_valid(ctx, ino)) abort();
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
        .xattr = {{.root = -1}},
    };
    inode_ref(ctx, inode);
    return inode;
}

static Ctx ctx_open(Fs *fs)
{
    return (Ctx) {
        .fs = fs,
        .time = {
            .secs = -1,
            .nanos = -1,
        },
    };
}

static Errno ctx_close(Ctx *ctx)
{
    return ctx->eno;
}

static void block_free(Ctx *ctx, Blkno blkno)
{
    blkno -= ctx_geo(ctx)->data_start;
    if (!(0 <= blkno && blkno < ctx_geo(ctx)->data_blocks)) abort();
    size_t byte_index = blkno / CHAR_BIT;
    int bit_index = blkno % CHAR_BIT;
    char *bitmap = bitmap_get(ctx);
    if (!((bitmap[byte_index] >> bit_index) & 1)) abort();
    bitmap[byte_index] &= ~(1 << bit_index);
}

static Errno ctx_abandon(Ctx *ctx)
{
    Errno eno = ctx_close(ctx);
    if (!eno) {
        fprintf(stderr, "an operation failed but no error code was given\n");
        abort();
    }
    return eno;
}

static Errno ctx_commit(Ctx *ctx)
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
        for (int i = 0; i < ctx->fs->geo->indirect_density; ++i)
            blocks += recurse(indirect[i], depth - 1);
        return blocks;
    }
    return recurse(data->root, data->depth - 1);
}

static blkcnt_t inode_blocks(Ctx *ctx, Inode const *inode)
{
    return data_blocks(ctx, inode->file_data);
}

static struct timespec timespec_from_thinfs_time(Time time)
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
    while (--depth > 0) cap *= ctx->fs->geo->indirect_density;
    return cap;
}

static __attribute__((pure)) uint64_t depth_capacity_bytes(Ctx *ctx, Depth depth)
{
    return depth_capacity_blocks(ctx, depth) * ctx_geo(ctx)->block_size;
}

static Blkno data_bmap(Ctx *ctx, Data *data, Blkno index)
{
    Blkno recurse(Blkno blkno, Depth depth, Blkno index) {
        if (depth == 0 && index == 0) return blkno;
        Blkno cap = depth_capacity_blocks(ctx, depth);
        if (!ino_valid(ctx, blkno)) abort();
        Blkno const *indirect = block_get(ctx, blkno);
        return recurse(indirect[index / cap], depth - 1, index % cap);
    }
    if (index >= depth_capacity_blocks(ctx, data->depth)) return -1;
    return recurse(data->root, data->depth - 1, index);
}

static ssize_t data_read(Ctx *ctx, Data const *data, void *buf, size_t count, Off off)
{
    void recurse(Blkno blkno, Depth depth, void *buf, size_t count, Off off) {
        if (blkno == -1) {
            memset(buf, 0, count);
            return;
        }
        if (!ino_valid(ctx, blkno)) abort();
        if (depth == 0) {
            if (count != block_read(ctx, blkno, buf, count, off)) abort();
            return;
        }
        Blkno const *indirect = block_get(ctx, blkno);
        uint64_t childcap = depth_capacity_bytes(ctx, depth);
        indirect += off / childcap;
        off %= childcap;
        while (count != 0) {
            size_t childcnt = MIN(count, childcap - off);
            recurse(*indirect, depth-1, buf, childcnt, off);
            count -= childcnt;
            off = 0;
            buf += childcnt;
            indirect++;
        }
    }
    count = MIN(count, MAX(data->size - off, 0));
    Off treecap = depth_capacity_bytes(ctx, data->depth);
    uint64_t treecnt = MIN(count, MAX(treecap - off, 0));
    if (treecnt) recurse(data->root, data->depth - 1, buf, treecnt, off);
    if (count > treecnt) memset(buf + treecnt, 0, count - treecnt);
    return count;
}

static bool data_lengthen(Ctx *ctx, Data *data, Off len)
{
    while (depth_capacity_bytes(ctx, data->depth) < len) {
        Blkno new_root = block_alloc(ctx);
        if (new_root == -1) return false;
        Blkno *indirect = block_get(ctx, new_root);
        memset(indirect, -1, ctx_geo(ctx)->block_size);
        *indirect = data->root;
        data->root = new_root;
        data->depth++;
    }
    return true;
}

static void data_shorten(Ctx *ctx, Data *data, Off len)
{
    Blkno recurse(Blkno blkno, Depth depth, Off len) {
        if (blkno == -1) return -1;
        if (!ino_valid(ctx, blkno)) abort();
        if (depth > 0) {
            Blkno *indirect = block_get(ctx, blkno);
            Blkno *indirect_end = indirect + ctx_geo(ctx)->indirect_density;
            indirect += len / depth_capacity_bytes(ctx, depth);
            Off childlen = len % depth_capacity_bytes(ctx, depth);
            for (; indirect != indirect_end; indirect++) {
                *indirect = recurse(*indirect, depth - 1, childlen);
                childlen = 0;
            }
        }
        if (len == 0) {
            block_free(ctx, blkno);
            blkno = -1;
        }
        return blkno;
    }
    data->root = recurse(data->root, data->depth - 1, MIN(len, depth_capacity_bytes(ctx, data->depth)));
    while (data->depth && depth_capacity_bytes(ctx, data->depth - 1) >= len) {
        if (data->root != -1) {
            Blkno *indirect = block_get(ctx, data->root);
            Blkno new_root = indirect[0];
            block_free(ctx, data->root);
            data->root = new_root;
        }
        data->depth--;
    }
    data->size = len;
}

static void data_truncate(Ctx *ctx, Data *data, Off len)
{
    if (len < data->size) data_shorten(ctx, data, len);
    else if (len > data->size) data->size = len;
}

static bool dir_is_empty(Inode *dir)
{
    if (!inode_is_dir(dir)) abort();
    return dir->file_data->size == 0;
}

static void inode_unref(Ctx *ctx, Inode *inode)
{
    inode->nlink--;
    if (inode->nlink < inode_nlink_min(inode)) abort();
    if (inode->nlink != inode_nlink_min(inode)) return;
    if (inode_is_dir(inode) && !dir_is_empty(inode)) abort();
    data_shorten(ctx, inode->file_data, 0);
    block_free(ctx, inode->ino);
}

void thinfs_unmount(Thinfs *fs)
{
    Ctx ctx = ctx_open(fs);
    for (Fd fd = 0; fd < MAX_FDS; ++fd) {
        if (fs->fds[fd] != -1) {
            inode_unref(&ctx, inode_get(&ctx, fs->fds[fd]));
            fs->fds[fd] = -1;
        }
    }
    ctx_commit(&ctx);
    munmap(fs->devbuf, fs->geo->block_count * fs->geo->block_size);
    close(fs->devfd);
    free(fs);
}

static ssize_t data_write(Ctx *ctx, Data *data, void const *buf, size_t count, Off off)
{
    if (count == 0) return 0;
    if (!data_lengthen(ctx, data, off + count)) return -1;
    size_t blksize = ctx_geo(ctx)->block_size;
    size_t recurse(Blkno blkno, Depth depth, void const *buf, size_t count, Off off) {
        if (depth == 0) {
            void *block = block_get(ctx, blkno);
            memcpy(block + off, buf, count);
            return count;
        }
        Blkno *indirect = block_get(ctx, blkno);
        Off childcap = depth_capacity_bytes(ctx, depth);
        indirect += off / childcap;
        off %= childcap;
        ssize_t nwrite = 0;
        while (count != 0) {
            if (*indirect == -1) {
                *indirect = block_alloc(ctx);
                if (*indirect == -1) return nwrite;
                if (depth > 1) {
                    void *block = block_get(ctx, *indirect);
                    memset(block, -1, ctx_geo(ctx)->block_size);
                }
            }
            Off childcnt = MIN(count, childcap - off);
            size_t childret = recurse(*indirect, depth - 1, buf, childcnt, off);
            nwrite += childret;
            if (childret != childcnt) return nwrite;
            buf += childcnt;
            count -= childcnt;
            off = 0;
            indirect++;
        }
        return nwrite;
    }
    size_t nwrite = recurse(data->root, data->depth - 1, buf, count, off);
    if (nwrite == 0) return -1;
    data->size = MAX(data->size, off + nwrite);
    return nwrite;
}

static ssize_t inode_read(Ctx *ctx, Inode const *inode, void *buf, size_t count, Off off)
{
    return data_read(ctx, inode->file_data, buf, count, off);
}

static Off inode_size(Ctx *ctx, Inode *inode)
{
    return inode_file_data(inode)->size;
}

static bool file_truncate(Ctx *ctx, Inode *inode, Off len)
{
    if (inode_is_dir(inode)) {
        ctx_set_errno(ctx, EISDIR);
        return false;
    }
    if (inode_size(ctx, inode) != len) {
        inode->ctime = ctx_time(ctx);
        inode->mtime = ctx_time(ctx);
    }
    data_truncate(ctx, inode_file_data(inode), len);
    return true;
}

static Inode *root_inode(Ctx *ctx)
{
    return inode_get(ctx, ctx->fs->geo->data_start);
}

static Off dir_entry_count(Ctx *ctx, Inode *dir)
{
    Off size = inode_file_data(dir)->size;
    Off entry_size = ctx_geo(ctx)->entry_size;
    if (size % entry_size) abort();
    return size / entry_size;
}

static Blkno entry_blkno(Ctx *ctx, Inode *dir, Off off)
{
    Blkno blkidx = off / ctx_geo(ctx)->entries_per_block;
    return data_bmap(ctx, inode_file_data(dir), blkidx);
}

static Entry *dir_entry_get(Ctx *ctx, Inode *inode, Off off)
{
    if (!inode || off == -1) return NULL;
    void *block = block_get(ctx, entry_blkno(ctx, inode, off));
    return block + (ctx_geo(ctx)->entry_size * (off % ctx_geo(ctx)->entries_per_block));
}

static Off dir_find(Ctx *ctx, Inode *dir, Path name)
{
    for (Off off = 0; off < dir_entry_count(ctx, dir); ++off) {
        Entry *entry = dir_entry_get(ctx, dir, off);
        if (entry->namelen != name.n) continue;
        if (memcmp(name.s, entry->name, name.n)) continue;
        return off;
    }
    ctx_set_errno(ctx, ENOENT);
    return -1;
}

static Off dir_add(Ctx *ctx, Inode *dir, Path name, Ino ino)
{
    if (-1 != dir_find(ctx, dir, name)) {
        ctx_set_errno(ctx, EEXIST);
        return -1;
    }
    if (ctx_get_errno(ctx) != ENOENT) return -1;
    ctx_clear_errno(ctx);
    Off entries = dir_entry_count(ctx, dir);
    if (!data_lengthen(ctx, dir->file_data, dir->file_data->size + ctx_geo(ctx)->entry_size)) return -1;
    size_t entry_size = ctx_geo(ctx)->entry_size;
    Entry *entry = alloca(entry_size);
    entry->ino = ino;
    entry->namelen = name.n;
    memcpy(entry->name, name.s, name.n);
    entry->name[name.n] = '\0';
    size_t written = data_write(ctx, inode_file_data(dir), entry, entry_size, entries * entry_size);
    if (written == -1) return -1;
    if (written != entry_size) abort();
    return entries;
}

static void inode_link(Ctx *ctx, Inode *dir, Inode *inode)
{
    if (inode_is_dir(inode)) {
        inode_ref(ctx, dir);
    }
    inode_ref(ctx, inode);
}

static void inode_unlink(Ctx *ctx, Inode *dir, Inode *inode)
{
    if (inode_is_dir(inode)) inode_unref(ctx, dir);
    inode_unref(ctx, inode);
}

static bool dir_remove(Ctx *ctx, Inode *dir, Off off)
{
    if (!dir || off == -1) return false;
    if (off != dir_entry_count(ctx, dir) - 1) {
        // move the entry down if it's not the last one
        Entry *dest = dir_entry_get(ctx, dir, off);
        Entry *src = dir_entry_get(ctx, dir, dir_entry_count(ctx, dir) - 1);
        memcpy(dest, src, ctx_geo(ctx)->entry_size);
    }
    // drop the last entry
    data_shorten(ctx, dir->file_data, dir->file_data->size - ctx_geo(ctx)->entry_size);
    return true;
}

static Inode *inode_from_path(Ctx *ctx, Path path)
{
    if (path.n >= PATH_MAX) {
        ctx_set_errno(ctx, ENAMETOOLONG);
        return NULL;
    }
    if (path.n-- == 0 || *path.s++ != '/') {
        ctx_set_errno(ctx, EINVAL);
        return NULL;
    }
    Inode *inode = root_inode(ctx);
    Path name = path_first_name(path);
    while (name.s) {
        if (name.n == 0) {
            ctx_set_errno(ctx, EINVAL);
            return NULL;
        } else if (name.n > NAME_MAX) {
            ctx_set_errno(ctx, ENAMETOOLONG);
            return NULL;
        }
        Entry *entry = dir_entry_get(ctx, inode, dir_find(ctx, inode, name));
        if (!entry) return NULL;
        inode = inode_get(ctx, entry->ino);
        name = path_next_name(path, name);
    }
    return inode;
}

static Fd fd_new(Ctx *ctx, Ino ino)
{
    if (ino == -1) return -1;
    for (Fd base_fd = 0; base_fd < MAX_FDS; ++base_fd) {
        Fd fd = (ctx->fs->last_fd + 1 + base_fd) % MAX_FDS;
        if (ctx->fs->fds[fd] == -1) {
            ctx->fs->fds[fd] = ino;
            inode_ref(ctx, inode_get(ctx, ino));
            ctx->fs->last_fd = fd;
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
    inode_unref(ctx, inode_get(ctx, ctx->fs->fds[fd]));
    ctx->fs->fds[fd] = -1;
    return true;
}

ssize_t thinfs_readlink(Fs *fs, char const *path, char *buf, size_t bufsize)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode const *inode = inode_from_path(ctx, path_from_cstr(path));
    if (!inode) goto fail;
    ssize_t actual = inode_read(ctx, inode, buf, bufsize, 0);
    if (actual == -1) goto fail;
    ctx_commit(ctx);
    return actual;
fail:
    return -ctx_close(ctx);
}

Fd thinfs_open(Fs *fs, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_from_path(ctx, path_from_cstr(path));
    if (!inode) return -ctx_abandon(ctx);
    Fd fd = fd_new(ctx, inode->ino);
    if (fd == -1) return -ctx_abandon(ctx);
    ctx_commit(ctx);
    return fd;
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
        .st_blksize = ctx_geo(ctx)->block_size,
        .st_blocks = inode_blocks(ctx, inode) * ctx_geo(ctx)->block_size / 512,
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
        .mode = S_IFDIR|0777,
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
    Inode *inode = inode_from_path(ctx, path_from_cstr(path));
    if (!inode) goto fail;
    inode->mode &= ~07777;
    inode->mode |= mode & 07777;
    inode->ctime = ctx_time(ctx);
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
}

ThinfsErrno thinfs_chown(Thinfs *fs, char const *path, uid_t uid, gid_t gid)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_from_path(ctx, path_from_cstr(path));
    if (!inode) goto fail;
    if (uid == -1 && gid == -1) goto done;
    if (uid != -1) inode->uid = uid;
    if (gid != -1) inode->gid = gid;
    inode->ctime = ctx_time(ctx);
    if (inode->mode & (S_IXUSR|S_IXGRP|S_IXOTH)) inode->mode &= ~(S_ISUID|S_ISGID);
done:
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
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
    Path dirname, basename;
    path_split(path_from_cstr(path), &dirname, &basename);
    Inode *dir = inode_from_path(ctx, dirname);
    if (!dir) return NULL;
    Inode *inode = inode_new(ctx, mode, 0, uid, gid);
    if (!inode) return NULL;
    if (-1 == dir_add(ctx, dir, basename, inode->ino)) {
        inode_unref(ctx, inode);
        return NULL;
    }
    inode_link(ctx, dir, inode);
    dir->ctime = dir->mtime = ctx_time(ctx);
    inode_unref(ctx, inode);
    return inode;
}

ThinfsFd thinfs_create(Thinfs *fs, char const *path, mode_t mode, uid_t uid, gid_t gid)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_create(ctx, path, mode, 0, uid, gid);
    if (!inode) goto fail;
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
    Inode *inode = inode_from_path(ctx, path_from_cstr(target));
    if (!inode) goto fail;
    Path dirname, basename;
    path_split(path_from_cstr(path), &dirname, &basename);
    Dir *dir = inode_from_path(ctx, dirname);
    if (!dir) goto fail;
    if (-1 == dir_add(ctx, dir, basename, inode->ino)) goto fail;
    inode_link(ctx, dir, inode);
    dir->ctime = ctx_time(ctx);
    dir->mtime = ctx_time(ctx);
    inode->ctime = ctx_time(ctx);
    return ctx_commit(ctx);
fail:
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
    Inode *inode = inode_get(ctx, fd_lookup(ctx, fd));
    ssize_t nread = inode_read(ctx, inode, buf, count, off);
    if (-1 == nread) goto fail;
    Errno eno = ctx_commit(ctx);
    if (eno) return -eno;
    return nread;
fail:
    return -ctx_abandon(ctx);
}

ssize_t thinfs_pwrite(Thinfs *fs, ThinfsFd fd, void const *buf, size_t count, off_t off)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_get(ctx, fd_lookup(ctx, fd));
    if (!inode) goto fail;
    ssize_t written = data_write(ctx, inode->file_data, buf, count, off);
    if (written == -1) goto fail;
    if (written > 0) {
        inode->ctime = ctx_time(ctx);
        inode->mtime = ctx_time(ctx);
    }
    ctx_commit(ctx);
    return written;
fail:
    return -ctx_abandon(ctx);
}

ThinfsErrno thinfs_unlink(Thinfs *fs, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Path dirname, basename;
    path_split(path_from_cstr(path), &dirname, &basename);
    Inode *dir = inode_from_path(ctx, dirname);
    Off off = dir_find(ctx, dir, basename);
    Entry *entry = dir_entry_get(ctx, dir, off);
    if (!entry) goto fail;
    Inode *inode = inode_get(ctx, entry->ino);
    if (!inode) goto fail;
    if (inode_is_dir(inode)) {
        ctx_set_errno(ctx, EISDIR);
        goto fail;
    }
    if (!dir_remove(ctx, dir, off)) goto fail;
    dir->ctime = ctx_time(ctx);
    dir->mtime = ctx_time(ctx);
    inode->ctime = ctx_time(ctx);
    inode_unlink(ctx, dir, inode);
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
}

ThinfsErrno thinfs_rename(Thinfs *fs, char const *oldpath, char const *newpath)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Path olddirname, oldbasename, newdirname, newbasename;
    path_split(path_from_cstr(oldpath), &olddirname, &oldbasename);
    path_split(path_from_cstr(newpath), &newdirname, &newbasename);
    Inode *olddir = inode_from_path(ctx, olddirname);
    Inode *newdir = inode_from_path(ctx, newdirname);
    Off oldentryoff = dir_find(ctx, olddir, oldbasename);
    Entry *oldentry = dir_entry_get(ctx, olddir, oldentryoff);
    if (!oldentry) goto fail;
    Inode *oldinode = inode_get(ctx, oldentry->ino);
    if (!oldinode) goto fail;
    Off newentryoff = dir_find(ctx, newdir, newbasename);
    Entry *newentry = dir_entry_get(ctx, newdir, newentryoff);
    Inode *newinode = newentry ? inode_get(ctx, newentry->ino) : NULL;
    if (newinode) {
        if (inode_is_dir(newinode)) {
            if (!inode_is_dir(oldinode)) {
                ctx_set_errno(ctx, EISDIR);
                goto fail;
            }
            if (!dir_is_empty(newinode)) {
                ctx_set_errno(ctx, ENOTEMPTY);
                goto fail;
            }
        } else {
            if (inode_is_dir(oldinode)) {
                ctx_set_errno(ctx, ENOTDIR);
                goto fail;
            }
        }
        newinode->ctime = ctx_time(ctx);
        inode_unlink(ctx, newdir, newinode);
        newentry->ino = oldinode->ino;
    } else {
        if (-1 == dir_add(ctx, newdir, newbasename, oldinode->ino)) goto fail;
    }
    inode_link(ctx, newdir, oldinode);
    if (!dir_remove(ctx, olddir, oldentryoff)) abort();
    inode_unlink(ctx, olddir, oldinode);
    olddir->ctime = ctx_time(ctx);
    olddir->mtime = ctx_time(ctx);
    newdir->ctime = ctx_time(ctx);
    newdir->mtime = ctx_time(ctx);
    // updating the ctime of renamed files is implementation defined
    oldinode->ctime = ctx_time(ctx);
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
}

ThinfsErrno thinfs_rmdir(Thinfs *fs, char const *path)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Path dirname, basename;
    path_split(path_from_cstr(path), &dirname, &basename);
    Inode *dir = inode_from_path(ctx, dirname);
    Off entryoff = dir_find(ctx, dir, basename);
    Inode *inode = inode_get(ctx, dir_entry_get(ctx, dir, entryoff)->ino);
    if (!dir_is_empty(inode)) {
        ctx_set_errno(ctx, ENOTEMPTY);
        goto fail;
    }
    if (!dir_remove(ctx, dir, entryoff)) abort();
    dir->ctime = dir->mtime = ctx_time(ctx);
    inode->ctime = ctx_time(ctx);
    inode_unlink(ctx, dir, inode);
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
}

Errno thinfs_symlink(Thinfs *fs, char const *target, char const *path, uid_t uid, gid_t gid)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Inode *inode = inode_create(ctx, path, S_IFLNK, 0, uid, gid);
    if (!inode) goto fail;
    size_t count = strlen(target);
    // TODO handle running out of space when writing the link
    if (count != data_write(ctx, inode->file_data, target, count, 0)) abort();
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
}

ThinfsErrno thinfs_truncate(Thinfs *fs, char const *path, off_t length)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (file_truncate(ctx, inode_from_path(ctx, path_from_cstr(path)), length))
        return ctx_commit(ctx);
    return ctx_abandon(ctx);
}

static uintmax_t count_set_bits(void const *buf_, uintmax_t bits)
{
    uintmax_t count = 0;
    char const *buf = buf_;
    for (size_t i = 0; i < bits / CHAR_BIT; ++i) {
        for (int j = 0; j < CHAR_BIT; ++j) {
            if ((buf[i] >> j) & 1) count++;
        }
    }
    for (int j = 0; j < bits % CHAR_BIT; ++j) {
        if ((buf[bits/CHAR_BIT] >> j) & 1) count++;
    }
    return count;
}

static Blkno bitmap_count_used(Ctx *ctx)
{
    return count_set_bits(bitmap_get(ctx), ctx_geo(ctx)->data_blocks);
}

ThinfsErrno thinfs_statvfs(Thinfs *fs, struct statvfs *buf)
{
    Ctx ctx[1] = {ctx_open(fs)};
    Blkno used_count = bitmap_count_used(ctx);
    size_t block_size = ctx_geo(ctx)->block_size;
    Blkno data_blocks = ctx_geo(ctx)->data_blocks;
    *buf = (struct statvfs) {
        .f_bsize = block_size,
        .f_frsize = block_size,
        .f_blocks = data_blocks,
        .f_bfree = data_blocks - used_count,
        .f_bavail = data_blocks - used_count,
        .f_namemax = NAME_MAX,
    };
    return ctx_commit(ctx);
}

ThinfsErrno thinfs_flush(Thinfs *fs, ThinfsFd fd)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (!fd_valid(ctx, fd)) {
        ctx_set_errno(ctx, EBADF);
        return ctx_abandon(ctx);
    }
    return ctx_commit(ctx);
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
    if (!inode_is_dir(inode)) {
        ctx_set_errno(ctx, ENOTDIR);
        goto fail;
    }
    Fd fd = fd_new(ctx, inode->ino);
    if (fd == -1) goto fail;
    return fd;
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
            Entry *entry = dir_entry_get(ctx, dir, off);
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
    Inode *inode = inode_get(ctx, fd_lookup(ctx, fd));
    if (!inode) goto fail;
    if (len == inode_file_data(inode)->size) goto done;
    data_truncate(ctx, inode_file_data(inode), len);
    inode->mtime = ctx_time(ctx);
    inode->ctime = ctx_time(ctx);
done:
    return ctx_commit(ctx);
fail:
    return ctx_abandon(ctx);
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

ThinfsErrno thinfs_bmap(Thinfs *fs, char const *path, size_t blocksize, uint64_t *idx)
{
    Ctx ctx[1] = {ctx_open(fs)};
    if (blocksize != ctx_geo(ctx)->block_size) abort();
    Inode *inode = inode_from_path(ctx, path_from_cstr(path));
    *idx = data_bmap(ctx, inode->file_data, *idx);
    return ctx_commit(ctx);
}

