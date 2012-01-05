#include "thinfs_fuse.h"
#include "thinfs.h"

static Thinfs *get_fs()
{
    return fuse_get_context()->private_data;
}

static uid_t get_uid()
{
    return fuse_get_context()->uid;
}

static gid_t get_gid()
{
    return fuse_get_context()->gid;
}

static int thinfs_fuse_getattr(const char *path, struct stat *stat)
{
    return -thinfs_stat(get_fs(), path, stat);
}

static int thinfs_fuse_readlink(const char *path, char *link, size_t size)
{
    ssize_t rv = thinfs_readlink(get_fs(), path, link, size - 1);
    if (rv < 0) return rv;
    link[rv] = '\0';
    return 0;
}

static int thinfs_fuse_mknod(char const *path, mode_t mode, dev_t dev)
{
    return -thinfs_mknod(get_fs(), path, mode, dev, get_uid(), get_gid());
}

static int thinfs_fuse_mkdir(char const *path, mode_t mode)
{
    return -thinfs_mkdir(get_fs(), path, mode, get_uid(), get_gid());
}

static int thinfs_fuse_unlink(char const *path)
{
    return -thinfs_unlink(get_fs(), path);
}

static int thinfs_fuse_rmdir(char const *path)
{
    return -thinfs_rmdir(get_fs(), path);
}

static int thinfs_fuse_symlink(char const *target, char const *path)
{
    return -thinfs_symlink(get_fs(), target, path);
}

static int thinfs_fuse_rename(char const *oldpath, char const *newpath)
{
    return -thinfs_rename(get_fs(), oldpath, newpath);
}

static int thinfs_fuse_link(char const *target, char const *path)
{
    return -thinfs_link(get_fs(), target, path);
}

static int thinfs_fuse_chmod(char const *path, mode_t mode)
{
    return -thinfs_chmod(get_fs(), path, mode);
}

static int thinfs_fuse_chown(char const *path, uid_t uid, gid_t gid)
{
    return -thinfs_chown(get_fs(), path, uid, gid);
}

static int thinfs_fuse_truncate(char const *path, off_t size)
{
    return -thinfs_truncate(get_fs(), path, size);
}

static int thinfs_fuse_open(char const *path, struct fuse_file_info *ffi)
{
    ThinfsFd fd = thinfs_open(get_fs(), path);
    if (fd < 0) return fd;
    ffi->fh = fd + 1;
    ffi->direct_io = 1;
    return 0;
}

static int thinfs_fuse_read(char const *path, char *buf, size_t count, off_t off, struct fuse_file_info *ffi)
{
    return thinfs_pread(get_fs(), ffi->fh - 1, buf, count, off);
}

static int thinfs_fuse_write(char const *path, char const *buf, size_t count, off_t off, struct fuse_file_info *ffi)
{
    return thinfs_pwrite(get_fs(), ffi->fh - 1, buf, count, off);
}

int thinfs_fuse_statfs(char const *path, struct statvfs *buf)
{
    return -thinfs_statvfs(get_fs(), buf);
}

int thinfs_fuse_flush(char const *path, struct fuse_file_info *ffi)
{
    return -thinfs_flush(get_fs(), ffi->fh - 1);
}

int thinfs_fuse_release(char const *path, struct fuse_file_info *ffi)
{
    return -thinfs_close(get_fs(), ffi->fh - 1);
}

int thinfs_fuse_fsync(char const *path, int dataonly, struct fuse_file_info *ffi)
{
    return -thinfs_fsync(get_fs(), ffi->fh - 1, dataonly);
}

//~ int thinfs_fuse_setxattr(char const *path, char const *name, char const *value, size_t size, int flags)
//~ {
    //~ return -thinfs_setxattr(get_fs(), path, name, value, size, flags);
//~ }
//~
//~ int thinfs_fuse_getxattr(char const *path, char const *name, char *value, size_t size)
//~ {
    //~ return thinfs_getxattr(get_fs(), path, name, value, size);
//~ }
//~
//~ int thinfs_fuse_listxattr(char const *path, char *list, size_t size)
//~ {
    //~ return thinfs_listxattr(get_fs(), path, list, size);
//~ }
//~
//~ int thinfs_fuse_removexattr(char const *path, char const *name)
//~ {
    //~ return -thinfs_removexattr(get_fs(), path, name);
//~ }

int thinfs_fuse_opendir(char const *path, struct fuse_file_info *ffi)
{
    ThinfsFd fd = thinfs_opendir(get_fs(), path);
    if (fd < 0) return fd;
    ffi->fh = fd + 1;
    ffi->direct_io = 1;
    return 0;
}

typedef struct {
    fuse_fill_dir_t filler;
    void *fuse_buf;
} ThinfsFuseFillDirBuf;

static bool thinfs_fuse_fill_dir(void *data, char const *name, struct stat const *stbuf, off_t off)
{
    ThinfsFuseFillDirBuf *buf = data;
    return !buf->filler(buf->fuse_buf, name, stbuf, off);
}

int thinfs_fuse_readdir(char const *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *ffi)
{
    ThinfsFuseFillDirBuf thinfs_buf = {
        .filler = filler,
        .fuse_buf = buf,
    };
    return -thinfs_readdir(get_fs(), ffi->fh - 1, &thinfs_buf, thinfs_fuse_fill_dir, off);
}

int thinfs_fuse_releasedir(char const *path, struct fuse_file_info *ffi)
{
    return -thinfs_releasedir(get_fs(), ffi->fh - 1);
}

int thinfs_fuse_fsyncdir(char const *path, int dataonly, struct fuse_file_info *ffi)
{
    return -thinfs_fsyncdir(get_fs(), ffi->fh - 1, dataonly);
}

void *thinfs_fuse_init(struct fuse_conn_info *conn)
{
    return get_fs();
}

void thinfs_fuse_destroy(void *data)
{
    thinfs_unmount(data);
}

int thinfs_fuse_create(char const *path, mode_t mode, struct fuse_file_info *ffi)
{
    ThinfsFd fd = thinfs_create(get_fs(), path, mode, get_uid(), get_gid());
    if (fd < 0) return fd;
    ffi->fh = fd + 1;
    ffi->direct_io = 1;
    return 0;
}

int thinfs_fuse_ftruncate(char const *path, off_t size, struct fuse_file_info *ffi)
{
    return -thinfs_ftruncate(get_fs(), ffi->fh - 1, size);
}

int thinfs_fuse_fgetattr(char const *path, struct stat *buf, struct fuse_file_info *ffi)
{
    return -thinfs_fstat(get_fs(), ffi->fh - 1, buf);
}

int thinfs_fuse_utimens(char const *path, struct timespec const tv[2])
{
    return -thinfs_utimens(get_fs(), path, tv);
}

struct fuse_operations thinfs_fuse_operations = {
    .getattr = thinfs_fuse_getattr,
    .readlink = thinfs_fuse_readlink,
    .mknod = thinfs_fuse_mknod,
    .mkdir = thinfs_fuse_mkdir,
    .unlink = thinfs_fuse_unlink,
    .rmdir = thinfs_fuse_rmdir,
    .symlink = thinfs_fuse_symlink,
    .rename = thinfs_fuse_rename,
    .link = thinfs_fuse_link,
    .chmod = thinfs_fuse_chmod,
    .chown = thinfs_fuse_chown,
    .truncate = thinfs_fuse_truncate,
    // .utime deprecated by utimens
    .open = thinfs_fuse_open,
    .read = thinfs_fuse_read,
    .write = thinfs_fuse_write,
    .statfs = thinfs_fuse_statfs,
    .flush = thinfs_fuse_flush,
    .release = thinfs_fuse_release,
    .fsync = thinfs_fuse_fsync,
    //~ .setxattr = thinfs_fuse_setxattr,
    //~ .getxattr = thinfs_fuse_getxattr,
    //~ .listxattr = thinfs_fuse_listxattr,
    //~ .removexattr = thinfs_fuse_removexattr,
    .opendir = thinfs_fuse_opendir,
    .readdir = thinfs_fuse_readdir,
    .releasedir = thinfs_fuse_releasedir,
    .fsyncdir = thinfs_fuse_fsyncdir,
    .init = thinfs_fuse_init,
    .destroy = thinfs_fuse_destroy,
    // .access not implemented
    .create = thinfs_fuse_create,
    .ftruncate = thinfs_fuse_ftruncate,
    .fgetattr = thinfs_fuse_fgetattr,
    // .lock is for network filesystems
    .utimens = thinfs_fuse_utimens,
    // .bmap not implemented
    .flag_nullpath_ok = 1,
    // .ioctl not unimplemented
    // .poll: backing device is always ready
};
