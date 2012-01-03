#include "thinfs_fuse.h"
#include "thinfs.h"

typedef ThinfsCtx Ctx;

static Thinfs *get_fs() {
    return fuse_get_context()->private_data;
}

static int thinfs_fuse_getattr(const char *path, struct stat *stat)
{
    Ctx *ctx = thinfs_ctx_new(get_fs());
    ThinfsFd fd = thinfs_open(ctx, path);
    thinfs_fstat(ctx, fd, stat);
    return -thinfs_ctx_commit(ctx);
}

static int thinfs_fuse_readlink(const char *path, char *link, size_t size)
{
    Ctx *ctx = thinfs_ctx_new(get_fs());
    thinfs_readlink(ctx, path, link, size);
    return -thinfs_ctx_commit(ctx);
}

struct fuse_operations thinfs_fuse_operations = {
    .getattr = thinfs_fuse_getattr,
    .readlink = thinfs_fuse_readlink,
};
