#include "thinfs_fuse.h"
#include "thinfs.h"

typedef ThinfsCtx Ctx;

Thinfs *get_fs() {
    return fuse_get_context()->private_data;
}

int fuse_getattr(const char *path, struct stat *stat)
{
    Ctx *ctx = thinfs_ctx_new(get_fs());
    ThinfsFd fd = thinfs_open(ctx, path);
    ThinfsErrno e = thinfs_open(ctx, path, &fd);
    if (e) return -e;
    e = thinfs_fstat(ctx, fd, stat);
    if (e) {
        thinfs_close(ctx, fd);
        return -e;
    }
    return -thinfs_close(ctx, fd);
}

struct fuse_operations thinfs_fuse_operations = {
    .getattr = fuse_getattr,
};
