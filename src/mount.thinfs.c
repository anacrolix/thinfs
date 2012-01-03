#include "thinfs_fuse.h"
#include "thinfs.h"
#include <fuse.h>
#include <fuse_opt.h>
#include <stdio.h>

int fuse_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    char const **fs_dev_path = data;
    if (key == FUSE_OPT_KEY_NONOPT && !*fs_dev_path) {
        *fs_dev_path = arg;
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    struct fuse_args fuse_args = FUSE_ARGS_INIT(argc, argv);
    char const *fs_dev_path = NULL;
    if (0 != fuse_opt_parse(&fuse_args, &fs_dev_path, NULL, fuse_opt_proc)) {
        fprintf(stderr, "error parsing fuse opts\n");
        return 2;
    }
    if (!fs_dev_path) {
        fprintf(stderr, "no device path specified\n");
        return 2;
    }
    Thinfs *fs = thinfs_mount(fs_dev_path);
    if (!fs) {
        fprintf(stderr, "failed to mount device\n");
        return 1;
    }
    fprintf(stderr, "arguments to fuse main:\n");
    for (int i = 0; i < fuse_args.argc; ++i)
        fprintf(stderr, "\t%s\n", fuse_args.argv[i]);
    if (0 != fuse_main(fuse_args.argc, fuse_args.argv, &thinfs_fuse_operations, NULL)) {
        fprintf(stderr, "fuse main returned error\n");
        return 1;
    }
    return 0;
}
