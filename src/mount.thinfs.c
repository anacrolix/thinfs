#include "thinfs_fuse.h"
#include "thinfs.h"
#include <fuse.h>
#include <fuse_opt.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage()
{
    fprintf(stderr,
"\n"
"thinfs-0.1\n"
"Copyright (C) 2012 Matt Joiner <anacrolix@gmail.com>\n"
"\n"
"Usage: %s <device|image_file> <mountpoint>\n"
"\n"
            , program_invocation_short_name);
    char *argv[] = {program_invocation_name, "-ho", NULL};
    fuse_main(2, argv, NULL, NULL);
}

enum {
    KEY_HELP,
};

int fuse_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    char const **fs_dev_path = data;
    switch (key) {
        case FUSE_OPT_KEY_NONOPT:
        if (!*fs_dev_path) {
            *fs_dev_path = arg;
            return 0;
        }
        return 1;
        case KEY_HELP:
        print_usage();
        exit(0);
        return -1;
        default:
        return 1;
    }
}

int main(int argc, char *argv[])
{
    struct fuse_args fuse_args = FUSE_ARGS_INIT(argc, argv);
    char const *fs_dev_path = NULL;
    // these options are hooked to replace fuse's
    struct fuse_opt const fuse_opts[] = {
        FUSE_OPT_KEY("-h", KEY_HELP),
        FUSE_OPT_KEY("--help", KEY_HELP),
        FUSE_OPT_END,
    };
    if (0 != fuse_opt_parse(&fuse_args, &fs_dev_path, fuse_opts, fuse_opt_proc)) {
        fprintf(stderr, "error parsing fuse opts\n");
        return 2;
    }
    if (!fs_dev_path) {
        fprintf(stderr, "no device path specified\n");
        return 2;
    }
    char const fsname_arg_prefix[] = "-ofsname=";
    char fsname_arg[sizeof fsname_arg_prefix + strlen(fs_dev_path)];
    strcpy(fsname_arg, fsname_arg_prefix);
    strcat(fsname_arg, fs_dev_path);
    fuse_opt_insert_arg(&fuse_args, 1, fsname_arg);
    fuse_opt_insert_arg(&fuse_args, 1, "-ouse_ino");
    fuse_opt_insert_arg(&fuse_args, 1, "-s");
    fuse_opt_insert_arg(&fuse_args, 1, "-osubtype=thinfs");
    Thinfs *fs = thinfs_mount(fs_dev_path);
    if (!fs) {
        fprintf(stderr, "failed to mount device\n");
        return 1;
    }
    fprintf(stderr, "arguments to fuse main:\n");
    for (int i = 0; i < fuse_args.argc; ++i)
        fprintf(stderr, "\t%s\n", fuse_args.argv[i]);
    if (0 != fuse_main(fuse_args.argc, fuse_args.argv, &thinfs_fuse_operations, fs)) {
        fprintf(stderr, "fuse main returned error\n");
        return 1;
    }
    return 0;
}
