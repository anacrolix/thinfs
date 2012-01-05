#include <sys/stat.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/statvfs.h>

typedef int ThinfsErrno;
typedef int ThinfsFd;
typedef struct Thinfs Thinfs;
typedef bool (*ThinfsFillDir)(void *data, char const *name, struct stat const *stbuf, off_t off);

bool thinfs_mkfs(int fd);

Thinfs *thinfs_mount(char const *path);
void thinfs_unmount(Thinfs *);

ThinfsErrno thinfs_chmod(Thinfs *, char const *path, mode_t mode);
ThinfsErrno thinfs_chown(Thinfs *, char const *path, uid_t uid, gid_t gid);
ThinfsErrno thinfs_close(Thinfs *, ThinfsFd fd);
ThinfsErrno thinfs_create(Thinfs *, char const *path, mode_t, uid_t, gid_t);
ThinfsErrno thinfs_fstat(Thinfs *, ThinfsFd fd, struct stat *buf);
ThinfsErrno thinfs_fsyncdir(Thinfs *, ThinfsFd, int dataonly);
ThinfsErrno thinfs_link(Thinfs *, char const *target, char const *path);
ThinfsErrno thinfs_stat(Thinfs *, char const *path, struct stat *buf);
ThinfsErrno thinfs_mkdir(Thinfs *, char const *path, mode_t mode, uid_t uid, gid_t gid);
ThinfsErrno thinfs_mknod(Thinfs *, char const *path, mode_t mode, dev_t dev, uid_t uid, gid_t gid);
ThinfsFd thinfs_open(Thinfs *, char const *path);
ssize_t thinfs_pread(Thinfs *, ThinfsFd fd, void *buf, size_t count, off_t);
ssize_t thinfs_pwrite(Thinfs *, ThinfsFd fd, void const *buf, size_t count, off_t);
ThinfsErrno thinfs_unlink(Thinfs *, char const *path);
ssize_t thinfs_readlink(Thinfs *, const char *path, char *buf, size_t bufsize);
ThinfsErrno thinfs_rename(Thinfs *, char const *oldpath, char const *newpath);
ThinfsErrno thinfs_rmdir(Thinfs *, char const *path);
ThinfsErrno thinfs_symlink(Thinfs *, char const *target, char const *path);
ThinfsErrno thinfs_truncate(Thinfs *, char const *path, off_t size);
ThinfsErrno thinfs_statvfs(Thinfs *, struct statvfs *);
ThinfsErrno thinfs_flush(Thinfs *, ThinfsFd);
ThinfsErrno thinfs_fsync(Thinfs *, ThinfsFd, int dataonly);
ThinfsErrno thinfs_setxattr(Thinfs *, char const *path, char const *name, char const *value, size_t size, int flags);
ssize_t thinfs_getxattr(Thinfs *, char const *path, char const *name, char *value, size_t size);
ssize_t thinfs_listxattr(Thinfs *, char const *path, char *list, size_t size);
ThinfsErrno thinfs_removexattr(Thinfs *, char const *path, char const *name);
ThinfsFd thinfs_opendir(Thinfs *, char const *path);
ThinfsErrno thinfs_readdir(Thinfs *, ThinfsFd, void *data, ThinfsFillDir, off_t);
ThinfsErrno thinfs_releasedir(Thinfs *, ThinfsFd);
ThinfsErrno thinfs_ftruncate(Thinfs *, ThinfsFd, off_t len);
ThinfsErrno thinfs_utimens(Thinfs *, char const *path, const struct timespec[2]);
