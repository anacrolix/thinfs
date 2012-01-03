#include <sys/stat.h>
#include <stdbool.h>

typedef int ThinfsErrno;
typedef int ThinfsFd;
typedef struct Thinfs Thinfs;
typedef struct ThinfsCtx ThinfsCtx;

bool thinfs_mkfs(int fd);

Thinfs *thinfs_mount(char const *path);
void thinfs_unmount(Thinfs *);

ThinfsCtx *thinfs_ctx_new(Thinfs *);
bool thinfs_ctx_commit(ThinfsCtx *);
void thinfs_ctx_free(ThinfsCtx *);

ThinfsErrno thinfs_open(ThinfsCtx *, char const *path, ThinfsFd *);
ThinfsErrno thinfs_close(ThinfsCtx *, ThinfsFd fd);
ThinfsErrno thinfs_fstat(ThinfsCtx *, ThinfsFd fd, struct stat *buf);
