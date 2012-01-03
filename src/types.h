#include <limits.h>
#include <stdint.h>

typedef ThinfsCtx Ctx;
typedef unsigned short Type;

typedef struct {
    uint64_t block_count;
    uint64_t block_size;
} MBR;

typedef struct {
    uint64_t bitmap_start;
    uint64_t bitmap_count;
    uint64_t data_start;
    uint64_t data_count;
    uint64_t block_size;
    uint64_t bitmap_density;
    uint64_t block_count;
    long page_size;
} Geometry;

typedef struct {
    uint64_t secs;
    uint64_t nanos;
} Time;

typedef uint64_t Blkno;
typedef Blkno Ino;
typedef int32_t Nlink;
typedef uint32_t Uid;
typedef uint32_t Gid;

typedef struct {
    Blkno root;
    uint64_t size;
} Data;

typedef struct {
    Ino ino;
    char name[NAME_MAX];
} Dentry;

typedef struct {
    Ino ino;
    Nlink nlink;
    Uid uid;
    Gid gid;
    Type type;
    Time atime;
    Time mtime;
    Time ctime;
    Data file_data;
} Inode;
