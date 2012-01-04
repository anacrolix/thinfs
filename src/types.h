#include <inttypes.h>
#include <limits.h>
#include <stdint.h>

typedef unsigned short Type;
typedef unsigned short Perms;
typedef int64_t Blkno;
#define PRIBLKNO PRIu64
typedef Blkno Ino;
#define PRIINO PRIBLKNO
typedef int32_t Nlink;
typedef uint32_t Uid;
typedef uint32_t Gid;
typedef uint8_t Depth;
typedef uint32_t Rdev;

typedef struct {
    uint64_t block_count;
    uint64_t block_size;
} MBR;

typedef struct {
    uint64_t bitmap_start;
    Blkno bitmap_blocks;
    uint64_t data_start;
    Blkno data_blocks;
    uint64_t block_size;
    uint64_t bitmap_density;
    uint64_t block_count;
    long page_size;
} Geometry;

typedef struct {
    uint64_t secs;
    uint32_t nanos;
} Time;


typedef struct {
    Blkno root;
    uint64_t size;
    Depth depth;
} Data;

typedef struct {
    Ino ino;
    char name[NAME_MAX];
} Entry;

typedef struct {
    Ino ino;
    Nlink nlink;
    Type type;
    Perms perms;
    Uid uid;
    Gid gid;
    Rdev rdev;
    Data file_data[1];
    Time atime;
    Time mtime;
    Time ctime;
} Inode;
