#include "thinfs.h"
#include <fcntl.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "wrong number of arguments\n");
        return 2;
    }
    int fd = open(argv[1], O_RDWR);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    if (!thinfs_mkfs(fd)) {
        fprintf(stderr, "error making filesystem\n");
        return 1;
    }
    return 0;
}
