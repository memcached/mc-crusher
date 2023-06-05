#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: balloon [megabytes]\n");
        exit(1);
    }
    // autoflush stdout.
    setvbuf(stdout, NULL, _IONBF, 0);

    int size = atoi(argv[1]);
    printf("megabytes: %d\n", size);

    int x;
    for (x = 0; x < size; x++) {
        // We're going to leak this.
        uint64_t *temp = calloc(1, 1024 * 1024);
        if (temp == NULL) {
            fprintf(stderr, "Failed to calloc chunk #%d\n", x);
            exit(1);
        }
        int i;
        // Fill a bit harder to ensure RAM gets allocated
        for (i = 0; i < (1024*1024) / sizeof(uint64_t); i++) {
            temp[i] = i;
        }
    }
    printf("done.\n");

    pause();
}
