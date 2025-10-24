#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE* fp = fopen("/proc/crypto", "r");
    if (!fp) {
        fprintf(stderr, "Failed to open /proc/crypto: %s\n", strerror(errno));
        return 1;
    }

    char* line = NULL;
    size_t len = 0;
    printf("Listing AF_ALG algorithms (type/name/prio):\n");

    char type[64] = {0};
    char name[128] = {0};
    char prio[32] = {0};

    while (getline(&line, &len, fp) != -1) {
        if (sscanf(line, "type : %63s", type) == 1) {
            name[0] = '\0';
            prio[0] = '\0';
        } else if (sscanf(line, "name : %127s", name) == 1) {
            continue;
        } else if (sscanf(line, "priority : %31s", prio) == 1) {
            if (type[0] && name[0]) {
                printf(" - %-10s %-30s priority=%s\n", type, name, prio);
            }
        }
    }

    free(line);
    fclose(fp);
    return 0;
}
