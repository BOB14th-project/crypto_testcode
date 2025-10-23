#include <errno.h>
#include <linux/if_alg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int open_rng_socket(const char* rng_name) {
    int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket(AF_ALG)");
        return -1;
    }

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "rng",
    };

    strncpy((char*)sa.salg_name, rng_name, sizeof(sa.salg_name));

    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "bind rng:%s failed: %s\n", rng_name, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

int main(void) {
    const char* candidates[] = {"drbg_pr", "stdrng", "drbg_nopr"};
    int ctrl = -1;

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        ctrl = open_rng_socket(candidates[i]);
        if (ctrl >= 0) {
            printf("AF_ALG rng:%s bound successfully\n", candidates[i]);
            break;
        }
    }

    if (ctrl < 0) {
        fprintf(stderr, "No AF_ALG rng algorithm available\n");
        return 1;
    }

    int op = accept(ctrl, NULL, NULL);
    if (op < 0) {
        perror("accept rng");
        close(ctrl);
        return 1;
    }

    unsigned char buf[32];
    ssize_t n = read(op, buf, sizeof(buf));
    if (n < 0) {
        perror("read rng");
        close(op);
        close(ctrl);
        return 1;
    }

    printf("AF_ALG random sample (%zd bytes):\n", n);
    for (ssize_t i = 0; i < n; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    close(op);
    close(ctrl);
    return 0;
}
