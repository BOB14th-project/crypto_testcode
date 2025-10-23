#include <errno.h>
#include <linux/if_alg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef ALG_OP_SIGN
#define ALG_OP_SIGN 2
#endif
#ifndef ALG_OP_VERIFY
#define ALG_OP_VERIFY 3
#endif

static void try_operation(int fd, int op, const char* name) {
    if (setsockopt(fd, SOL_ALG, ALG_SET_OP, &op, sizeof(op)) < 0) {
        printf("ALG_SET_OP (%s) failed: %s\n", name, strerror(errno));
    } else {
        printf("ALG_SET_OP (%s) accepted\n", name);
    }
}

int main(void) {
    int ctrl = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (ctrl < 0) {
        perror("socket(AF_ALG)");
        return 1;
    }

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "akcipher",
    };
    strncpy((char*)sa.salg_name, "rsa", sizeof(sa.salg_name));

    if (bind(ctrl, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        printf("bind akcipher:rsa failed: %s\n", strerror(errno));
        printf("This system may lack kernel RSA support; continuing with probe.\n");
    } else {
        printf("akcipher:rsa bound successfully.\n");
    }

    try_operation(ctrl, ALG_OP_SIGN, "sign");
    try_operation(ctrl, ALG_OP_VERIFY, "verify");

    unsigned char mock_digest[32] = {0};
    unsigned char dummy_key[32] = {0};

    if (setsockopt(ctrl, SOL_ALG, ALG_SET_PUBKEY, dummy_key, sizeof(dummy_key)) < 0) {
        printf("ALG_SET_PUBKEY (mock) failed as expected: %s\n", strerror(errno));
    } else {
        printf("ALG_SET_PUBKEY (mock) succeeded (unexpected)\n");
    }

    int opfd = accept(ctrl, NULL, NULL);
    if (opfd < 0) {
        printf("accept failed: %s\n", strerror(errno));
    } else {
        ssize_t sent = send(opfd, mock_digest, sizeof(mock_digest), 0);
        if (sent < 0) {
            printf("send digest failed: %s\n", strerror(errno));
        } else {
            printf("Sent %zd bytes for signature operation\n", sent);
        }
        close(opfd);
    }

    close(ctrl);
    return 0;
}
