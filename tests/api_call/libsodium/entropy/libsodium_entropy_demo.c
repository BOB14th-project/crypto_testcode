#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    unsigned char buf[32];
    randombytes_buf(buf, sizeof(buf));

    printf("libsodium randombytes sample:\n");
    for (size_t i = 0; i < sizeof(buf); ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    return 0;
}
