#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secerr.h>
#include <stdio.h>

static void dump_hex(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS_NoDB_Init failed: %d\n", PR_GetError());
        return 1;
    }

    unsigned char random_bytes[32];
    if (PK11_GenerateRandom(random_bytes, sizeof(random_bytes)) != SECSuccess) {
        fprintf(stderr, "PK11_GenerateRandom failed: %d\n", PR_GetError());
        NSS_Shutdown();
        return 1;
    }

    printf("NSS random sample:\n");
    dump_hex(random_bytes, sizeof(random_bytes));

    NSS_Shutdown();
    return 0;
}
