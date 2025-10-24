#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

static void dump_hex(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    int ret = gnutls_global_init();
    if (ret < 0) {
        fprintf(stderr, "gnutls_global_init failed: %s\n", gnutls_strerror(ret));
        return 1;
    }

    unsigned char seed[32];
    ret = gnutls_rnd(GNUTLS_RND_RANDOM, seed, sizeof(seed));
    if (ret < 0) {
        fprintf(stderr, "gnutls_rnd failed: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    printf("GnuTLS random sample:\n");
    dump_hex(seed, sizeof(seed));

    gnutls_global_deinit();
    return 0;
}
