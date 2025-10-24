#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <string.h>

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

    const char* password = "classical-password";
    const unsigned char salt_data[] = "salt";

    gnutls_datum_t pwd = {(unsigned char*)password, (unsigned)strlen(password)};
    gnutls_datum_t salt = {(unsigned char*)salt_data, sizeof(salt_data) - 1};

    unsigned char out[32];
    ret = gnutls_pbkdf2(GNUTLS_MAC_SHA256, &pwd, &salt, 10000, out, sizeof(out));
    if (ret < 0) {
        fprintf(stderr, "gnutls_pbkdf2 failed: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    printf("PBKDF2-HMAC-SHA256 (10k iters):\n");
    dump_hex(out, sizeof(out));

    gnutls_global_deinit();
    return 0;
}
