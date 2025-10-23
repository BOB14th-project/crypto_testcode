#include <sodium.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    const char* password = "classical-password";
    unsigned char out[32];
    unsigned char salt[crypto_pwhash_SALTBYTES] = {0};
    memset(salt, 0x42, sizeof(salt));

    if (crypto_pwhash(out, sizeof(out),
                      password, strlen(password), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "crypto_pwhash failed\n");
        return 1;
    }

    printf("libsodium crypto_pwhash output:\n");
    for (size_t i = 0; i < sizeof(out); ++i) {
        printf("%02x", out[i]);
    }
    printf("\n");
    return 0;
}
