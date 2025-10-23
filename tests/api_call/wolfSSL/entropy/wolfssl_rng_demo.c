#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>

int main(void) {
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) {
        printf("wc_InitRng failed\n");
        return 1;
    }

    unsigned char buf[32];
    if (wc_RNG_GenerateBlock(&rng, buf, sizeof(buf)) != 0) {
        printf("wc_RNG_GenerateBlock failed\n");
        wc_FreeRng(&rng);
        return 1;
    }

    printf("wolfSSL RNG sample:\n");
    for (size_t i = 0; i < sizeof(buf); ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    wc_FreeRng(&rng);
    return 0;
}
