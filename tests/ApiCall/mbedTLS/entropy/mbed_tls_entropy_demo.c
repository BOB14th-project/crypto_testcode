#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "mbedtls-entropy-demo";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers, strlen(pers)) != 0) {
        printf("ctr_drbg_seed failed\n");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return 1;
    }

    unsigned char buf[32];
    if (mbedtls_ctr_drbg_random(&ctr_drbg, buf, sizeof(buf)) != 0) {
        printf("ctr_drbg_random failed\n");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return 1;
    }

    printf("mbedTLS CTR-DRBG sample:\n");
    for (size_t i = 0; i < sizeof(buf); ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return 0;
}
