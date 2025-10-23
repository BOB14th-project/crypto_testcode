#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    mbedtls_ecdsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "mbedtls-ecdsa-sign";

    mbedtls_ecdsa_init(&ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers, strlen(pers)) != 0) {
        printf("ctr_drbg_seed failed\n");
        goto cleanup;
    }

    if (mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1,
                             mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        printf("ecdsa_genkey failed\n");
        goto cleanup;
    }

    unsigned char hash[32] = {0};
    strcpy((char*)hash, "mbedtls-signature");

    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = 0;
    if (mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256,
                                      hash, 32, sig, &sig_len,
                                      mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        printf("write_signature failed\n");
        goto cleanup;
    }

    printf("ECDSA signature generated (len=%zu)\n", sig_len);
    if (mbedtls_ecdsa_read_signature(&ctx, hash, 32, sig, sig_len) == 0) {
        printf("Signature verification OK\n");
    } else {
        printf("Signature verification FAILED\n");
    }

cleanup:
    mbedtls_ecdsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return 0;
}
