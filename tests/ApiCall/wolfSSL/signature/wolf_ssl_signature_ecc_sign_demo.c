#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>
#include <string.h>

int main(void) {
    WC_RNG rng;
    ecc_key key;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte sig[256];
    word32 sig_len = sizeof(sig);

    wc_InitRng(&rng);
    wc_ecc_init(&key);

    if (wc_ecc_make_key(&rng, 32, &key) != 0) {
        printf("wc_ecc_make_key failed\n");
        goto cleanup;
    }

    const char* message = "wolfssl-signature-demo";
    wc_Sha256Hash((const byte*)message, (word32)strlen(message), hash);

    if (wc_ecc_sign_hash(hash, sizeof(hash), sig, &sig_len, &rng, &key) != 0) {
        printf("wc_ecc_sign_hash failed\n");
        goto cleanup;
    }

    int verify = wc_ecc_verify_hash(sig, sig_len, hash, sizeof(hash), NULL, &key);
    printf("Signature verification result: %s (len=%u)\n",
           verify == 1 ? "OK" : "FAIL", sig_len);

cleanup:
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    return 0;
}
