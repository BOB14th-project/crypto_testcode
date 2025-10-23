#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <stdio.h>

int main(void) {
    wolfSSL_Init();

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) {
        printf("wolfSSL_CTX_new failed\n");
        wolfSSL_Cleanup();
        return 1;
    }

    wolfSSL_CTX_set_cipher_list(ctx, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);

    printf("wolfSSL configured for TLS 1.2 with AES-256-GCM.\n");

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
