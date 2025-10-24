#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secerr.h>
#include <stdio.h>
#include <string.h>

static void dump_hex(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS init failed: %d\n", PR_GetError());
        return 1;
    }

    const char* message = "classical-nss-hash-demo";
    unsigned char digest[32];
    unsigned int digest_len = 0;

    PK11Context* ctx = PK11_CreateDigestContext(SEC_OID_SHA256);
    if (!ctx) {
        fprintf(stderr, "CreateDigestContext failed: %d\n", PR_GetError());
        NSS_Shutdown();
        return 1;
    }

    if (PK11_DigestBegin(ctx) != SECSuccess ||
        PK11_DigestOp(ctx, (const unsigned char*)message, strlen(message)) != SECSuccess ||
        PK11_DigestFinal(ctx, digest, &digest_len, sizeof(digest)) != SECSuccess) {
        fprintf(stderr, "Digest operation failed: %d\n", PR_GetError());
        PK11_DestroyContext(ctx, PR_TRUE);
        NSS_Shutdown();
        return 1;
    }

    printf("SHA-256 digest (%u bytes):\n", digest_len);
    dump_hex(digest, digest_len);

    PK11_DestroyContext(ctx, PR_TRUE);
    NSS_Shutdown();
    return 0;
}
