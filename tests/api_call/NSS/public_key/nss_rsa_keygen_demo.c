#include <nss.h>
#include <pk11pub.h>
#include <secerr.h>
#include <sechash.h>
#include <keyhi.h>
#include <stdio.h>

int main(void) {
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS init failed: %d\n", PR_GetError());
        return 1;
    }

    PK11SlotInfo* slot = PK11_GetInternalKeySlot();
    if (!slot) {
        fprintf(stderr, "GetInternalKeySlot failed: %d\n", PR_GetError());
        NSS_Shutdown();
        return 1;
    }

    SECKEYPublicKey* pub = NULL;
    SECKEYPrivateKey* priv = SECKEY_CreateRSAPrivateKey(slot, 2048, &pub, PR_TRUE, PR_TRUE, NULL);
    if (!priv) {
        fprintf(stderr, "RSA keygen failed: %d\n", PR_GetError());
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    printf("Generated RSA modulus bits: %u\n", SECKEY_PublicKeyStrengthInBits(pub));

    SECKEY_DestroyPrivateKey(priv);
    SECKEY_DestroyPublicKey(pub);
    PK11_FreeSlot(slot);
    NSS_Shutdown();
    return 0;
}
