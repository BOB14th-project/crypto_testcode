#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <secerr.h>
#include <secoidt.h>
#include <secitem.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char* message = "nss-signature-demo";

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

    PK11RSAGenParams params = {2048, 0x10001};
    SECKEYPublicKey* pub = NULL;
    SECKEYPrivateKey* priv = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN,
                                                 &params, &pub, PR_FALSE, PR_TRUE, NULL);
    if (!priv) {
        fprintf(stderr, "RSA keygen failed: %d\n", PR_GetError());
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    SECItem signature = {siBuffer, NULL, 0};
    SECItem data = {siBuffer, (unsigned char*)message, (unsigned int)strlen(message)};

    if (SEC_SignData(&signature, data.data, data.len, priv,
                     SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION) != SECSuccess) {
        fprintf(stderr, "SignData failed: %d\n", PR_GetError());
        SECKEY_DestroyPrivateKey(priv);
        SECKEY_DestroyPublicKey(pub);
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    printf("Signature size: %u bytes\n", signature.len);

    if (VFY_VerifyData(data.data, data.len, pub, &signature,
                       SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION, NULL) != SECSuccess) {
        fprintf(stderr, "VerifyData failed: %d\n", PR_GetError());
        SECITEM_FreeItem(&signature, PR_FALSE);
        SECKEY_DestroyPrivateKey(priv);
        SECKEY_DestroyPublicKey(pub);
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    printf("Signature verification: OK\n");

    SECITEM_FreeItem(&signature, PR_FALSE);
    SECKEY_DestroyPrivateKey(priv);
    SECKEY_DestroyPublicKey(pub);
    PK11_FreeSlot(slot);
    NSS_Shutdown();
    return 0;
}
