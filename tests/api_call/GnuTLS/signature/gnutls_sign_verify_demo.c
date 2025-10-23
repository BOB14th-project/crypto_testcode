#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <string.h>

static void dump_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    const char* message = "classical-algorithm-demo";
    gnutls_datum_t msg = {(unsigned char*)message, (unsigned)strlen(message)};

    if (gnutls_global_init() < 0) {
        fprintf(stderr, "gnutls_global_init failed\n");
        return 1;
    }

    gnutls_x509_privkey_t xpriv;
    if (gnutls_x509_privkey_init(&xpriv) < 0) {
        fprintf(stderr, "x509 privkey init failed\n");
        gnutls_global_deinit();
        return 1;
    }

    if (gnutls_x509_privkey_generate(xpriv, GNUTLS_PK_RSA, 2048, 0) < 0) {
        fprintf(stderr, "privkey generate failed\n");
        gnutls_x509_privkey_deinit(xpriv);
        gnutls_global_deinit();
        return 1;
    }

    gnutls_privkey_t priv;
    if (gnutls_privkey_init(&priv) < 0) {
        fprintf(stderr, "privkey init failed\n");
        gnutls_x509_privkey_deinit(xpriv);
        gnutls_global_deinit();
        return 1;
    }
    if (gnutls_privkey_import_x509(priv, xpriv, 0) < 0) {
        fprintf(stderr, "privkey import failed\n");
        gnutls_privkey_deinit(priv);
        gnutls_x509_privkey_deinit(xpriv);
        gnutls_global_deinit();
        return 1;
    }

    gnutls_datum_t sig = {0};
    if (gnutls_privkey_sign_data(priv, GNUTLS_DIG_SHA256, 0, &msg, &sig) < 0) {
        fprintf(stderr, "sign_data failed\n");
        gnutls_privkey_deinit(priv);
        gnutls_x509_privkey_deinit(xpriv);
        gnutls_global_deinit();
        return 1;
    }

    printf("Signature (%u bytes):\n", sig.size);
    dump_hex(sig.data, sig.size);

    gnutls_pubkey_t pub;
    if (gnutls_pubkey_init(&pub) < 0) {
        fprintf(stderr, "pubkey init failed\n");
        gnutls_free(sig.data);
        gnutls_privkey_deinit(priv);
        gnutls_x509_privkey_deinit(xpriv);
        gnutls_global_deinit();
        return 1;
    }
    if (gnutls_pubkey_import_privkey(pub, priv, GNUTLS_KEY_DIGITAL_SIGNATURE, 0, 0) < 0) {
        fprintf(stderr, "pubkey import failed\n");
        gnutls_pubkey_deinit(pub);
        gnutls_free(sig.data);
        gnutls_privkey_deinit(priv);
        gnutls_x509_privkey_deinit(xpriv);
        gnutls_global_deinit();
        return 1;
    }

    int verify = gnutls_pubkey_verify_data2(pub, GNUTLS_SIGN_RSA_SHA256, 0, &msg, &sig);
    printf("Verify result: %s\n", verify >= 0 ? "OK" : "FAILED");

    gnutls_pubkey_deinit(pub);
    gnutls_free(sig.data);
    gnutls_privkey_deinit(priv);
    gnutls_x509_privkey_deinit(xpriv);
    gnutls_global_deinit();
    return verify >= 0 ? 0 : 1;
}
