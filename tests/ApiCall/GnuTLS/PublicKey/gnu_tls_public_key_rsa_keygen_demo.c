#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>

int main(void) {
    int ret = gnutls_global_init();
    if (ret < 0) {
        fprintf(stderr, "init failed: %s\n", gnutls_strerror(ret));
        return 1;
    }

    gnutls_x509_privkey_t priv;
    ret = gnutls_x509_privkey_init(&priv);
    if (ret < 0) {
        fprintf(stderr, "privkey init failed: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    ret = gnutls_x509_privkey_generate(priv, GNUTLS_PK_RSA, 2048, 0);
    if (ret < 0) {
        fprintf(stderr, "RSA generate failed: %s\n", gnutls_strerror(ret));
        gnutls_x509_privkey_deinit(priv);
        gnutls_global_deinit();
        return 1;
    }

    gnutls_datum_t m = {0}, e = {0};
    ret = gnutls_x509_privkey_export_rsa_raw(priv, &m, &e, NULL, NULL, NULL, NULL);
    if (ret < 0) {
        fprintf(stderr, "export rsa raw failed: %s\n", gnutls_strerror(ret));
        gnutls_x509_privkey_deinit(priv);
        gnutls_global_deinit();
        return 1;
    }

    printf("Generated RSA modulus bits: %u\n", (unsigned)m.size * 8);
    printf("Public exponent: 0x");
    for (unsigned i = 0; i < e.size; ++i) {
        printf("%02x", e.data[i]);
    }
    printf("\n");

    gnutls_free(m.data);
    gnutls_free(e.data);
    gnutls_x509_privkey_deinit(priv);
    gnutls_global_deinit();
    return 0;
}
