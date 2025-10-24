#include <gnutls/gnutls.h>
#include <stdio.h>

int main(void) {
    if (gnutls_global_init() < 0) {
        fprintf(stderr, "gnutls_global_init failed\n");
        return 1;
    }

    gnutls_priority_t priority;
    const char* err = NULL;
    int ret = gnutls_priority_init(&priority, "NONE:+VERS-TLS1.2:+CIPHER-AES-256-GCM:+SIGN-RSA-SHA256:+KX-RSA", &err);
    if (ret < 0) {
        fprintf(stderr, "priority init failed at: %s (%s)\n", err ? err : "n/a", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    unsigned idx = 0;
    printf("Enabled key exchanges:\n");
    for (;;) {
        gnutls_kx_algorithm_t kx = gnutls_priority_get_kx(priority, idx++);
        if (kx == GNUTLS_KX_UNKNOWN) {
            break;
        }
        printf(" - %s\n", gnutls_kx_get_name(kx));
    }

    idx = 0;
    printf("Enabled signature algorithms:\n");
    for (;;) {
        gnutls_sign_algorithm_t sig = gnutls_priority_get_sig(priority, idx++);
        if (sig == GNUTLS_SIGN_UNKNOWN) {
            break;
        }
        printf(" - %s\n", gnutls_sign_get_name(sig));
    }

    gnutls_priority_deinit(priority);
    gnutls_global_deinit();
    return 0;
}
