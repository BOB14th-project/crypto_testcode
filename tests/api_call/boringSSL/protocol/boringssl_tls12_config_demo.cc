#include <openssl/ssl.h>

#include <cstdio>

int main() {
    if (!SSL_library_init()) {
        std::fprintf(stderr, "SSL_library_init failed\n");
        return 1;
    }

    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    if (!ctx) {
        std::fprintf(stderr, "SSL_CTX_new failed\n");
        return 1;
    }

    if (!SSL_CTX_set_min_proto_version(ctx.get(), TLS1_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx.get(), TLS1_2_VERSION)) {
        std::fprintf(stderr, "Failed to restrict protocol range\n");
        return 1;
    }

    SSL_CTX_set_cipher_list(ctx.get(), "AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");

    std::printf("Configured TLS 1.0 - TLS 1.2 only, AES-256-GCM suites.\n");
    return 0;
}
