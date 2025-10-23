#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>
#include <memory>
#include <vector>

namespace {
struct EVPKeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct EVPKeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
using EVPKeyPtr = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;
using EVPKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EVPKeyCtxDeleter>;
}  // namespace

static EVPKeyPtr generate_p256_key() {
    EVPKeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return nullptr;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) return nullptr;
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) return nullptr;
    return EVPKeyPtr(raw);
}

int main() {
    EVPKeyPtr alice = generate_p256_key();
    EVPKeyPtr bob = generate_p256_key();
    if (!alice || !bob) {
        std::fprintf(stderr, "EC key generation failed\n");
        return 1;
    }

    EVPKeyCtxPtr derive(EVP_PKEY_CTX_new(alice.get(), nullptr));
    if (!derive) {
        std::fprintf(stderr, "derive ctx alloc failed\n");
        return 1;
    }
    if (EVP_PKEY_derive_init(derive.get()) <= 0 ||
        EVP_PKEY_derive_set_peer(derive.get(), bob.get()) <= 0) {
        std::fprintf(stderr, "derive init failed\n");
        return 1;
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(derive.get(), nullptr, &secret_len) <= 0) {
        std::fprintf(stderr, "derive length failed\n");
        return 1;
    }

    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(derive.get(), secret.data(), &secret_len) <= 0) {
        std::fprintf(stderr, "derive failed\n");
        return 1;
    }

    std::printf("ECDH shared secret (%zu bytes):\n", secret_len);
    for (size_t i = 0; i < secret_len; ++i) {
        std::printf("%02x", secret[i]);
    }
    std::printf("\n");
    return 0;
}
