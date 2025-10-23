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
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
using EVPKeyPtr = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;
using EVP_MD_CtxPtr = std::unique_ptr<EVP_MD_CTX, EVPKeyCtxDeleter>;
}  // namespace

int main() {
    EVPKeyPtr key;
    {
        EVP_PKEY_CTX* gen = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!gen) {
            std::fprintf(stderr, "ctx new failed\n");
            return 1;
        }
        if (EVP_PKEY_keygen_init(gen) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(gen, NID_X9_62_prime256v1) <= 0) {
            std::fprintf(stderr, "keygen init failed\n");
            EVP_PKEY_CTX_free(gen);
            return 1;
        }
        EVP_PKEY* raw = nullptr;
        if (EVP_PKEY_keygen(gen, &raw) <= 0) {
            std::fprintf(stderr, "keygen failed\n");
            EVP_PKEY_CTX_free(gen);
            return 1;
        }
        key.reset(raw);
        EVP_PKEY_CTX_free(gen);
    }

    const unsigned char message[] = "boringssl-signature";
    EVP_MD_CtxPtr sign(EVP_MD_CTX_new());
    if (!sign) {
        std::fprintf(stderr, "md ctx alloc failed\n");
        return 1;
    }

    if (EVP_DigestSignInit(sign.get(), nullptr, EVP_sha256(), nullptr, key.get()) <= 0 ||
        EVP_DigestSignUpdate(sign.get(), message, sizeof(message) - 1) <= 0) {
        std::fprintf(stderr, "DigestSign init/update failed\n");
        return 1;
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(sign.get(), nullptr, &sig_len) <= 0) {
        std::fprintf(stderr, "DigestSignFinal size failed\n");
        return 1;
    }

    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(sign.get(), signature.data(), &sig_len) <= 0) {
        std::fprintf(stderr, "DigestSignFinal failed\n");
        return 1;
    }
    signature.resize(sig_len);

    EVP_MD_CtxPtr verify(EVP_MD_CTX_new());
    if (!verify) {
        std::fprintf(stderr, "verify ctx alloc failed\n");
        return 1;
    }
    if (EVP_DigestVerifyInit(verify.get(), nullptr, EVP_sha256(), nullptr, key.get()) <= 0 ||
        EVP_DigestVerifyUpdate(verify.get(), message, sizeof(message) - 1) <= 0) {
        std::fprintf(stderr, "DigestVerify init/update failed\n");
        return 1;
    }
    int ok = EVP_DigestVerifyFinal(verify.get(), signature.data(), signature.size());
    std::printf("ECDSA verify: %s (signature len %zu)\n", ok == 1 ? "OK" : "FAIL",
                signature.size());
    return ok == 1 ? 0 : 1;
}
