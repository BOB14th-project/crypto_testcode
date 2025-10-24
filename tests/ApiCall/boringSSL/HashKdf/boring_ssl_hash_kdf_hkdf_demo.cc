#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>

int main() {
    unsigned char ikm[32];
    RAND_bytes(ikm, sizeof(ikm));

    const unsigned char salt[] = "boringssl-salt";
    const unsigned char info[] = "hkdf-demo";

    unsigned char okm[32];
    if (!HKDF(okm, sizeof(okm), EVP_sha256(), ikm, sizeof(ikm), salt, sizeof(salt) - 1,
              info, sizeof(info) - 1)) {
        std::fprintf(stderr, "HKDF failed\n");
        return 1;
    }

    std::printf("HKDF-SHA256 output:\n");
    for (size_t i = 0; i < sizeof(okm); ++i) {
        std::printf("%02x", okm[i]);
    }
    std::printf("\n");
    return 0;
}
