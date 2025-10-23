#include <cstdint>
#include <iostream>

struct RSAKey {
    uint64_t n;
    uint64_t exponent;
};

uint64_t egcd(uint64_t a, uint64_t b, int64_t& x, int64_t& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int64_t x1 = 0, y1 = 0;
    uint64_t g = egcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - static_cast<int64_t>(a / b) * y1;
    return g;
}

uint64_t modinv(uint64_t a, uint64_t mod) {
    int64_t x = 0, y = 0;
    uint64_t g = egcd(a, mod, x, y);
    if (g != 1) {
        throw std::runtime_error("inverse does not exist");
    }
    int64_t res = x % static_cast<int64_t>(mod);
    if (res < 0) {
        res += mod;
    }
    return static_cast<uint64_t>(res);
}

uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

void generate_rsa(RSAKey& pub, RSAKey& priv) {
    const uint64_t p = 31337;
    const uint64_t q = 31357;
    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 65537;
    uint64_t d = modinv(e, phi);
    pub = {n, e};
    priv = {n, d};
}

int main() {
    RSAKey pub{}, priv{};
    generate_rsa(pub, priv);

    uint64_t message = 424242;
    uint64_t ciphertext = modexp(message, pub.exponent, pub.n);
    uint64_t recovered = modexp(ciphertext, priv.exponent, priv.n);

    std::cout << "RSA public key (n, e): (" << pub.n << ", " << pub.exponent
              << ")\n";
    std::cout << "ciphertext: " << ciphertext << "\n";
    std::cout << "recovered: " << recovered << "\n";
    return 0;
}
