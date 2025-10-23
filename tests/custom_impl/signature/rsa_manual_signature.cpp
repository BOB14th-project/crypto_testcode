#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

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
    if (res < 0) res += mod;
    return static_cast<uint64_t>(res);
}

uint64_t toy_hash(const std::string& msg, uint64_t mod) {
    uint64_t h = 0;
    for (unsigned char c : msg) {
        h = (h * 131 + c) % mod;
    }
    return h;
}

int main() {
    const uint64_t p = 29573;
    const uint64_t q = 29611;
    const uint64_t n = p * q;
    const uint64_t phi = (p - 1) * (q - 1);

    const uint64_t e = 3;  // 작은 지수 → 취약 예시
    const uint64_t d = modinv(e, phi);

    const std::string message = "classical-signature";
    uint64_t hashed = toy_hash(message, n);

    uint64_t signature = modexp(hashed, d, n);
    uint64_t verified = modexp(signature, e, n);

    std::cout << "message: " << message << "\n";
    std::cout << "hash (toy): " << hashed << "\n";
    std::cout << "signature: " << signature << "\n";
    std::cout << "verify result: " << (verified == hashed ? "OK" : "FAIL") << "\n";

    const std::string tampered = "classical-signature!";
    uint64_t tampered_hash = toy_hash(tampered, n);
    std::cout << "tampered verify: "
              << (modexp(signature, e, n) == tampered_hash ? "OK" : "FAIL") << "\n";
    return 0;
}
