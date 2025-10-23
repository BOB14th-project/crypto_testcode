#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using ByteVec = std::vector<uint8_t>;

// 매우 단순화된 32바이트 해시 (교육용) – FNV-1a 변형
ByteVec toy_hash(const ByteVec& data) {
    ByteVec out(32, 0);
    const uint64_t FNV_PRIME = 1099511628211ULL;
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < data.size(); ++i) {
        hash ^= data[i];
        hash *= FNV_PRIME;
        out[i % out.size()] ^= static_cast<uint8_t>((hash >> (i % 8) * 8) & 0xFF);
    }
    return out;
}

ByteVec hmac_toy(const ByteVec& key, const ByteVec& message) {
    ByteVec k = key;
    if (k.size() > 32) {
        k = toy_hash(k);
    }
    if (k.size() < 32) {
        k.resize(32, 0x00);
    }

    ByteVec o_key_pad(32), i_key_pad(32);
    for (size_t i = 0; i < 32; ++i) {
        o_key_pad[i] = k[i] ^ 0x5C;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    ByteVec inner(i_key_pad);
    inner.insert(inner.end(), message.begin(), message.end());
    ByteVec inner_hash = toy_hash(inner);

    ByteVec outer(o_key_pad);
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return toy_hash(outer);
}

ByteVec pbkdf2_toy(const ByteVec& password, const ByteVec& salt,
                   uint32_t iterations, size_t dk_len) {
    if (iterations == 0) {
        throw std::runtime_error("iterations must be positive");
    }
    ByteVec derived;
    uint32_t block_index = 1;
    while (derived.size() < dk_len) {
        ByteVec salt_block(salt);
        salt_block.push_back((block_index >> 24) & 0xFF);
        salt_block.push_back((block_index >> 16) & 0xFF);
        salt_block.push_back((block_index >> 8) & 0xFF);
        salt_block.push_back(block_index & 0xFF);

        ByteVec u = hmac_toy(password, salt_block);
        ByteVec t = u;

        for (uint32_t iter = 1; iter < iterations; ++iter) {
            u = hmac_toy(password, u);
            for (size_t i = 0; i < t.size(); ++i) {
                t[i] ^= u[i];
            }
        }

        size_t take = std::min(t.size(), dk_len - derived.size());
        derived.insert(derived.end(), t.begin(), t.begin() + take);
        ++block_index;
    }
    return derived;
}

void print_hex(const ByteVec& data) {
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

int main() {
    ByteVec password({'c', 'l', 'a', 's', 's', 'i', 'c', 'a', 'l'});
    ByteVec salt({'s', 'a', 'l', 't'});
    ByteVec derived = pbkdf2_toy(password, salt, 1000, 32);

    std::cout << "Toy PBKDF2 output:\n";
    print_hex(derived);
    return 0;
}
