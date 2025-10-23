#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// 간단한 XOR 스트림 암호 구현 (교육용)
std::vector<uint8_t> xor_stream(const std::vector<uint8_t>& data,
                                const std::vector<uint8_t>& key) {
    if (key.empty()) {
        throw std::runtime_error("Key must not be empty");
    }
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        out[i] = data[i] ^ key[i % key.size()];
    }
    return out;
}

void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " ";
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

int main() {
    std::vector<uint8_t> key = {0x13, 0x37, 0xBE, 0xEF};  // 매우 짧은 키 (취약)
    std::vector<uint8_t> nonce = {0x00, 0x00, 0x00, 0x01};

    auto encrypt = [&](const std::string& plaintext) {
        std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
        auto keystream = xor_stream(pt, key);
        std::vector<uint8_t> ct;
        ct.reserve(nonce.size() + keystream.size());
        ct.insert(ct.end(), nonce.begin(), nonce.end());
        ct.insert(ct.end(), keystream.begin(), keystream.end());
        return ct;
    };

    auto ct1 = encrypt("ATTACK AT DAWN");
    auto ct2 = encrypt("MEET AT NOON  ");  // 길이 맞춤

    print_hex("ciphertext1:", ct1);
    print_hex("ciphertext2:", ct2);

    // 동일 키/논스 재사용 시 암호문 XOR = 평문 XOR
    std::vector<uint8_t> xor_plain(ct1.size() - nonce.size());
    for (size_t i = 0; i < xor_plain.size(); ++i) {
        xor_plain[i] = ct1[nonce.size() + i] ^ ct2[nonce.size() + i];
    }

    std::cout << "ct1 XOR ct2 reveals: ";
    for (uint8_t b : xor_plain) {
        char c = (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
        std::cout << c;
    }
    std::cout << "\n";
    return 0;
}
