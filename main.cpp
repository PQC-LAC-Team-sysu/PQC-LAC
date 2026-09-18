#include "lac/kem.hpp"
#include <openssl/crypto.h>
#include <array>
#include <iostream>
#include <vector>

int main() {
    try {
        std::cout << "PQC-LAC-KEM-v1 / " << OpenSSL_version(OPENSSL_VERSION) << '\n';
        std::cout << "Research implementation; see docs/KEM_DESIGN.md for compatibility and security scope.\n";
        for (auto set : {lac::ParameterSet::Light, lac::ParameterSet::Lac128,
                         lac::ParameterSet::Lac192, lac::ParameterSet::Lac256}) {
            lac::Kem sender(set), receiver(set);
            const auto& p = sender.params();
            std::vector<lac::Byte> pk(p.public_key_bytes), sk(p.secret_key_bytes);
            std::vector<lac::Byte> ct(p.ciphertext_bytes), ss1(p.message_bytes), ss2(p.message_bytes);
            if (sender.keypair(pk, sk) != lac::Status::Ok ||
                sender.encapsulate(pk, ct, ss1) != lac::Status::Ok ||
                receiver.decapsulate(sk, ct, ss2) != lac::Status::Ok ||
                CRYPTO_memcmp(ss1.data(), ss2.data(), ss1.size()) != 0) {
                std::cerr << p.name << ": KEM round-trip failed\n";
                OPENSSL_cleanse(sk.data(), sk.size());
                OPENSSL_cleanse(ss1.data(), ss1.size());
                OPENSSL_cleanse(ss2.data(), ss2.size());
                return 1;
            }
            std::cout << p.name << " [" << sender.backend_name() << "] pk=" << pk.size()
                      << " sk=" << sk.size() << " ct=" << ct.size()
                      << " ss=" << ss1.size() << " bytes: round-trip OK\n";
            ct.back() ^= 1;
            if (receiver.decapsulate(sk, ct, ss2) != lac::Status::Ok ||
                CRYPTO_memcmp(ss1.data(), ss2.data(), ss1.size()) == 0) {
                std::cerr << "Invalid-ciphertext rejection check failed\n";
                OPENSSL_cleanse(sk.data(), sk.size());
                OPENSSL_cleanse(ss1.data(), ss1.size());
                OPENSSL_cleanse(ss2.data(), ss2.size());
                return 1;
            }
            OPENSSL_cleanse(sk.data(), sk.size());
            OPENSSL_cleanse(ss1.data(), ss1.size());
            OPENSSL_cleanse(ss2.data(), ss2.size());
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
