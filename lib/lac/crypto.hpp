#pragma once

#include "parameters.hpp"
#include <initializer_list>
#include <span>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_md_st EVP_MD;

namespace lac::detail {
// Reuses EVP contexts. Construction may throw; operations report failure.
// Like Kem, an instance must not be called concurrently by multiple threads.
class Crypto final {
public:
    Crypto();
    ~Crypto();
    Crypto(const Crypto&) = delete;
    Crypto& operator=(const Crypto&) = delete;
    bool expand(std::span<Byte> output, std::span<const Byte, 32> seed) noexcept;
    bool digest(std::span<Byte, 32> output,
                std::initializer_list<std::span<const Byte>> parts) noexcept;
    static bool random(std::span<Byte> output) noexcept;
private:
    EVP_CIPHER_CTX* cipher_context_ = nullptr;
    EVP_MD_CTX* digest_context_ = nullptr;
    EVP_CIPHER* cipher_ = nullptr;
    EVP_MD* digest_ = nullptr;
};
void cleanse(std::span<Byte> memory) noexcept;
} // namespace lac::detail
