#include "crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace lac::detail {
namespace {
// The original AES-NI PRF increments a 32-bit lane before reversing the bytes
// in each 64-bit half. With nonce zero its AES inputs are exactly the standard
// big-endian CTR inputs 0, 1, ... , 2^32-1. Do not silently extend that stream.
constexpr std::uint64_t maximum_prf_bytes = (std::uint64_t{1} << 32) * 16;
constexpr std::array<Byte, 32> zero_key{};
constexpr std::array<Byte, 16> zero_iv{};

struct EraseOnExit {
    std::span<Byte> bytes;
    ~EraseOnExit() { cleanse(bytes); }
};

// Keep the allocated provider context, but replace its current key and IV.
// OpenSSL owns opaque provider storage: this does not promise erasure of every
// provider-internal copy, nor does it make the rest of LAC constant-time.
bool clear_cipher(EVP_CIPHER_CTX* context, const EVP_CIPHER* cipher) noexcept {
    if (EVP_EncryptInit_ex2(context, cipher, zero_key.data(), zero_iv.data(), nullptr) == 1)
        return true;
    (void)EVP_CIPHER_CTX_reset(context);
    return false;
}

bool clear_digest(EVP_MD_CTX* context, const EVP_MD* digest) noexcept {
    if (EVP_DigestInit_ex2(context, digest, nullptr) == 1)
        return true;
    (void)EVP_MD_CTX_reset(context);
    return false;
}
} // namespace

Crypto::Crypto() {
    // All temporary owners survive every initialization failure. Publish the
    // raw members only after the complete backend has initialized successfully.
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(
        EVP_CIPHER_fetch(nullptr, "AES-256-CTR", nullptr), EVP_CIPHER_free);
    std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(
        EVP_MD_fetch(nullptr, "SHA256", nullptr), EVP_MD_free);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_context(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest_context(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!cipher || !digest || !cipher_context || !digest_context ||
        EVP_EncryptInit_ex2(cipher_context.get(), cipher.get(), zero_key.data(),
                           zero_iv.data(), nullptr) != 1 ||
        EVP_DigestInit_ex2(digest_context.get(), digest.get(), nullptr) != 1)
        throw std::runtime_error("Cannot initialize the OpenSSL LAC crypto backend");

    cipher_ = cipher.release();
    digest_ = digest.release();
    cipher_context_ = cipher_context.release();
    digest_context_ = digest_context.release();
}

Crypto::~Crypto() {
    EVP_CIPHER_CTX_free(cipher_context_);
    EVP_MD_CTX_free(digest_context_);
    EVP_CIPHER_free(cipher_);
    EVP_MD_free(digest_);
}

bool Crypto::expand(std::span<Byte> output, std::span<const Byte, 32> seed) noexcept {
    // Invalid lengths are rejected before accessing the caller's memory.
    if (static_cast<std::uint64_t>(output.size()) > maximum_prf_bytes)
        return false;
    if (output.empty())
        return true;

    // Several original sampling call sites expand their seed in place.
    std::array<Byte, 32> key{};
    std::copy(seed.begin(), seed.end(), key.begin());
    EraseOnExit erase_key{key};
    std::array<Byte, EVP_MAX_BLOCK_LENGTH> final_block{};
    EraseOnExit erase_final{final_block};

    bool success = EVP_EncryptInit_ex2(cipher_context_, cipher_, key.data(),
                                      zero_iv.data(), nullptr) == 1;
    if (success) {
        // CTR permits exactly overlapping input and output. Zeroing after the
        // seed copy avoids a separate scratch allocation, even for long output.
        std::fill(output.begin(), output.end(), Byte{0});
        std::size_t offset = 0;
        while (success && offset < output.size()) {
            const auto length = static_cast<int>(std::min(
                output.size() - offset, static_cast<std::size_t>(INT_MAX)));
            int produced = 0;
            success = EVP_EncryptUpdate(cipher_context_, output.data() + offset,
                                         &produced, output.data() + offset, length) == 1 &&
                      produced == length;
            offset += static_cast<std::size_t>(length);
        }
    }
    int final_size = 0;
    if (success)
        success = EVP_EncryptFinal_ex(cipher_context_, final_block.data(), &final_size) == 1 &&
                  final_size == 0;

    const bool cleared = clear_cipher(cipher_context_, cipher_);
    if (!success || !cleared)
        cleanse(output);
    return success && cleared;
}

bool Crypto::digest(std::span<Byte, 32> output,
                    std::initializer_list<std::span<const Byte>> parts) noexcept {
    // Delay the output write until every part has been consumed, including
    // when an input part aliases the caller's digest buffer.
    std::array<Byte, 32> result{};
    EraseOnExit erase_result{result};
    bool success = EVP_DigestInit_ex2(digest_context_, digest_, nullptr) == 1;
    for (const auto part : parts) {
        if (!success)
            break;
        if (!part.empty())
            success = EVP_DigestUpdate(digest_context_, part.data(), part.size()) == 1;
    }
    unsigned int length = 0;
    if (success)
        success = EVP_DigestFinal_ex(digest_context_, result.data(), &length) == 1 &&
                  length == result.size();
    const bool cleared = clear_digest(digest_context_, digest_);
    if (success && cleared)
        std::copy(result.begin(), result.end(), output.begin());
    else
        cleanse(output);
    return success && cleared;
}

bool Crypto::random(std::span<Byte> output) noexcept {
    if (output.empty())
        return true;
    if (RAND_priv_bytes_ex(nullptr, output.data(), output.size(), 256) == 1)
        return true;
    cleanse(output);
    return false;
}

void cleanse(std::span<Byte> memory) noexcept {
    if (!memory.empty())
        OPENSSL_cleanse(memory.data(), memory.size());
}
} // namespace lac::detail
