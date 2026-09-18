#include "../lib/lac/crypto.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef LAC_TEST_LEGACY_AES_REFERENCE
#if defined(_MSC_VER)
#include <intrin.h>
#endif
extern "C" void aes256ctr_prf(unsigned char*, unsigned long long,
                              const unsigned char*, unsigned char);
#endif

namespace {
using lac::Byte;
using lac::detail::Crypto;

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

std::vector<Byte> unhex(std::string_view text) {
    require(text.size() % 2 == 0, "Invalid test hex length");
    auto nibble = [](char ch) -> Byte {
        if (ch >= '0' && ch <= '9') return static_cast<Byte>(ch - '0');
        if (ch >= 'a' && ch <= 'f') return static_cast<Byte>(ch - 'a' + 10);
        if (ch >= 'A' && ch <= 'F') return static_cast<Byte>(ch - 'A' + 10);
        throw std::runtime_error("Invalid test hex digit");
    };
    std::vector<Byte> result(text.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<Byte>((nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1]));
    return result;
}

bool equal(std::span<const Byte> left, std::span<const Byte> right) {
    return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin());
}

// A separate ECB-based oracle constructs AES inputs explicitly. This avoids
// relying on CTR mode to test the original implementation's counter layout.
std::vector<Byte> ecb_encrypt(std::span<const Byte, 32> key,
                              std::span<const Byte> plaintext) {
    require(plaintext.size() % 16 == 0, "ECB oracle requires complete blocks");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(context != nullptr, "Cannot create ECB oracle context");
    require(EVP_EncryptInit_ex2(context.get(), EVP_aes_256_ecb(), key.data(), nullptr, nullptr) == 1,
            "Cannot initialize ECB oracle");
    require(EVP_CIPHER_CTX_set_padding(context.get(), 0) == 1, "Cannot disable ECB padding");
    std::vector<Byte> output(plaintext.size() + 16);
    int written = 0;
    require(EVP_EncryptUpdate(context.get(), output.data(), &written, plaintext.data(),
                              static_cast<int>(plaintext.size())) == 1,
            "ECB oracle update failed");
    int final_size = 0;
    require(EVP_EncryptFinal_ex(context.get(), output.data() + written, &final_size) == 1,
            "ECB oracle finalization failed");
    output.resize(static_cast<std::size_t>(written + final_size));
    return output;
}

std::vector<Byte> reference_stream(std::span<const Byte, 32> key, std::size_t length) {
    if (length == 0)
        return {};
    const auto blocks = (length + 15) / 16;
    std::vector<Byte> counters(blocks * 16, 0);
    for (std::size_t i = 0; i < blocks; ++i) {
        const auto counter = static_cast<std::uint32_t>(i);
        counters[16 * i + 12] = static_cast<Byte>(counter >> 24);
        counters[16 * i + 13] = static_cast<Byte>(counter >> 16);
        counters[16 * i + 14] = static_cast<Byte>(counter >> 8);
        counters[16 * i + 15] = static_cast<Byte>(counter);
    }
    auto output = ecb_encrypt(key, counters);
    output.resize(length);
    return output;
}

#ifdef LAC_TEST_LEGACY_AES_REFERENCE
bool has_legacy_aes_cpu_support() {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    int registers[4]{};
    __cpuid(registers, 1);
    return (registers[2] & (1 << 25)) != 0 && (registers[2] & (1 << 9)) != 0;
#elif defined(__i386__) || defined(__x86_64__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("ssse3");
#else
    return false;
#endif
}
#endif

void test_aes_oracle() {
    // FIPS 197 AES-256 example: published AES block known-answer vector.
    const auto key_bytes = unhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    std::array<Byte, 32> key{};
    std::copy(key_bytes.begin(), key_bytes.end(), key.begin());
    const auto plaintext = unhex("00112233445566778899aabbccddeeff");
    require(equal(ecb_encrypt(key, plaintext), unhex("8ea2b7ca516745bfeafc49904b496089")),
            "FIPS 197 AES-256 known-answer mismatch");

    Crypto crypto;
    std::array<Byte, 32> zero_seed{};
    std::array<Byte, 32> stream{};
    require(crypto.expand(stream, zero_seed), "Zero-seed expansion failed");
    require(equal(stream, unhex(
        "dc95c078a2408989ad48a21492842087530f8afbc74536b9a963b4f1c4cb738b")),
        "Zero-seed CTR known-answer mismatch");
}

void test_prf() {
    Crypto crypto;
    constexpr std::array<std::size_t, 13> lengths{
        0, 1, 15, 16, 17, 32, 127, 128, 129, 2048, 4095, 4096, 4097};
    // 4097 crosses the low-byte carry in the counter as well as an AES block.
    std::array<Byte, 32> seed{};
#ifdef LAC_TEST_LEGACY_AES_REFERENCE
    const bool legacy_available = has_legacy_aes_cpu_support();
#endif
    for (unsigned int pattern = 0; pattern < 8; ++pattern) {
        for (std::size_t i = 0; i < seed.size(); ++i)
            seed[i] = static_cast<Byte>(pattern * 37 + i * 19);
        for (const auto length : lengths) {
            std::vector<Byte> guarded(length + 16, 0xa5);
            const auto expected = reference_stream(seed, length);
            const auto output = std::span<Byte>(guarded).subspan(8, length);
            require(crypto.expand(output, seed), "PRF expansion failed");
            require(equal(output, expected), "PRF disagrees with explicit-counter ECB oracle");
            require(std::all_of(guarded.begin(), guarded.begin() + 8,
                                [](Byte value) { return value == 0xa5; }) &&
                    std::all_of(guarded.end() - 8, guarded.end(),
                                [](Byte value) { return value == 0xa5; }),
                    "PRF wrote outside output span");
#ifdef LAC_TEST_LEGACY_AES_REFERENCE
            if (legacy_available) {
                std::vector<Byte> legacy(length + 1);
                aes256ctr_prf(legacy.data(), static_cast<unsigned long long>(length), seed.data(), 0);
                require(equal(output, std::span<const Byte>(legacy).first(length)),
                        "OpenSSL PRF differs from original AES-NI PRF");
            }
#endif
            // Full overlap, and partial overlap with the seed before or after
            // the output start, exercise copy-before-write independently.
            for (const std::size_t seed_offset : {std::size_t{0}, std::size_t{8}, std::size_t{24}}) {
                std::vector<Byte> overlap(std::max(length + 8, seed_offset + seed.size()) + 8, 0x5a);
                std::copy(seed.begin(), seed.end(), overlap.begin() + seed_offset);
                const auto seed_view = std::span<const Byte, 32>(overlap.data() + seed_offset, 32);
                const auto overlapping_output = std::span<Byte>(overlap).subspan(8, length);
                require(crypto.expand(overlapping_output, seed_view), "Overlapping PRF expansion failed");
                require(equal(overlapping_output, expected), "Overlapping PRF changed the seed stream");
            }
        }
    }
#ifdef LAC_TEST_LEGACY_AES_REFERENCE
    std::cout << (legacy_available ? "Original AES-NI compatibility: passed\n"
                                   : "Original AES-NI compatibility: skipped (CPU lacks AES/SSSE3)\n");
#else
    std::cout << "Original AES-NI compatibility: not linked; explicit-counter oracle passed\n";
#endif
}

std::span<const Byte> bytes(std::string_view text) {
    return {reinterpret_cast<const Byte*>(text.data()), text.size()};
}

void test_digest() {
    Crypto crypto;
    std::array<Byte, 32> output{};
    require(crypto.digest(output, {}), "Empty SHA-256 failed");
    require(equal(output, unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
            "Empty SHA-256 vector mismatch");
    require(crypto.digest(output, {bytes("a"), {}, bytes("b"), bytes("c")}), "Multipart SHA-256 failed");
    require(equal(output, unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
            "SHA-256 abc vector mismatch");
    require(crypto.digest(output, {bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")}),
            "Multiblock SHA-256 failed");
    require(equal(output, unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")),
            "Multiblock SHA-256 vector mismatch");

    output.fill(0);
    output[0] = 'a'; output[1] = 'b'; output[2] = 'c';
    require(crypto.digest(output, {std::span<const Byte>(output).first(3)}), "Aliased SHA-256 failed");
    require(equal(output, unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
            "Aliased SHA-256 vector mismatch");

    // Exercise independent contexts and reuse after a different operation.
    std::array<Byte, 32> seed{};
    require(crypto.expand(output, seed), "PRF after SHA-256 failed");
    require(crypto.digest(output, {bytes("abc")}), "SHA-256 after PRF failed");
    require(equal(output, unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
            "Reused SHA-256 context mismatch");
}

void test_random_and_cleanse() {
    std::array<Byte, 64> random{};
    require(Crypto::random({}), "Empty random request failed");
    require(Crypto::random(random), "OpenSSL private random generator failed");
    // This is a smoke test, not a statistical certification of the RNG.
    require(std::any_of(random.begin(), random.end(), [](Byte value) { return value != 0; }),
            "Random generator returned an all-zero block");
    lac::detail::cleanse(random);
    require(std::all_of(random.begin(), random.end(), [](Byte value) { return value == 0; }),
            "Secret cleanse failed");
    lac::detail::cleanse({});
}
} // namespace

int main() {
    try {
        test_aes_oracle();
        test_prf();
        test_digest();
        test_random_and_cleanse();
        std::cout << "Crypto backend tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Crypto backend test failure: " << error.what() << '\n';
        return 1;
    }
}
