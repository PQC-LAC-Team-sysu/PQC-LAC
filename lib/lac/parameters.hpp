#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace lac {
using Byte = std::uint8_t;
enum class ParameterSet { Light, Lac128, Lac192, Lac256 };
enum class Backend { Auto, Portable, Avx2 };

struct Parameters {
    ParameterSet id;
    std::string_view name;
    std::size_t dimension;
    std::size_t weight; // Number of +1 positions and, separately, -1 positions.
    std::size_t sample_words;
    std::size_t message_bytes;
    std::size_t public_key_bytes;
    std::size_t secret_key_bytes;
    std::size_t ciphertext_bytes;
    std::size_t ecc_bytes;
    std::size_t c2_coefficients;
};

inline constexpr std::size_t seed_bytes = 32;
inline constexpr std::size_t max_dimension = 1024;
inline constexpr std::size_t max_weight = 192;
inline constexpr std::size_t max_message_bytes = 32;
inline constexpr std::size_t max_public_key_bytes = 1056;
inline constexpr std::size_t max_secret_key_bytes = 2080;
inline constexpr std::size_t max_ciphertext_bytes = 1448;
inline constexpr std::size_t max_code_bytes = 53;
inline constexpr std::uint16_t modulus = 251;

const Parameters& parameters(ParameterSet set);
} // namespace lac
