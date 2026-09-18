// SPDX-License-Identifier: GPL-2.0-only
// Tables and encoding conventions derived from the repository's bch128.h,
// bch192.h, bch256.h and Ivan Djelic's binary BCH library (Parrot S.A., 2011).
// See the copyright and license notice in bch.cpp.
//
// Provenance: generator words are entry 1 of each original mod8_tab, stored
// most-significant word first. Repeated polynomial shifts reproduce ALL 2048,
// 3072 and 6144 words, respectively, of those original four-slice tables.
// Field tables are generated with the original primitive polynomials 0x11d
// (GF256) and 0x211 (GF512). No generated binary or mutable table is required.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace lac::detail::bch_tables {
template <std::size_t Order>
struct Field {
    std::array<std::uint16_t, Order> powers{};
    std::array<std::uint16_t, Order> logs{};
};

template <std::size_t Order>
constexpr Field<Order> make_field(unsigned primitive) noexcept {
    Field<Order> result{};
    unsigned value = 1;
    for (std::size_t i = 0; i < Order - 1; ++i) {
        result.powers[i] = static_cast<std::uint16_t>(value);
        result.logs[value] = static_cast<std::uint16_t>(i);
        value <<= 1;
        if ((value & Order) != 0) value ^= primitive;
    }
    result.powers[Order - 1] = 1;
    return result;
}

template <std::size_t Words>
constexpr std::array<std::uint32_t, 4 * 256 * Words>
make_remainders(const std::array<std::uint32_t, Words>& generator) noexcept {
    std::array<std::uint32_t, 4 * 256 * Words> result{};
    // Generate each one-bit remainder once, then use GF(2) linearity to
    // combine it into byte entries. The slices represent successive x^8
    // multiples; this also keeps compile-time evaluation small on MSVC.
    std::array<std::uint32_t, Words> bit_remainder = generator;
    for (std::size_t bit = 0; bit < 32; ++bit) {
        const std::size_t slice = bit / 8;
        const unsigned bit_mask = 1u << (bit % 8);
        for (unsigned byte = 0; byte < 256; ++byte) {
            if ((byte & bit_mask) == 0) continue;
            for (std::size_t word = 0; word < Words; ++word)
                result[(slice * 256 + byte) * Words + word] ^= bit_remainder[word];
        }
        const std::uint32_t mask = 0u - (bit_remainder[0] >> 31);
        for (std::size_t word = 0; word < Words; ++word) {
            const std::uint32_t next = word + 1 < Words ? bit_remainder[word + 1] >> 31 : 0u;
            bit_remainder[word] = (bit_remainder[word] << 1 | next) ^ (generator[word] & mask);
        }
    }
    return result;
}

inline constexpr auto field256 = make_field<256>(0x11du);
inline constexpr auto field512 = make_field<512>(0x211u);
inline constexpr auto remainder128 = make_remainders(std::array<std::uint32_t, 2>{
    0x6ce707e2u, 0x6b6f9977u});
inline constexpr auto remainder192 = make_remainders(std::array<std::uint32_t, 3>{
    0xb8ba069bu, 0x8b1ffe26u, 0xe5000000u});
inline constexpr auto remainder256 = make_remainders(std::array<std::uint32_t, 6>{
    0xbe4b8d96u, 0x594433b7u, 0x0e3f574du, 0xc380ffc2u, 0x12fb5680u, 0u});

struct Configuration {
    unsigned n;
    unsigned t;
    unsigned ecc_bits;
    std::size_t message_bytes;
    std::size_t ecc_bytes;
    std::size_t words;
    std::span<const std::uint16_t> powers;
    std::span<const std::uint16_t> logs;
    std::span<const std::uint32_t> remainders;
};

inline constexpr Configuration lac128{
    255, 8, 64, 16, 8, 2, field256.powers, field256.logs, remainder128};
inline constexpr Configuration lac192{
    511, 8, 72, 32, 9, 3, field512.powers, field512.logs, remainder192};
inline constexpr Configuration lac256{
    511, 18, 153, 32, 21, 6, field512.powers, field512.logs, remainder256};
} // namespace lac::detail::bch_tables
