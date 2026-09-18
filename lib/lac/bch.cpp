/* SPDX-License-Identifier: GPL-2.0-only
 * Binary BCH encoding/decoding for LAC's three fixed parameter sets.
 *
 * Adapted from the repository's generic binary BCH library and parameter
 * tables. Copyright (C) 2011 Parrot S.A.
 * Original author: Ivan Djelic <ivan.djelic@parrot.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General
 * Public License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * C++ port: immutable tables, safe endian loads, bounded stack workspaces,
 * standard Berlekamp-Massey and full shortened-code Chien search. There is no
 * constant-time claim: field/remainder table addresses depend on data.
 */
#include "bch.hpp"
#include "bch_tables.hpp"
#include "crypto.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace lac::detail {
namespace {
using bch_tables::Configuration;
constexpr std::size_t max_t = 18;
constexpr std::size_t max_terms = 2 * max_t + 1;
constexpr std::size_t max_ecc = 21;

const Configuration* configuration(ParameterSet set) noexcept {
    switch (set) {
    case ParameterSet::Lac128: return &bch_tables::lac128;
    case ParameterSet::Lac192: return &bch_tables::lac192;
    case ParameterSet::Lac256: return &bch_tables::lac256;
    default: return nullptr;
    }
}

// The uint32_t mask retains every bit: message positions may exceed 255.
constexpr std::uint32_t mask_of(bool condition) noexcept {
    return 0u - static_cast<std::uint32_t>(condition);
}

unsigned reduce(unsigned exponent, unsigned n) noexcept {
    // Callers guarantee exponent < 2*n.
    return exponent - (n & mask_of(exponent >= n));
}

unsigned multiply(const Configuration& p, unsigned a, unsigned b) noexcept {
    const unsigned exponent = reduce(p.logs[a] + p.logs[b], p.n);
    return p.powers[exponent] & mask_of((a != 0) & (b != 0));
}

unsigned ratio(const Configuration& p, unsigned a, unsigned b) noexcept {
    // Berlekamp-Massey keeps b nonzero, including zero-discrepancy rounds.
    const unsigned exponent = reduce(p.logs[a] + p.n - p.logs[b], p.n);
    return p.powers[exponent] & mask_of(a != 0);
}

std::uint32_t load_big_endian(const Byte* data) noexcept {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           static_cast<std::uint32_t>(data[3]);
}

template <typename T>
class Wiped final {
public:
    T value{};
    ~Wiped() { cleanse({reinterpret_cast<Byte*>(&value), sizeof(value)}); }
    Wiped() = default;
    Wiped(const Wiped&) = delete;
    Wiped& operator=(const Wiped&) = delete;
};

void parity(const Configuration& p, std::span<const Byte> data,
            std::span<Byte> output) noexcept {
    Wiped<std::array<std::uint32_t, 6>> scratch;
    auto& words = scratch.value;
    const std::size_t count = p.words;
    // Four-slice encoding with explicit loads is portable, unaligned-safe
    // and retains the legacy implementation's four-byte processing rate.
    for (std::size_t offset = 0; offset < data.size(); offset += 4) {
        const std::uint32_t word = words[0] ^ load_big_endian(data.data() + offset);
        const auto* tab0 = p.remainders.data() + count * (word & 255u);
        const auto* tab1 = p.remainders.data() + count * (256u + ((word >> 8) & 255u));
        const auto* tab2 = p.remainders.data() + count * (512u + ((word >> 16) & 255u));
        const auto* tab3 = p.remainders.data() + count * (768u + (word >> 24));
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint32_t next = i + 1 < count ? words[i + 1] : 0u;
            words[i] = next ^ tab0[i] ^ tab1[i] ^ tab2[i] ^ tab3[i];
        }
    }
    for (std::size_t i = 0; i < p.ecc_bytes; ++i)
        output[i] = static_cast<Byte>(words[i / 4] >> (24u - 8u * (i % 4)));
}

struct DecoderScratch {
    std::array<Byte, max_code_bytes> corrected{};
    std::array<Byte, max_ecc> expected_parity{};
    std::array<unsigned, 2 * max_t> syndromes{};
    std::array<unsigned, max_terms> locator{};
    std::array<unsigned, max_terms> previous{};
    std::array<unsigned, max_terms> saved{};
    std::array<unsigned, max_t + 1> representations{};
    std::array<std::uint32_t, max_t + 1> coefficient_masks{};
};

void syndromes(const Configuration& p, std::span<const Byte> received_parity,
               DecoderScratch& work) noexcept {
    // Evaluate the parity difference at odd powers; obtain even syndromes
    // by squaring. Padding outside ecc_bits is deliberately excluded.
    for (unsigned bit = 0; bit < p.ecc_bits; ++bit) {
        const unsigned received = received_parity[bit / 8] ^ work.expected_parity[bit / 8];
        const auto mask = mask_of(((received >> (7u - bit % 8)) & 1u) != 0);
        const unsigned power = p.ecc_bits - 1u - bit;
        unsigned exponent = power;
        for (unsigned j = 0; j < 2 * p.t; j += 2) {
            work.syndromes[j] ^= p.powers[exponent] & mask;
            exponent = reduce(exponent + 2 * power, p.n);
        }
    }
    for (unsigned j = 0; j < p.t; ++j) {
        const unsigned value = work.syndromes[j];
        work.syndromes[2 * j + 1] = multiply(p, value, value);
    }
}

unsigned error_locator(const Configuration& p, DecoderScratch& work) noexcept {
    const unsigned rounds = 2 * p.t;
    auto& locator = work.locator;
    auto& previous = work.previous;
    locator[0] = 1;
    previous[1] = 1; // B(x) already includes the x^shift factor.
    unsigned degree = 0;
    unsigned prior_discrepancy = 1;
    for (unsigned round = 0; round < rounds; ++round) {
        unsigned discrepancy = work.syndromes[round];
        // Bounds depend only on the public round index, never on degree.
        for (unsigned i = 1; i <= round; ++i)
            discrepancy ^= multiply(p, locator[i], work.syndromes[round - i]);
        const unsigned scale = ratio(p, discrepancy, prior_discrepancy);
        const auto update = mask_of((discrepancy != 0) & (2 * degree <= round));
        for (unsigned i = 0; i <= rounds; ++i) {
            work.saved[i] = locator[i];
            locator[i] ^= multiply(p, scale, previous[i]);
        }
        for (unsigned i = 0; i <= rounds; ++i)
            previous[i] = (work.saved[i] & update) | (previous[i] & ~update);
        degree = ((round + 1u - degree) & update) | (degree & ~update);
        prior_discrepancy = (discrepancy & update) | (prior_discrepancy & ~update);
        for (unsigned i = rounds; i != 0; --i) previous[i] = previous[i - 1];
        previous[0] = 0;
    }
    return degree;
}

unsigned correct_roots(const Configuration& p, DecoderScratch& work) noexcept {
    const unsigned bits = static_cast<unsigned>(p.message_bytes * 8) + p.ecc_bits;
    const unsigned start = p.n - (bits - 1u);
    for (unsigned j = 1; j <= p.t; ++j) {
        work.representations[j] = (p.logs[work.locator[j]] + j * start) % p.n;
        work.coefficient_masks[j] = mask_of(work.locator[j] != 0);
    }
    unsigned roots = 0;
    // Search every data AND parity bit. There is no error-index array, hence
    // no out-of-bounds root writes even on malformed uncorrectable input.
    for (unsigned bit = 0; bit < bits; ++bit) {
        unsigned value = work.locator[0];
        for (unsigned j = 1; j <= p.t; ++j) {
            value ^= p.powers[work.representations[j]] & work.coefficient_masks[j];
            work.representations[j] = reduce(work.representations[j] + j, p.n);
        }
        const auto root = mask_of(value == 0);
        roots += root & 1u;
        work.corrected[bit / 8] ^= static_cast<Byte>(root & (1u << (7u - bit % 8)));
    }
    return roots;
}
} // namespace

bool BchCodec::encode(std::span<const Byte> message, std::span<Byte> code) const noexcept {
    const auto* p = configuration(set_);
    if (!p) return false;
    if (message.size() != p->message_bytes || code.size() != p->message_bytes + p->ecc_bytes) {
        if (code.size() == p->message_bytes + p->ecc_bytes) std::fill(code.begin(), code.end(), Byte{0});
        return false;
    }
    // Copy before writing parity, permitting even partial input/output overlap.
    std::memmove(code.data(), message.data(), message.size());
    parity(*p, code.first(p->message_bytes), code.subspan(p->message_bytes));
    return true;
}

bool BchCodec::decode(std::span<const Byte> code, std::span<Byte> message) const noexcept {
    const auto* p = configuration(set_);
    if (!p) return false;
    if (code.size() != p->message_bytes + p->ecc_bytes || message.size() != p->message_bytes) {
        if (message.size() == p->message_bytes) std::fill(message.begin(), message.end(), Byte{0});
        return false;
    }
    Wiped<DecoderScratch> scratch;
    auto& work = scratch.value;
    std::copy(code.begin(), code.end(), work.corrected.begin());
    parity(*p, code.first(p->message_bytes), work.expected_parity);
    syndromes(*p, code.subspan(p->message_bytes), work);
    const unsigned degree = error_locator(*p, work);
    const unsigned roots = correct_roots(*p, work);

    // Validate the entire corrected codeword, not just the locator degree.
    parity(*p, std::span<const Byte>(work.corrected).first(p->message_bytes), work.expected_parity);
    unsigned difference = 0;
    for (unsigned bit = 0; bit < p->ecc_bits; ++bit) {
        difference |= ((work.corrected[p->message_bytes + bit / 8] ^ work.expected_parity[bit / 8]) >>
                       (7u - bit % 8)) & 1u;
    }
    const bool valid = (degree <= p->t) & (roots == degree) & (difference == 0);
    const auto mask = mask_of(valid);
    for (std::size_t i = 0; i < p->message_bytes; ++i)
        message[i] = static_cast<Byte>(work.corrected[i] & mask);
    return valid;
}
} // namespace lac::detail
