// SPDX-License-Identifier: GPL-2.0-only
// Standalone regression tests for the bounded BCH port.
#include "lac/bch.hpp"
#include "lac/bch_tables.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
using lac::Byte;
using lac::ParameterSet;
using lac::detail::BchCodec;
using lac::detail::bch_tables::Configuration;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::uint64_t fingerprint(std::span<const std::uint32_t> words) {
    std::uint64_t hash = 14695981039346656037ull;
    for (const auto word : words) {
        for (unsigned shift = 0; shift < 32; shift += 8) {
            hash ^= (word >> shift) & 255u;
            hash *= 1099511628211ull;
        }
    }
    return hash;
}

std::vector<Byte> from_hex(const char* text) {
    const std::string hex(text);
    require(hex.size() % 2 == 0, "malformed test vector");
    std::vector<Byte> bytes(hex.size() / 2);
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<Byte>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    return bytes;
}

// Independent byte-at-a-time reference corresponding to the original
// encode_bch_unaligned. The production path instead uses four table slices.
std::vector<Byte> reference_parity(const Configuration& p, std::span<const Byte> data) {
    std::array<std::uint32_t, 6> state{};
    for (const auto byte : data) {
        const auto index = static_cast<std::size_t>((state[0] >> 24) ^ byte) * p.words;
        for (std::size_t j = 0; j < p.words; ++j) {
            const auto next = j + 1 < p.words ? state[j + 1] >> 24 : 0u;
            state[j] = ((state[j] << 8) | next) ^ p.remainders[index + j];
        }
    }
    std::vector<Byte> result(p.ecc_bytes);
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<Byte>(state[i / 4] >> (24u - 8u * (i % 4)));
    return result;
}

void flip_serial_bit(std::span<Byte> data, std::size_t bit) {
    data[bit / 8] ^= static_cast<Byte>(1u << (7u - bit % 8));
}

void test_set(ParameterSet set, const Configuration& p,
              const std::array<const char*, 3>& golden) {
    const BchCodec codec(set);
    std::vector<Byte> message(p.message_bytes);
    std::vector<Byte> code(p.message_bytes + p.ecc_bytes);
    std::vector<Byte> recovered(p.message_bytes);
    // Golden parity strings were evaluated directly from the original
    // bch128.h/bch192.h/bch256.h tables, independent of this C++ port.
    for (unsigned sample = 0; sample < golden.size(); ++sample) {
        for (std::size_t i = 0; i < message.size(); ++i)
            message[i] = static_cast<Byte>(sample == 0 ? i : sample == 1 ? 255 : i * 73 + 129);
        require(codec.encode(message, code), "golden encode failed");
        const auto expected = from_hex(golden[sample]);
        require(expected.size() == p.ecc_bytes, "wrong golden length");
        require(std::equal(expected.begin(), expected.end(), code.begin() + p.message_bytes), "legacy parity changed");
        require(codec.decode(code, recovered) && recovered == message, "golden roundtrip failed");
    }

    std::mt19937 rng(static_cast<unsigned>(set) * 13579u);
    for (unsigned sample = 0; sample < 128; ++sample) {
        for (auto& byte : message) byte = static_cast<Byte>(rng());
        require(codec.encode(message, code), "random encode failed");
        const auto expected = reference_parity(p, message);
        require(std::equal(expected.begin(), expected.end(), code.begin() + p.message_bytes), "byte reference mismatch");
    }

    const std::size_t bits = p.message_bytes * 8 + p.ecc_bits;
    const auto clean_code = code;
    // Exhaust every data/parity bit, including shortened-code bit positions
    // above 255 and the most significant bit of every message byte.
    for (std::size_t bit = 0; bit < bits; ++bit) {
        code = clean_code;
        flip_serial_bit(code, bit);
        require(codec.decode(code, recovered) && recovered == message, "single-bit correction failed");
    }

    std::vector<std::size_t> locations(bits);
    for (std::size_t i = 0; i < bits; ++i) locations[i] = i;
    for (unsigned errors = 0; errors <= p.t; ++errors) {
        for (unsigned sample = 0; sample < 24; ++sample) {
            for (auto& byte : message) byte = static_cast<Byte>(rng());
            require(codec.encode(message, code), "correctable encode failed");
            std::shuffle(locations.begin(), locations.end(), rng);
            for (unsigned i = 0; i < errors; ++i) flip_serial_bit(code, locations[i]);
            require(codec.decode(code, recovered) && recovered == message, "up-to-t correction failed");
        }
    }

    // Beyond t, BCH may reject OR miscorrect to another codeword; KEM's
    // ciphertext check must provide authentication. Assert safe handling and
    // cleared output on actual rejection, not universal rejection beyond t.
    unsigned rejections = 0;
    for (unsigned sample = 0; sample < 128; ++sample) {
        for (auto& byte : code) byte = static_cast<Byte>(rng());
        std::fill(recovered.begin(), recovered.end(), Byte{0xa5});
        if (!codec.decode(code, recovered)) {
            ++rejections;
            require(std::all_of(recovered.begin(), recovered.end(), [](Byte b) { return b == 0; }), "failure output not cleared");
        }
    }
    require(rejections > 100, "unexpected decoder acceptance of random input");

    // Padding is not part of the BCH polynomial and was ignored by the
    // original decoder; retain that behavior for noisy LAC256 codewords.
    require(codec.encode(message, code), "padding encode failed");
    for (std::size_t bit = bits; bit < code.size() * 8; ++bit) {
        auto padded = code;
        flip_serial_bit(padded, bit);
        require(codec.decode(padded, recovered) && recovered == message, "padding changed decoding");
    }

    // Guard bytes catch wrong-size writes, including malformed spans.
    std::vector<Byte> guard_code(code.size() + 2, 0x5a);
    auto code_view = std::span<Byte>(guard_code).subspan(1, code.size());
    require(!codec.encode(std::span<const Byte>(message).first(message.size() - 1), code_view), "short message accepted");
    require(std::all_of(code_view.begin(), code_view.end(), [](Byte b) { return b == 0; }), "encode failure not cleared");
    require(guard_code.front() == 0x5a && guard_code.back() == 0x5a, "encode guard overwritten");

    std::vector<Byte> guard_message(message.size() + 2, 0x5a);
    auto message_view = std::span<Byte>(guard_message).subspan(1, message.size());
    require(!codec.decode(std::span<const Byte>(code).first(code.size() - 1), message_view), "short code accepted");
    require(std::all_of(message_view.begin(), message_view.end(), [](Byte b) { return b == 0; }), "decode failure not cleared");
    require(guard_message.front() == 0x5a && guard_message.back() == 0x5a, "decode guard overwritten");
    require(!codec.encode(message, {}), "empty code accepted");
    require(!codec.decode(code, {}), "empty output accepted");

    // Check unaligned buffers and both overlapping directions.
    std::vector<Byte> storage(code.size() + 8, 0);
    std::copy(message.begin(), message.end(), storage.begin() + 3);
    require(codec.encode(std::span<const Byte>(storage).subspan(3, message.size()),
                         std::span<Byte>(storage).subspan(1, code.size())), "overlap encode failed");
    require(codec.decode(std::span<const Byte>(storage).subspan(1, code.size()),
                         std::span<Byte>(storage).subspan(2, message.size())), "overlap decode failed");
    require(std::equal(message.begin(), message.end(), storage.begin() + 2), "overlap changed message");
}

void shared_codec_concurrency() {
    const BchCodec codec(ParameterSet::Lac256);
    std::atomic<bool> success{true};
    std::array<std::thread, 4> threads;
    for (unsigned thread = 0; thread < threads.size(); ++thread) {
        threads[thread] = std::thread([&, thread] {
            std::array<Byte, 32> message{};
            std::array<Byte, 32> recovered{};
            std::array<Byte, 53> code{};
            for (unsigned sample = 0; sample < 32; ++sample) {
                for (unsigned i = 0; i < message.size(); ++i)
                    message[i] = static_cast<Byte>(i * 19 + sample * 7 + thread);
                if (!codec.encode(message, code)) success = false;
                for (unsigned error = 0; error < 18; ++error)
                    flip_serial_bit(code, (error * 17 + sample) % 409);
                if (!codec.decode(code, recovered) || recovered != message) success = false;
            }
        });
    }
    for (auto& thread : threads) thread.join();
    require(success, "shared codec concurrency failed");
}
} // namespace

int main() {
    try {
        namespace tables = lac::detail::bch_tables;
        // Fingerprints obtained from every original table word, serialized
        // low byte first. These lock down all 11,264 words, not just vectors.
        require(fingerprint(tables::remainder128) == 0x5ba2d36d139a9fa5ull, "LAC128 table fingerprint");
        require(fingerprint(tables::remainder192) == 0x44382532d98d9b05ull, "LAC192 table fingerprint");
        require(fingerprint(tables::remainder256) == 0xdbc93a7d31096505ull, "LAC256 table fingerprint");
        test_set(ParameterSet::Lac128, tables::lac128, {
            "5270ee038af3eff4", "7cdab08eb3d45ef0", "55036fb1d2dd3b1f"});
        test_set(ParameterSet::Lac192, tables::lac192, {
            "63c5e49d50e0f50f8f", "621468382e9181cf7a", "541d9775ca6d6ef9ee"});
        test_set(ParameterSet::Lac256, tables::lac256, {
            "afef4481c5061c369042beeb6553dbd039ad900000",
            "2f51c42bdb74142146977ff015376f87546b670000",
            "8010474d54de1b276eab7f2ca0ee647483ebdf0000"});
        require(!BchCodec(ParameterSet::Light).encode({}, {}), "LIGHT accepted by BCH");
        require(!BchCodec(static_cast<ParameterSet>(99)).decode({}, {}), "invalid set accepted by BCH");
        shared_codec_concurrency();
        std::cout << "BCH tests passed: legacy encoding, exhaustive single-bit and up-to-t errors, malformed inputs, padding, overlap, concurrency\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BCH test failure: " << error.what() << '\n';
        return 1;
    }
}
