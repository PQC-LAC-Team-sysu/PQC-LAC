#include "lac/kem.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

// Repeatable functional/fault stress, not a performance benchmark or an
// estimator of the extremely small decryption-failure rates claimed in papers.
// The deterministic source below is TEST ONLY and must never secure real keys.
namespace {
using lac::Byte;

struct WipedBytes {
    std::vector<Byte> value;
    explicit WipedBytes(std::size_t size) : value(size) {}
    WipedBytes(const WipedBytes&) = delete;
    WipedBytes& operator=(const WipedBytes&) = delete;
    ~WipedBytes() { wipe(); }
    void wipe() noexcept {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    }
};

struct WipedDigest {
    std::array<Byte, 32> value{};
    WipedDigest() = default;
    WipedDigest(const WipedDigest&) = delete;
    WipedDigest& operator=(const WipedDigest&) = delete;
    ~WipedDigest() { OPENSSL_cleanse(value.data(), value.size()); }
};

struct TestRandom {
    std::uint64_t state;
    explicit TestRandom(std::uint64_t seed) : state(seed) {}
    ~TestRandom() { OPENSSL_cleanse(&state, sizeof(state)); }

    std::uint64_t next() noexcept {
        state += 0x9e3779b97f4a7c15ULL;
        std::uint64_t word = state;
        word = (word ^ (word >> 30)) * 0xbf58476d1ce4e5b9ULL;
        word = (word ^ (word >> 27)) * 0x94d049bb133111ebULL;
        return word ^ (word >> 31);
    }

    static bool fill(std::span<Byte> output, void* context) noexcept {
        auto& random = *static_cast<TestRandom*>(context);
        std::size_t offset = 0;
        while (offset < output.size()) {
            auto word = random.next();
            const auto count = std::min(std::size_t{8}, output.size() - offset);
            for (std::size_t i = 0; i < count; ++i) {
                output[offset++] = static_cast<Byte>(word);
                word >>= 8;
            }
            OPENSSL_cleanse(&word, sizeof(word));
        }
        return true;
    }

    lac::RandomSource source() noexcept { return {fill, this}; }
};

struct Counts {
    std::uint64_t honest_attempts = 0;
    std::uint64_t honest_mismatches = 0;
    std::uint64_t bitflip_attempts = 0;
    std::uint64_t bitflip_rejection_mismatches = 0;
    std::uint64_t random_attempts = 0;
    std::uint64_t random_rejection_mismatches = 0;

    bool passed() const noexcept {
        return honest_mismatches == 0 && bitflip_rejection_mismatches == 0 &&
               random_rejection_mismatches == 0;
    }
};

void expect_ok(lac::Status status, std::string_view parameter,
               std::uint64_t round, std::string_view operation) {
    if (status != lac::Status::Ok)
        throw std::runtime_error(std::string(parameter) + " round " + std::to_string(round) +
            " " + std::string(operation) + ": " + std::string(lac::status_message(status)));
}

void independent_sha256(std::span<const Byte> input, std::span<Byte, 32> output) {
    unsigned int length = 0;
    if (EVP_Digest(input.data(), input.size(), output.data(), &length, EVP_sha256(), nullptr) != 1 ||
        length != output.size())
        throw std::runtime_error("Independent EVP_Digest SHA-256 calculation failed");
}

bool run(lac::ParameterSet set, std::size_t set_index, std::uint64_t rounds, lac::Backend backend) {
    // Independent streams keep the honest key/message sequence unaffected by
    // the additional random bytes needed to construct malformed ciphertexts.
    const std::uint64_t key_seed = 0x4c41435f53545253ULL + set_index;
    const std::uint64_t fault_seed = 0x4641554c545f5631ULL + set_index;
    TestRandom key_random(key_seed), fault_random(fault_seed);
    lac::Kem kem(set, backend, key_random.source());
    const auto& p = kem.params();
    WipedBytes pk(p.public_key_bytes), sk(p.secret_key_bytes), ct(p.ciphertext_bytes);
    WipedBytes shared(p.message_bytes), recovered(p.message_bytes), malformed(p.ciphertext_bytes);
    WipedBytes rejection_transcript(32 + p.ciphertext_bytes);
    Counts counts;

    for (std::uint64_t round = 0; round < rounds; ++round) {
        expect_ok(kem.keypair(pk.value, sk.value), p.name, round, "keypair");
        expect_ok(kem.encapsulate(pk.value, ct.value, shared.value), p.name, round, "encapsulate");
        expect_ok(kem.decapsulate(sk.value, ct.value, recovered.value), p.name, round, "honest decapsulate");
        ++counts.honest_attempts;
        if (shared.value != recovered.value) ++counts.honest_mismatches;

        // Exactly one fault per honest round. Even zero-based rounds flip one
        // bit; odd rounds replace every ciphertext byte with the test stream.
        const bool bitflip = (round & 1u) == 0;
        if (bitflip) {
            std::copy(ct.value.begin(), ct.value.end(), malformed.value.begin());
            const auto offset = static_cast<std::size_t>(fault_random.next() % malformed.value.size());
            const auto bit = static_cast<unsigned int>(fault_random.next() % 8);
            malformed.value[offset] ^= static_cast<Byte>(1u << bit);
            ++counts.bitflip_attempts;
        } else {
            TestRandom::fill(malformed.value, &fault_random);
            ++counts.random_attempts;
        }

        WipedDigest hashed_secret_key, expected;
        independent_sha256(sk.value, hashed_secret_key.value);
        std::copy(hashed_secret_key.value.begin(), hashed_secret_key.value.end(),
                  rejection_transcript.value.begin());
        std::copy(malformed.value.begin(), malformed.value.end(), rejection_transcript.value.begin() + 32);
        independent_sha256(rejection_transcript.value, expected.value);

        recovered.wipe();
        expect_ok(kem.decapsulate(sk.value, malformed.value, recovered.value), p.name, round,
                  bitflip ? "single-bit fault decapsulate" : "random ciphertext decapsulate");
        const bool expected_rejection = std::equal(recovered.value.begin(), recovered.value.end(),
                                                   expected.value.begin());
        if (!expected_rejection) {
            if (bitflip) ++counts.bitflip_rejection_mismatches;
            else ++counts.random_rejection_mismatches;
        }

        // Wipe outputs every round, as well as during exception unwinding.
        pk.wipe(); sk.wipe(); ct.wipe(); shared.wipe(); recovered.wipe();
        malformed.wipe(); rejection_transcript.wipe();
    }

    std::cout << p.name << ',' << kem.backend_name() << ',' << rounds << ','
              << counts.honest_attempts << ',' << counts.honest_mismatches << ','
              << counts.bitflip_attempts << ',' << counts.bitflip_rejection_mismatches << ','
              << counts.random_attempts << ',' << counts.random_rejection_mismatches << ','
              << key_seed << ',' << fault_seed << '\n';
    std::cout.flush();
    return counts.passed();
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc > 3) throw std::invalid_argument("Too many arguments");
        std::uint64_t rounds = 1000;
        if (argc >= 2) {
            const std::string_view argument(argv[1]);
            const auto result = std::from_chars(argument.data(), argument.data() + argument.size(), rounds);
            if (result.ec != std::errc{} || result.ptr != argument.data() + argument.size() ||
                rounds < 1 || rounds > 1000000)
                throw std::invalid_argument("rounds must be an integer from 1 to 1000000");
        }
        lac::Backend backend = lac::Backend::Auto;
        if (argc == 3) {
            const std::string_view argument(argv[2]);
            if (argument == "portable") backend = lac::Backend::Portable;
            else if (argument != "auto") throw std::invalid_argument("backend must be portable or auto");
        }

        std::cerr << "Deterministic TEST-ONLY entropy; one alternating fault per honest round.\n"
                     "Zero observed failures do not establish an extremely small decryption-failure rate.\n";
        std::cout << "parameter,backend,rounds,honest_attempts,honest_mismatches,"
                     "bitflip_attempts,bitflip_rejection_mismatches,random_attempts,"
                     "random_rejection_mismatches,key_rng_seed,fault_rng_seed\n";
        constexpr std::array sets{lac::ParameterSet::Light, lac::ParameterSet::Lac128,
                                   lac::ParameterSet::Lac192, lac::ParameterSet::Lac256};
        bool passed = true;
        for (std::size_t i = 0; i < sets.size(); ++i) {
            const bool current_passed = run(sets[i], i, rounds, backend);
            passed = current_passed && passed;
        }
        return passed ? 0 : 1;
    } catch (const std::invalid_argument& error) {
        std::cerr << "Usage: kem_stress [rounds:1..1000000] [portable|auto]\n"
                  << "Error: " << error.what() << '\n';
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "Stress test aborted: " << error.what() << '\n';
        return 1;
    }
}
