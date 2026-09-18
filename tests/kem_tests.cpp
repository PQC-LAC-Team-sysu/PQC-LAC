#include "lac/kem.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <future>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using lac::Backend;
using lac::Byte;
using lac::Kem;
using lac::ParameterSet;
using lac::Status;
using Bytes = std::vector<Byte>;

constexpr std::array all_sets{ParameterSet::Light, ParameterSet::Lac128,
                               ParameterSet::Lac192, ParameterSet::Lac256};

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void require_status(Status actual, Status expected, const std::string& operation) {
    require(actual == expected, operation + ": expected " +
        std::string(lac::status_message(expected)) + ", got " +
        std::string(lac::status_message(actual)));
}

bool equal(std::span<const Byte> left, std::span<const Byte> right) {
    return std::equal(left.begin(), left.end(), right.begin(), right.end());
}

bool zero(std::span<const Byte> bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](Byte b) { return b == 0; });
}

struct GuardedBuffer {
    static constexpr std::size_t guard_size = 16;
    static constexpr Byte canary = 0xa5;
    Bytes storage;
    std::size_t size;

    explicit GuardedBuffer(std::size_t bytes)
        : storage(bytes + 2 * guard_size, canary), size(bytes) { reset(); }

    std::span<Byte> bytes() { return {storage.data() + guard_size, size}; }
    void reset() { std::fill(bytes().begin(), bytes().end(), Byte{0xcc}); }
    void check(const std::string& name) const {
        const auto is_canary = [](Byte b) { return b == canary; };
        require(std::all_of(storage.begin(), storage.begin() + guard_size, is_canary),
                name + ": leading buffer guard was overwritten");
        require(std::all_of(storage.end() - guard_size, storage.end(), is_canary),
                name + ": trailing buffer guard was overwritten");
    }
};

// Deterministic testing only. This deliberately is not a cryptographic RNG.
struct TestRandom {
    std::uint64_t state = 0x7699d8642721c76bULL;
    std::size_t calls = 0;
    bool fail = false;
    std::array<Byte, 64> last{};
    std::size_t last_size = 0;

    static bool fill(std::span<Byte> output, void* context) noexcept {
        auto& self = *static_cast<TestRandom*>(context);
        ++self.calls;
        self.last_size = output.size();
        for (std::size_t i = 0; i < output.size(); ++i) {
            self.state += 0x9e3779b97f4a7c15ULL;
            auto word = self.state;
            word = (word ^ (word >> 30)) * 0xbf58476d1ce4e5b9ULL;
            word = (word ^ (word >> 27)) * 0x94d049bb133111ebULL;
            output[i] = static_cast<Byte>((word ^ (word >> 31)) >> 56);
            if (i < self.last.size()) self.last[i] = output[i];
        }
        // A failing source is allowed to have already written partial output.
        return !self.fail;
    }
    lac::RandomSource source() { return {fill, this}; }
};

std::array<Byte, 32> sha256(std::initializer_list<std::span<const Byte>> parts) {
    Bytes concatenated;
    for (const auto part : parts) concatenated.insert(concatenated.end(), part.begin(), part.end());
    std::array<Byte, 32> result{};
    unsigned int length = 0;
    require(EVP_Digest(concatenated.data(), concatenated.size(), result.data(), &length,
                       EVP_sha256(), nullptr) == 1 && length == result.size(),
            "independent SHA-256 calculation failed");
    return result;
}

void check_canonical_key(const lac::Parameters& p, std::span<const Byte> pk,
                         std::span<const Byte> sk) {
    require(std::all_of(pk.begin() + lac::seed_bytes, pk.end(),
                        [](Byte b) { return b < lac::modulus; }), "public key coefficient >= q");
    require(equal(sk.subspan(p.dimension), pk), "secret key embedded public key mismatch");
    require(zero(sk.subspan(4 * p.weight, p.dimension - 4 * p.weight)),
            "secret key has uninitialized/noncanonical reserved bytes");
    std::vector<bool> used(p.dimension, false);
    for (std::size_t i = 0; i < 2 * p.weight; ++i) {
        const auto index = static_cast<std::size_t>(sk[2 * i]) |
                           (static_cast<std::size_t>(sk[2 * i + 1]) << 8);
        require(index < p.dimension, "secret index is out of bounds");
        require(!used[index], "secret indices contain duplicates");
        used[index] = true;
    }
}

void roundtrip_and_rejection(ParameterSet set, Backend backend, std::size_t rounds) {
    TestRandom random;
    Kem kem(set, backend, random.source());
    const auto& p = kem.params();
    GuardedBuffer pk(p.public_key_bytes), sk(p.secret_key_bytes), ct(p.ciphertext_bytes);
    GuardedBuffer ss(p.message_bytes), recovered(p.message_bytes);
    for (std::size_t round = 0; round < rounds; ++round) {
        require_status(kem.keypair(pk.bytes(), sk.bytes()), Status::Ok, "keypair");
        check_canonical_key(p, pk.bytes(), sk.bytes());
        const Bytes original_pk(pk.bytes().begin(), pk.bytes().end());
        const Bytes original_sk(sk.bytes().begin(), sk.bytes().end());
        require_status(kem.encapsulate(pk.bytes(), ct.bytes(), ss.bytes()), Status::Ok, "encapsulate");
        require(random.last_size == p.message_bytes, "encapsulation entropy request changed");
        const auto expected_success = sha256({std::span(random.last).first(p.message_bytes), ct.bytes()});
        require(equal(ss.bytes(), std::span(expected_success).first(p.message_bytes)),
                "success secret is not SHA256(message || ciphertext)");
        const Bytes original_ct(ct.bytes().begin(), ct.bytes().end());
        require_status(kem.decapsulate(sk.bytes(), ct.bytes(), recovered.bytes()), Status::Ok, "decapsulate");
        require(equal(ss.bytes(), recovered.bytes()), "roundtrip shared secrets differ");
        require(equal(pk.bytes(), original_pk) && equal(sk.bytes(), original_sk) && equal(ct.bytes(), original_ct),
                "an input buffer was modified");

        if (round == 0) {
            const std::array offsets{std::size_t{0}, p.dimension / 2, p.dimension - 1,
                                     p.dimension, p.ciphertext_bytes / 2, p.ciphertext_bytes - 1};
            const auto hashed_sk = sha256({sk.bytes()});
            for (const auto offset : offsets) {
                Bytes altered = original_ct;
                altered[offset] ^= 0x80;
                const auto expected = sha256({hashed_sk, altered});
                require_status(kem.decapsulate(sk.bytes(), altered, recovered.bytes()), Status::Ok,
                               "tampered ciphertext implicit rejection");
                require(equal(recovered.bytes(), std::span(expected).first(p.message_bytes)),
                        "tampered ciphertext did not produce specified rejection secret");
                require(!equal(recovered.bytes(), ss.bytes()), "tampered ciphertext retained valid secret");
                Bytes repeated(p.message_bytes);
                require_status(kem.decapsulate(sk.bytes(), altered, repeated), Status::Ok, "repeat rejection");
                require(equal(repeated, recovered.bytes()), "rejection secret is not deterministic");
            }
            for (const Byte invalid_coefficient : {Byte{251}, Byte{255}}) {
                Bytes altered = original_ct;
                altered[0] = invalid_coefficient;
                const auto expected = sha256({hashed_sk, altered});
                require_status(kem.decapsulate(sk.bytes(), altered, recovered.bytes()), Status::Ok,
                               "noncanonical c1 coefficient implicit rejection");
                require(equal(recovered.bytes(), std::span(expected).first(p.message_bytes)),
                        "noncanonical coefficient did not select rejection secret");
            }
        }
    }
    pk.check("pk"); sk.check("sk"); ct.check("ct"); ss.check("ss"); recovered.check("recovered");
}

void invalid_lengths(ParameterSet set) {
    Kem kem(set, Backend::Portable);
    const auto& p = kem.params();
    GuardedBuffer pk(p.public_key_bytes), sk(p.secret_key_bytes), ct(p.ciphertext_bytes), ss(p.message_bytes);
    require_status(kem.keypair(pk.bytes(), sk.bytes()), Status::Ok, "length setup keypair");
    require_status(kem.encapsulate(pk.bytes(), ct.bytes(), ss.bytes()), Status::Ok, "length setup encapsulate");
    const Bytes valid_pk(pk.bytes().begin(), pk.bytes().end());
    const Bytes valid_sk(sk.bytes().begin(), sk.bytes().end());
    const Bytes valid_ct(ct.bytes().begin(), ct.bytes().end());

    // All spans have real backing storage: malformed lengths must not require
    // invalid pointers or violate std::span's valid-range precondition.
    for (const auto size : {std::size_t{0}, p.public_key_bytes - 1, p.public_key_bytes + 1}) {
        GuardedBuffer wrong(size);
        sk.reset();
        require_status(kem.keypair(wrong.bytes(), sk.bytes()), Status::InvalidArgument, "wrong keypair pk length");
        require(zero(sk.bytes()), "correct-size secret key not cleared on bad pk length");
        ct.reset(); ss.reset();
        require_status(kem.encapsulate(wrong.bytes(), ct.bytes(), ss.bytes()), Status::InvalidArgument,
                       "wrong encapsulate pk length");
        require(zero(ct.bytes()) && zero(ss.bytes()), "encapsulate outputs not cleared on bad pk length");
        wrong.check("wrong pk length");
    }
    for (const auto size : {std::size_t{0}, p.secret_key_bytes - 1, p.secret_key_bytes + 1}) {
        GuardedBuffer wrong(size);
        pk.reset();
        require_status(kem.keypair(pk.bytes(), wrong.bytes()), Status::InvalidArgument, "wrong keypair sk length");
        require(zero(pk.bytes()), "correct-size public key not cleared on bad sk length");
        ss.reset();
        require_status(kem.decapsulate(wrong.bytes(), valid_ct, ss.bytes()), Status::InvalidArgument,
                       "wrong decapsulate sk length");
        require(zero(ss.bytes()), "decapsulate output not cleared on bad sk length");
        wrong.check("wrong sk length");
    }
    for (const auto size : {std::size_t{0}, p.ciphertext_bytes - 1, p.ciphertext_bytes + 1}) {
        GuardedBuffer wrong(size);
        ss.reset();
        require_status(kem.encapsulate(valid_pk, wrong.bytes(), ss.bytes()), Status::InvalidArgument,
                       "wrong encapsulate ct length");
        require(zero(ss.bytes()), "secret not cleared on bad ct output length");
        ss.reset();
        require_status(kem.decapsulate(valid_sk, wrong.bytes(), ss.bytes()), Status::InvalidArgument,
                       "wrong decapsulate ct length");
        require(zero(ss.bytes()), "secret not cleared on bad ct input length");
        wrong.check("wrong ct length");
    }
    for (const auto size : {std::size_t{0}, p.message_bytes - 1, p.message_bytes + 1}) {
        GuardedBuffer wrong(size);
        ct.reset();
        require_status(kem.encapsulate(valid_pk, ct.bytes(), wrong.bytes()), Status::InvalidArgument,
                       "wrong encapsulate secret length");
        require(zero(ct.bytes()), "ct not cleared on bad secret output length");
        require_status(kem.decapsulate(valid_sk, valid_ct, wrong.bytes()), Status::InvalidArgument,
                       "wrong decapsulate secret length");
        wrong.check("wrong secret length");
    }
    pk.check("pk length tests"); sk.check("sk length tests"); ct.check("ct length tests"); ss.check("ss length tests");
}

void invalid_keys_and_entropy(ParameterSet set) {
    TestRandom random;
    Kem kem(set, Backend::Portable, random.source());
    const auto& p = kem.params();
    Bytes pk(p.public_key_bytes), sk(p.secret_key_bytes), ct(p.ciphertext_bytes), ss(p.message_bytes);
    require_status(kem.keypair(pk, sk), Status::Ok, "validation setup keypair");
    require_status(kem.encapsulate(pk, ct, ss), Status::Ok, "validation setup encapsulate");
    const auto calls = random.calls;
    for (const Byte bad_coefficient : {Byte{251}, Byte{255}}) {
        Bytes bad_pk = pk;
        bad_pk[lac::seed_bytes] = bad_coefficient;
        GuardedBuffer bad_ct(p.ciphertext_bytes), bad_ss(p.message_bytes);
        require_status(kem.encapsulate(bad_pk, bad_ct.bytes(), bad_ss.bytes()), Status::InvalidKey,
                       "invalid public coefficient");
        require(zero(bad_ct.bytes()) && zero(bad_ss.bytes()), "invalid-key outputs not cleared");
        require(random.calls == calls, "invalid key consumed entropy before validation");
        bad_ct.check("invalid pk ct"); bad_ss.check("invalid pk ss");
    }
    std::vector<Bytes> invalid{sk, sk, sk};
    invalid[0][0] = static_cast<Byte>(p.dimension & 0xff);
    invalid[0][1] = static_cast<Byte>(p.dimension >> 8);
    invalid[1][2] = invalid[1][0]; invalid[1][3] = invalid[1][1];
    invalid[2][p.dimension + lac::seed_bytes] = 251;
    if (4 * p.weight < p.dimension) {
        invalid.push_back(sk);
        invalid.back()[4 * p.weight] = 1;
    }
    for (const auto& bad_sk : invalid) {
        GuardedBuffer output(p.message_bytes);
        require_status(kem.decapsulate(bad_sk, ct, output.bytes()), Status::InvalidKey, "invalid secret key");
        require(zero(output.bytes()), "invalid secret-key output not cleared");
        output.check("invalid secret key output");
    }

    random.fail = true;
    GuardedBuffer failed_pk(p.public_key_bytes), failed_sk(p.secret_key_bytes);
    GuardedBuffer failed_ct(p.ciphertext_bytes), failed_ss(p.message_bytes);
    require_status(kem.keypair(failed_pk.bytes(), failed_sk.bytes()), Status::CryptoFailure, "failed keypair RNG");
    require(zero(failed_pk.bytes()) && zero(failed_sk.bytes()), "failed RNG leaked keypair output");
    require_status(kem.encapsulate(pk, failed_ct.bytes(), failed_ss.bytes()), Status::CryptoFailure,
                   "failed encapsulate RNG");
    require(zero(failed_ct.bytes()) && zero(failed_ss.bytes()), "failed RNG leaked encapsulate output");
    failed_pk.check("failed pk"); failed_sk.check("failed sk");
    failed_ct.check("failed ct"); failed_ss.check("failed ss");
    // Decapsulation does not need fresh entropy, even after source failure.
    require_status(kem.decapsulate(sk, ct, failed_ss.bytes()), Status::Ok, "decapsulate with failed RNG");
    require(equal(ss, failed_ss.bytes()), "RNG failure altered deterministic decapsulation");
}

void overlap_contract(ParameterSet set) {
    Kem kem(set, Backend::Portable);
    const auto& p = kem.params();
    Bytes pk(p.public_key_bytes), sk(p.secret_key_bytes), ct(p.ciphertext_bytes), ss(p.message_bytes);
    require_status(kem.keypair(pk, sk), Status::Ok, "overlap setup keypair");
    require_status(kem.encapsulate(pk, ct, ss), Status::Ok, "overlap setup encapsulate");
    GuardedBuffer buffer(p.secret_key_bytes + p.ciphertext_bytes + p.public_key_bytes + 32);
    auto memory = buffer.bytes();
    require_status(kem.keypair(memory.first(p.public_key_bytes), memory.subspan(1, p.secret_key_bytes)),
                   Status::InvalidArgument, "overlapping keypair outputs");
    std::copy(pk.begin(), pk.end(), memory.begin());
    require_status(kem.encapsulate(memory.first(p.public_key_bytes), memory.subspan(1, p.ciphertext_bytes), ss),
                   Status::InvalidArgument, "overlapping pk and ct");
    std::copy(pk.begin(), pk.end(), memory.begin());
    require_status(kem.encapsulate(memory.first(p.public_key_bytes), ct, memory.subspan(1, p.message_bytes)),
                   Status::InvalidArgument, "overlapping pk and ss");
    require_status(kem.encapsulate(pk, memory.first(p.ciphertext_bytes), memory.subspan(1, p.message_bytes)),
                   Status::InvalidArgument, "overlapping encapsulate outputs");
    std::copy(sk.begin(), sk.end(), memory.begin());
    require_status(kem.decapsulate(memory.first(p.secret_key_bytes), ct, memory.subspan(1, p.message_bytes)),
                   Status::InvalidArgument, "overlapping sk and ss");
    std::copy(ct.begin(), ct.end(), memory.begin());
    require_status(kem.decapsulate(sk, memory.first(p.ciphertext_bytes), memory.subspan(1, p.message_bytes)),
                   Status::InvalidArgument, "overlapping ct and ss");
    std::copy(sk.begin(), sk.end(), memory.begin());
    require_status(kem.decapsulate(memory.first(p.secret_key_bytes), memory.subspan(1, p.ciphertext_bytes), ss),
                   Status::InvalidArgument, "overlapping decapsulate inputs");
    buffer.check("overlap workspace");

    // Exact adjacency is disjoint and must remain valid.
    Bytes adjacent(p.public_key_bytes + p.secret_key_bytes);
    auto joined = std::span(adjacent);
    require_status(kem.keypair(joined.first(p.public_key_bytes), joined.subspan(p.public_key_bytes)),
                   Status::Ok, "adjacent keypair outputs");
}

void differential_backends(ParameterSet set) {
    TestRandom left_random, right_random;
    Kem portable(set, Backend::Portable, left_random.source());
    Kem automatic(set, Backend::Auto, right_random.source());
    const auto& p = portable.params();
    Bytes pk1(p.public_key_bytes), pk2(p.public_key_bytes), sk1(p.secret_key_bytes), sk2(p.secret_key_bytes);
    Bytes ct1(p.ciphertext_bytes), ct2(p.ciphertext_bytes), ss1(p.message_bytes), ss2(p.message_bytes);
    Bytes recovered1(p.message_bytes), recovered2(p.message_bytes);
    for (int round = 0; round < 8; ++round) {
        require_status(portable.keypair(pk1, sk1), Status::Ok, "portable differential keypair");
        require_status(automatic.keypair(pk2, sk2), Status::Ok, "automatic differential keypair");
        require(pk1 == pk2 && sk1 == sk2, "backend deterministic keypair mismatch");
        require_status(portable.encapsulate(pk1, ct1, ss1), Status::Ok, "portable differential encapsulate");
        require_status(automatic.encapsulate(pk2, ct2, ss2), Status::Ok, "automatic differential encapsulate");
        require(ct1 == ct2 && ss1 == ss2, "backend deterministic encapsulation mismatch");
        require_status(portable.decapsulate(sk1, ct2, recovered1), Status::Ok, "portable cross-decapsulate");
        require_status(automatic.decapsulate(sk2, ct1, recovered2), Status::Ok, "automatic cross-decapsulate");
        require(recovered1 == ss2 && recovered2 == ss1, "backend cross-decapsulation mismatch");
    }
}

void default_entropy_smoke(ParameterSet set) {
    Kem kem(set);
    const auto& p = kem.params();
    Bytes pk(p.public_key_bytes), sk(p.secret_key_bytes), ct(p.ciphertext_bytes);
    Bytes ss(p.message_bytes), recovered(p.message_bytes);
    require_status(kem.keypair(pk, sk), Status::Ok, "OpenSSL entropy keypair");
    require_status(kem.encapsulate(pk, ct, ss), Status::Ok, "OpenSSL entropy encapsulate");
    require_status(kem.decapsulate(sk, ct, recovered), Status::Ok, "OpenSSL entropy decapsulate");
    require(ss == recovered, "OpenSSL entropy roundtrip mismatch");
}

void check_moved_from(Kem& kem, const lac::Parameters& p,
                      const Bytes& valid_pk, const Bytes& valid_sk, const Bytes& valid_ct) {
    require(kem.backend_name() == "moved-from", "move source still owns a backend");
    // A moved-from instance no longer knows its former parameter set, so its
    // contract clears every supplied output, including noncanonical lengths.
    for (const bool exact : {true, false}) {
        GuardedBuffer pk(exact ? p.public_key_bytes : 3);
        GuardedBuffer sk(exact ? p.secret_key_bytes : p.secret_key_bytes + 1);
        GuardedBuffer ct(exact ? p.ciphertext_bytes : p.ciphertext_bytes + 1);
        GuardedBuffer ss(exact ? p.message_bytes : 1);
        require_status(kem.keypair(pk.bytes(), sk.bytes()), Status::InvalidArgument,
                       "moved-from keypair");
        require(zero(pk.bytes()) && zero(sk.bytes()), "moved-from keypair outputs not cleared");
        require_status(kem.encapsulate(valid_pk, ct.bytes(), ss.bytes()), Status::InvalidArgument,
                       "moved-from encapsulate");
        require(zero(ct.bytes()) && zero(ss.bytes()), "moved-from encapsulate outputs not cleared");
        ss.reset();
        require_status(kem.decapsulate(valid_sk, valid_ct, ss.bytes()), Status::InvalidArgument,
                       "moved-from decapsulate");
        require(zero(ss.bytes()), "moved-from decapsulate output not cleared");
        pk.check("moved-from pk"); sk.check("moved-from sk");
        ct.check("moved-from ct"); ss.check("moved-from ss");
    }
    require_status(kem.keypair({}, {}), Status::InvalidArgument, "moved-from empty keypair outputs");
    require_status(kem.encapsulate(valid_pk, {}, {}), Status::InvalidArgument,
                   "moved-from empty encapsulate outputs");
    require_status(kem.decapsulate(valid_sk, valid_ct, {}), Status::InvalidArgument,
                   "moved-from empty decapsulate output");
}

void move_lifecycle(ParameterSet set) {
    TestRandom random;
    Kem source(set, Backend::Portable, random.source());
    const auto& p = source.params();
    Bytes pk(p.public_key_bytes), sk(p.secret_key_bytes), ct(p.ciphertext_bytes);
    Bytes ss(p.message_bytes), recovered(p.message_bytes);
    // Populate the cached public polynomial and OpenSSL contexts before moving.
    require_status(source.keypair(pk, sk), Status::Ok, "move setup keypair");
    require_status(source.encapsulate(pk, ct, ss), Status::Ok, "move setup encapsulate");
    const auto original_pk = pk, original_sk = sk, original_ct = ct;

    Kem constructed(std::move(source));
    require(constructed.params().id == set && constructed.backend_name() == "portable",
            "move constructor lost parameters or backend");
    check_moved_from(source, p, pk, sk, ct);
    require(pk == original_pk && sk == original_sk && ct == original_ct,
            "moved-from calls modified disjoint input buffers");
    require_status(constructed.decapsulate(sk, ct, recovered), Status::Ok,
                   "move-constructed decapsulate existing ciphertext");
    require(ss == recovered, "move constructor lost existing key/ciphertext behavior");
    const auto calls_before = random.calls;
    require_status(constructed.encapsulate(pk, ct, ss), Status::Ok, "move-constructed encapsulate");
    require(random.calls == calls_before + 1, "move constructor lost custom entropy source");
    require_status(constructed.decapsulate(sk, ct, recovered), Status::Ok, "move-constructed roundtrip");
    require(ss == recovered, "move-constructed roundtrip mismatch");

    // Replace a previously used instance with a different parameter set. This
    // tests destruction of the old state and transfer of the new dimensions.
    TestRandom replaced_random;
    const auto other_set = set == ParameterSet::Light ? ParameterSet::Lac256 : ParameterSet::Light;
    Kem assigned(other_set, Backend::Auto, replaced_random.source());
    Bytes replaced_pk(assigned.params().public_key_bytes), replaced_sk(assigned.params().secret_key_bytes);
    require_status(assigned.keypair(replaced_pk, replaced_sk), Status::Ok, "move assignment old state");
    const auto replaced_calls = replaced_random.calls;
    assigned = std::move(constructed);
    require(assigned.params().id == set && assigned.backend_name() == "portable",
            "move assignment retained the replaced parameters or backend");
    check_moved_from(constructed, p, pk, sk, ct);
    require_status(assigned.decapsulate(sk, ct, recovered), Status::Ok,
                   "move-assigned decapsulate existing ciphertext");
    require(ss == recovered, "move assignment lost existing key/ciphertext behavior");
    require_status(assigned.keypair(pk, sk), Status::Ok, "move-assigned keypair");
    require_status(assigned.encapsulate(pk, ct, ss), Status::Ok, "move-assigned encapsulate");
    require_status(assigned.decapsulate(sk, ct, recovered), Status::Ok, "move-assigned roundtrip");
    require(ss == recovered, "move-assigned roundtrip mismatch");
    require(replaced_random.calls == replaced_calls, "move assignment retained the replaced entropy source");

    // An empty move source remains assignable and can become usable again.
    source = std::move(assigned);
    require_status(source.decapsulate(sk, ct, recovered), Status::Ok, "reassigned move source");
    require(ss == recovered, "reassigned move source roundtrip mismatch");
    check_moved_from(assigned, p, pk, sk, ct);
}
} // namespace

int main() {
    try {
        for (const auto set : all_sets) {
            const auto name = lac::parameters(set).name;
            try {
                roundtrip_and_rejection(set, Backend::Portable, 8);
                roundtrip_and_rejection(set, Backend::Auto, 8);
                invalid_lengths(set);
                invalid_keys_and_entropy(set);
                overlap_contract(set);
                differential_backends(set);
                default_entropy_smoke(set);
                move_lifecycle(set);
            } catch (const std::exception& error) {
                throw std::runtime_error(std::string(name) + ": " + error.what());
            }
            std::cout << "PASS " << name << ": roundtrip, transcript, rejection, bounds, keys, RNG, overlap, backends, moves\n";
        }
        std::vector<std::future<void>> workers;
        for (const auto set : all_sets) {
            workers.emplace_back(std::async(std::launch::async, [set] {
                roundtrip_and_rejection(set, Backend::Auto, 4);
            }));
        }
        for (auto& worker : workers) worker.get();
        std::cout << "PASS separate-instance concurrent use (four parameter sets)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
