#include "kem.hpp"
#include "crypto.hpp"
#include "bch.hpp"
#include "kernels.hpp"
#ifdef LAC_BUILD_TESTING
#include "testing.hpp"
#endif
#include <openssl/crypto.h>
#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace lac {
namespace {
constexpr std::array parameter_sets{
    Parameters{ParameterSet::Light, "LAC_LIGHT", 512, 64, 245, 16, 544, 1056, 664, 3, 304},
    Parameters{ParameterSet::Lac128, "LAC128", 512, 128, 590, 16, 544, 1056, 704, 8, 384},
    Parameters{ParameterSet::Lac192, "LAC192", 1024, 128, 495, 32, 1056, 2080, 1352, 9, 656},
    Parameters{ParameterSet::Lac256, "LAC256", 1024, 192, 815, 32, 1056, 2080, 1448, 21, 848}
};

template<class T, class U>
bool overlaps(std::span<T> a, std::span<U> b) noexcept {
    if (a.empty() || b.empty()) return false;
    const auto x = reinterpret_cast<std::uintptr_t>(a.data());
    const auto y = reinterpret_cast<std::uintptr_t>(b.data());
    return x <= y ? y - x < a.size_bytes() : x - y < b.size_bytes();
}

std::uint16_t load16(const Byte* in) noexcept {
    return static_cast<std::uint16_t>(in[0] | (static_cast<unsigned>(in[1]) << 8));
}
void store16(Byte* out, std::uint16_t value) noexcept {
    out[0] = static_cast<Byte>(value);
    out[1] = static_cast<Byte>(value >> 8);
}

// Legacy wire format: 64-coefficient blocks pair [i] with [i+32].
// A short final block pairs consecutive coefficients. Preserve this layout.
void compress(std::span<const Byte> in, std::span<Byte> out) noexcept {
    const std::size_t end = in.size() / 64 * 64;
    for (std::size_t i = 0; i < end; i += 64)
        for (std::size_t j = 0; j < 32; ++j)
            out[i / 2 + j] = static_cast<Byte>((in[i + j] >> 4) | (in[i + 32 + j] & 0xf0));
    for (std::size_t i = end; i < in.size(); i += 2)
        out[i / 2] = static_cast<Byte>((in[i] >> 4) | (in[i + 1] & 0xf0));
}

void decompress(std::span<const Byte> in, std::span<Byte> out) noexcept {
    const std::size_t end = out.size() / 64 * 64;
    for (std::size_t i = 0; i < end; i += 64)
        for (std::size_t j = 0; j < 32; ++j) {
            const Byte value = in[i / 2 + j];
            out[i + j] = static_cast<Byte>((value << 4) | 8);
            out[i + j + 32] = static_cast<Byte>((value & 0xf0) | 8);
        }
    for (std::size_t i = end; i < out.size(); i += 2) {
        out[i] = static_cast<Byte>((in[i / 2] << 4) | 8);
        out[i + 1] = static_cast<Byte>((in[i / 2] & 0xf0) | 8);
    }
}

std::pair<std::uint16_t, Byte> light_parity(std::span<const Byte> message) noexcept {
    std::uint16_t columns = 0;
    Byte rows = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        const auto word = load16(message.data() + 2 * i);
        columns ^= word;
        rows |= static_cast<Byte>((std::popcount(word) & 1) << i);
    }
    return {columns, rows};
}

struct SecretWorkspace {
    std::array<Byte, 96> seeds{};
    std::array<Byte, 32> seed{};
    std::array<Byte, 1630> samples{};
    std::array<std::uint16_t, max_dimension> permutation{};
    std::array<std::uint16_t, 2 * max_weight> secret_positions{};
    std::array<std::uint16_t, 2 * max_weight> ephemeral_positions{};
    std::array<std::uint16_t, 2 * max_weight> noise_positions{};
    std::array<Byte, max_dimension> seen{};
    std::array<Byte, max_dimension> noise{};
    std::array<Byte, max_dimension> c1{};
    std::array<Byte, max_dimension> c2{};
    std::array<Byte, max_dimension> product{};
    std::array<Byte, max_code_bytes> code{};
    std::array<Byte, max_message_bytes> message{};
    std::array<Byte, max_ciphertext_bytes> verified_ciphertext{};
    std::array<Byte, 32> candidate_secret{};
    std::array<Byte, 32> rejection_secret{};
    std::array<Byte, 32> secret_key_hash{};
    detail::PolyWorkspace polynomial{};
    void clear() noexcept {
        detail::cleanse({reinterpret_cast<Byte*>(this), sizeof(*this)});
    }
};
struct ClearOnExit {
    SecretWorkspace& memory;
    ~ClearOnExit() { memory.clear(); }
};
} // namespace

const Parameters& parameters(ParameterSet set) {
    for (const auto& p : parameter_sets) if (p.id == set) return p;
    throw std::invalid_argument("Unknown LAC parameter set");
}

std::string_view status_message(Status status) noexcept {
    switch (status) {
    case Status::Ok: return "ok";
    case Status::InvalidArgument: return "invalid size or overlapping buffers";
    case Status::InvalidKey: return "invalid serialized key";
    case Status::CryptoFailure: return "random source or cryptographic operation failed";
    }
    return "unknown status";
}

struct Kem::Impl {
    const Parameters& p;
    RandomSource rng;
    detail::Crypto crypto;
    detail::BchCodec bch;
    detail::Multiply multiply = detail::multiply_portable;
    std::string_view backend = "portable";
    SecretWorkspace w{};
    // Public, per-instance cache; never caches a secret or an ephemeral seed.
    std::array<Byte, max_dimension> public_a{};
    std::array<Byte, 32> public_seed{};
    bool a_cached = false;

    Impl(ParameterSet set, Backend requested, RandomSource source)
        : p(parameters(set)), rng(source), bch(set) {
        if (requested != Backend::Auto && requested != Backend::Portable && requested != Backend::Avx2)
            throw std::invalid_argument("Unknown LAC backend");
        if (requested == Backend::Avx2 && !detail::avx2_available())
            throw std::invalid_argument("AVX2 backend unavailable on this build/CPU");
#ifdef LAC_HAVE_AVX2
        if (requested != Backend::Portable && detail::avx2_available()) {
            multiply = detail::multiply_avx2;
            backend = "avx2";
        }
#endif
    }
    ~Impl() { w.clear(); }

    bool random(std::span<Byte> output) noexcept {
        return rng.fill ? rng.fill(output, rng.context) : detail::Crypto::random(output);
    }

    bool valid_public_key(std::span<const Byte> pk) const noexcept {
        unsigned bad = 0;
        for (std::size_t i = 32; i < pk.size(); ++i) bad |= static_cast<unsigned>(pk[i] >= modulus);
        return bad == 0;
    }

    bool parse_secret(std::span<const Byte> sk) noexcept {
        std::fill(w.seen.begin(), w.seen.end(), 0);
        unsigned bad = 0;
        for (std::size_t i = 0; i < 2 * p.weight; ++i) {
            const auto position = load16(sk.data() + 2 * i);
            bad |= static_cast<unsigned>(position >= p.dimension);
            const auto safe_position = position & (p.dimension - 1);
            bad |= w.seen[safe_position];
            w.seen[safe_position] = 1;
            w.secret_positions[i] = static_cast<std::uint16_t>(safe_position);
        }
        for (std::size_t i = 4 * p.weight; i < p.dimension; ++i) bad |= sk[i];
        bad |= static_cast<unsigned>(!valid_public_key(sk.subspan(p.dimension)));
        return bad == 0;
    }

    bool expand_a(std::span<const Byte, 32> seed) noexcept {
        if (a_cached && std::equal(seed.begin(), seed.end(), public_seed.begin())) return true;
        a_cached = false;
        if (!crypto.expand(std::span(public_a).first(p.dimension), seed)) return false;
        std::array<Byte, 128> extra{};
        if (!crypto.expand(extra, std::span<const Byte, 32>(public_a.data(), 32))) return false;
        std::size_t used = 0;
        for (std::size_t i = 0; i < p.dimension; ++i) {
            while (public_a[i] >= modulus) {
                if (used == extra.size()) {
                    if (!crypto.expand(extra, std::span<const Byte, 32>(extra.data(), 32))) return false;
                    used = 0;
                }
                public_a[i] = extra[used++];
            }
        }
        std::copy(seed.begin(), seed.end(), public_seed.begin());
        a_cached = true;
        return true;
    }

    bool sample_positions(std::span<Byte, 32> seed,
                          std::span<std::uint16_t> output) noexcept {
        for (std::size_t i = 0; i < p.dimension; ++i)
            w.permutation[i] = static_cast<std::uint16_t>(i);
        std::size_t selected = 0;
        while (selected < output.size()) {
            auto sample = std::span(w.samples).first(2 * p.sample_words);
            if (!crypto.expand(sample, seed)) return false;
            for (std::size_t i = 0; i < p.sample_words && selected < output.size(); ++i) {
                const auto index = load16(sample.data() + 2 * i) & (p.dimension - 1);
                const auto accepted = static_cast<std::size_t>(index >= selected);
                const auto position = index >= selected ? index : selected;
                std::swap(w.permutation[selected], w.permutation[position]);
                selected += accepted;
            }
            if (selected < output.size()) std::copy_n(sample.begin(), 32, seed.begin());
        }
        std::copy_n(w.permutation.begin(), output.size(), output.begin());
        return true;
    }

    bool sample_noise(std::span<Byte, 32> seed) noexcept {
        auto positions = std::span(w.noise_positions).first(2 * p.weight);
        if (!sample_positions(seed, positions)) return false;
        std::fill_n(w.noise.begin(), p.dimension, 0);
        for (std::size_t i = 0; i < p.weight; ++i) {
            w.noise[positions[i]] = 1;
            w.noise[positions[p.weight + i]] = static_cast<Byte>(modulus - 1);
        }
        return true;
    }

    bool encode(std::span<const Byte> message) noexcept {
        auto code = std::span(w.code).first(p.message_bytes + p.ecc_bytes);
        if (p.id == ParameterSet::Light) {
            std::copy(message.begin(), message.end(), code.begin());
            const auto [columns, rows] = light_parity(message);
            store16(code.data() + 16, columns);
            code[18] = rows;
        } else if (!bch.encode(message, code)) return false;
        const auto half = p.c2_coefficients / 2;
        for (std::size_t i = 0; i < half; ++i) {
            const auto encoded = 125 * ((code[i / 8] >> (i % 8)) & 1);
            // Preserve the supplied PKE's byte arithmetic as well as wire layout.
            w.noise[i] = static_cast<Byte>(w.noise[i] + encoded);
            w.noise[i + half] = static_cast<Byte>(w.noise[i + half] + encoded);
        }
        return true;
    }

    bool encrypt(std::span<const Byte> pk, std::span<const Byte> message,
                 std::span<const Byte, 32> seed, std::span<Byte> ct) noexcept {
        if (!expand_a(std::span<const Byte, 32>(pk.data(), 32)) ||
            !crypto.expand(w.seeds, seed)) return false;
        auto positions = std::span(w.ephemeral_positions).first(2 * p.weight);
        if (!sample_positions(std::span<Byte, 32>(w.seeds.data(), 32), positions) ||
            !sample_noise(std::span<Byte, 32>(w.seeds.data() + 32, 32))) return false;
        multiply(std::span(public_a).first(p.dimension), positions, p.weight,
                 std::span(w.noise).first(p.dimension), ct.first(p.dimension), w.polynomial);
        if (!sample_noise(std::span<Byte, 32>(w.seeds.data() + 64, 32)) || !encode(message)) return false;
        auto c2 = std::span(w.c2).first(p.c2_coefficients);
        multiply(pk.subspan(32), positions, p.weight,
                 std::span(w.noise).first(p.c2_coefficients), c2, w.polynomial);
        compress(c2, ct.subspan(p.dimension));
        return true;
    }

    bool decrypt(std::span<const Byte> ct, std::span<Byte> message) noexcept {
        // Ciphertext coefficients are public. Normalize before indexing kernels;
        // noncanonical encodings cannot pass the later bytewise re-encryption check.
        for (std::size_t i = 0; i < p.dimension; ++i)
            w.c1[i] = static_cast<Byte>(ct[i] % modulus);
        auto decoded = std::span(w.c2).first(p.c2_coefficients);
        decompress(ct.subspan(p.dimension), decoded);
        auto product = std::span(w.product).first(p.c2_coefficients);
        multiply(std::span(w.c1).first(p.dimension),
                 std::span(w.secret_positions).first(2 * p.weight), p.weight, {}, product, w.polynomial);
        std::fill(w.code.begin(), w.code.end(), 0);
        const auto half = p.c2_coefficients / 2;
        for (std::size_t i = 0; i < half; ++i) {
            int a = (decoded[i] - product[i] + modulus) % modulus;
            int b = (decoded[i + half] - product[i + half] + modulus) % modulus;
            a = a < 125 ? 250 - a : a;
            b = b < 125 ? 250 - b : b;
            const auto bit = static_cast<unsigned>(a + b - modulus < 125);
            w.code[i / 8] |= static_cast<Byte>(bit << (i % 8));
        }
        if (p.id == ParameterSet::Light) {
            auto [columns, rows] = light_parity(std::span(w.code).first(16));
            columns ^= load16(w.code.data() + 16);
            rows ^= w.code[18];
            for (std::size_t i = 0; i < 8; ++i) {
                const auto word = load16(w.code.data() + 2 * i);
                store16(w.code.data() + 2 * i, static_cast<std::uint16_t>(
                    word ^ (columns * ((rows >> i) & 1))));
            }
            std::copy_n(w.code.begin(), 16, message.begin());
            return true;
        }
        return bch.decode(std::span(w.code).first(p.message_bytes + p.ecc_bytes), message);
    }
};

Kem::Kem(ParameterSet set, Backend backend, RandomSource random)
    : impl_(std::make_unique<Impl>(set, backend, random)) {}
Kem::~Kem() = default;
Kem::Kem(Kem&&) noexcept = default;
Kem& Kem::operator=(Kem&&) noexcept = default;
const Parameters& Kem::params() const noexcept { return impl_ ? impl_->p : parameter_sets[0]; }
std::string_view Kem::backend_name() const noexcept { return impl_ ? impl_->backend : "moved-from"; }

Status Kem::keypair(std::span<Byte> pk, std::span<Byte> sk) noexcept {
    if (!impl_) {
        detail::cleanse(pk);
        detail::cleanse(sk);
        return Status::InvalidArgument;
    }
    auto& x = *impl_;
    ClearOnExit guard{x.w};
    const auto fail = [&](Status status) {
        if (pk.size() == x.p.public_key_bytes) detail::cleanse(pk);
        if (sk.size() == x.p.secret_key_bytes) detail::cleanse(sk);
        return status;
    };
    if (pk.size() != x.p.public_key_bytes || sk.size() != x.p.secret_key_bytes || overlaps(pk, sk))
        return fail(Status::InvalidArgument);
    if (!x.random(x.w.seed) || !x.crypto.expand(x.w.seeds, x.w.seed)) return fail(Status::CryptoFailure);
    std::fill(sk.begin(), sk.end(), 0);
    std::copy_n(x.w.seeds.begin(), 32, pk.begin());
    if (!x.expand_a(std::span<const Byte, 32>(pk.data(), 32)) ||
        !x.sample_positions(std::span<Byte, 32>(x.w.seeds.data() + 32, 32),
                            std::span(x.w.secret_positions).first(2 * x.p.weight)) ||
        !x.sample_noise(std::span<Byte, 32>(x.w.seeds.data() + 64, 32)))
        return fail(Status::CryptoFailure);
    for (std::size_t i = 0; i < 2 * x.p.weight; ++i) store16(sk.data() + 2 * i, x.w.secret_positions[i]);
    x.multiply(std::span(x.public_a).first(x.p.dimension),
               std::span(x.w.secret_positions).first(2 * x.p.weight), x.p.weight,
               std::span(x.w.noise).first(x.p.dimension), pk.subspan(32), x.w.polynomial);
    std::copy(pk.begin(), pk.end(), sk.begin() + static_cast<std::ptrdiff_t>(x.p.dimension));
    return Status::Ok;
}

Status Kem::encapsulate(std::span<const Byte> pk, std::span<Byte> ct, std::span<Byte> ss) noexcept {
    if (!impl_) {
        detail::cleanse(ct);
        detail::cleanse(ss);
        return Status::InvalidArgument;
    }
    auto& x = *impl_;
    ClearOnExit guard{x.w};
    const auto fail = [&](Status status) {
        if (ct.size() == x.p.ciphertext_bytes) detail::cleanse(ct);
        if (ss.size() == x.p.message_bytes) detail::cleanse(ss);
        return status;
    };
    if (pk.size() != x.p.public_key_bytes || ct.size() != x.p.ciphertext_bytes ||
        ss.size() != x.p.message_bytes || overlaps(pk, ct) || overlaps(pk, ss) || overlaps(ct, ss))
        return fail(Status::InvalidArgument);
    if (!x.valid_public_key(pk)) return fail(Status::InvalidKey);
    auto message = std::span(x.w.message).first(x.p.message_bytes);
    if (!x.random(message) || !x.crypto.digest(x.w.seed, {message, pk.first(32)}) ||
        !x.encrypt(pk, message, x.w.seed, ct) ||
        !x.crypto.digest(x.w.candidate_secret, {message, ct})) return fail(Status::CryptoFailure);
    std::copy_n(x.w.candidate_secret.begin(), ss.size(), ss.begin());
    return Status::Ok;
}

Status Kem::decapsulate(std::span<const Byte> sk, std::span<const Byte> ct, std::span<Byte> ss) noexcept {
    if (!impl_) {
        detail::cleanse(ss);
        return Status::InvalidArgument;
    }
    auto& x = *impl_;
    ClearOnExit guard{x.w};
    const auto fail = [&](Status status) {
        if (ss.size() == x.p.message_bytes) detail::cleanse(ss);
        return status;
    };
    if (sk.size() != x.p.secret_key_bytes || ct.size() != x.p.ciphertext_bytes ||
        ss.size() != x.p.message_bytes || overlaps(sk, ct) || overlaps(sk, ss) || overlaps(ct, ss))
        return fail(Status::InvalidArgument);
    if (!x.parse_secret(sk)) return fail(Status::InvalidKey);
    const auto pk = sk.subspan(x.p.dimension);
    auto message = std::span(x.w.message).first(x.p.message_bytes);
    const bool decoded = x.decrypt(ct, message);
    auto verified = std::span(x.w.verified_ciphertext).first(x.p.ciphertext_bytes);
    // Both candidates are always derived, including on invalid ciphertext.
    if (!x.crypto.digest(x.w.seed, {message, pk.first(32)}) ||
        !x.encrypt(pk, message, x.w.seed, verified) ||
        !x.crypto.digest(x.w.candidate_secret, {message, ct}) ||
        !x.crypto.digest(x.w.secret_key_hash, {sk}) ||
        !x.crypto.digest(x.w.rejection_secret, {x.w.secret_key_hash, ct}))
        return fail(Status::CryptoFailure);
    const unsigned matches = static_cast<unsigned>(CRYPTO_memcmp(ct.data(), verified.data(), ct.size()) == 0);
    const auto mask = static_cast<Byte>(0U - (matches & static_cast<unsigned>(decoded)));
    for (std::size_t i = 0; i < ss.size(); ++i)
        ss[i] = static_cast<Byte>((x.w.candidate_secret[i] & mask) |
                                 (x.w.rejection_secret[i] & static_cast<Byte>(~mask)));
    return Status::Ok;
}

#ifdef LAC_BUILD_TESTING
struct TestingAccess {
    static Status decrypt(Kem& kem, std::span<const Byte> sk, std::span<const Byte> ct,
                          std::span<Byte> message) {
        auto& x = *kem.impl_;
        ClearOnExit guard{x.w};
        if (sk.size() != x.p.secret_key_bytes || ct.size() != x.p.ciphertext_bytes ||
            message.size() != x.p.message_bytes) return Status::InvalidArgument;
        if (!x.parse_secret(sk)) return Status::InvalidKey;
        return x.decrypt(ct, message) ? Status::Ok : Status::InvalidKey;
    }
    static Status encrypt(Kem& kem, std::span<const Byte> pk, std::span<const Byte> message,
                          std::span<const Byte> seed, std::span<Byte> ct) {
        auto& x = *kem.impl_;
        ClearOnExit guard{x.w};
        if (pk.size() != x.p.public_key_bytes || ct.size() != x.p.ciphertext_bytes ||
            message.size() != x.p.message_bytes || seed.size() != 32) return Status::InvalidArgument;
        if (!x.valid_public_key(pk)) return Status::InvalidKey;
        return x.encrypt(pk, message, std::span<const Byte, 32>(seed.data(), 32), ct)
            ? Status::Ok : Status::CryptoFailure;
    }
};
namespace testing {
Status pke_decrypt(ParameterSet set, Backend backend, std::span<const Byte> sk,
                   std::span<const Byte> ct, std::span<Byte> message) {
    Kem kem(set, backend);
    return TestingAccess::decrypt(kem, sk, ct, message);
}
Status pke_encrypt_seed(ParameterSet set, Backend backend, std::span<const Byte> pk,
                       std::span<const Byte> message, std::span<const Byte> seed, std::span<Byte> ct) {
    Kem kem(set, backend);
    return TestingAccess::encrypt(kem, pk, message, seed, ct);
}
}
#endif
} // namespace lac
