#include "lac/kem.hpp"
#include "lac/testing.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using lac::Byte;
using Bytes = std::vector<Byte>;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

bool equal(std::span<const Byte> left, std::span<const Byte> right) {
    return std::equal(left.begin(), left.end(), right.begin(), right.end());
}

void require_ok(lac::Status status, const char* operation) {
    require(status == lac::Status::Ok,
            std::string(operation) + ": " + std::string(lac::status_message(status)));
}

std::array<Byte, 32> sha256(std::initializer_list<std::span<const Byte>> parts) {
    Bytes concatenated;
    for (const auto part : parts) concatenated.insert(concatenated.end(), part.begin(), part.end());
    std::array<Byte, 32> result{};
    unsigned int size = 0;
    require(EVP_Digest(concatenated.data(), concatenated.size(), result.data(), &size,
                       EVP_sha256(), nullptr) == 1 && size == result.size(),
            "independent SHA-256 failed");
    return result;
}

class VectorReader {
public:
    explicit VectorReader(const std::filesystem::path& path) {
        std::ifstream input(path, std::ios::binary);
        require(input.is_open(), "cannot open " + path.string());
        const std::string raw{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        std::string hex;
        for (const unsigned char c : raw) if (!std::isspace(c)) hex.push_back(static_cast<char>(c));
        require(hex.size() % 2 == 0, "odd length in vector hex stream");
        bytes_.reserve(hex.size() / 2);
        for (std::size_t i = 0; i < hex.size(); i += 2)
            bytes_.push_back(static_cast<Byte>((digit(hex[i]) << 4) | digit(hex[i + 1])));
    }

    Bytes field(std::size_t expected, const char* name) {
        require(bytes_.size() - position_ >= 4, std::string("missing field length: ") + name);
        std::uint32_t size = 0;
        for (unsigned int i = 0; i < 4; ++i) size = (size << 8) | bytes_[position_++];
        require(size == expected, std::string("unexpected field length: ") + name);
        require(size <= bytes_.size() - position_, std::string("truncated field: ") + name);
        Bytes output(bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
                     bytes_.begin() + static_cast<std::ptrdiff_t>(position_ + size));
        position_ += size;
        return output;
    }
    bool done() const { return position_ == bytes_.size(); }

private:
    static unsigned int digit(char c) {
        if (c >= '0' && c <= '9') return static_cast<unsigned int>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned int>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned int>(c - 'A' + 10);
        throw std::runtime_error("invalid character in vector hex stream");
    }
    Bytes bytes_;
    std::size_t position_ = 0;
};

void check_header(VectorReader& reader) {
    const auto seed = reader.field(48, "legacy test generator seed");
    for (std::size_t i = 0; i < seed.size(); ++i)
        require(seed[i] == i, "unexpected vector header seed");
    // This is metadata, not a reproducible keygen seed: the original DLL used
    // OpenSSL RAND_bytes rather than the DRBG initialized by the vector driver.
}

void canonicalize_legacy_key(const lac::Parameters& p, Bytes& sk, const Bytes& pk) {
    require(equal(std::span(sk).subspan(p.dimension), pk), "legacy embedded public key mismatch");
    // Old DLL serialized uninitialized reserved bytes. Do not copy that behavior
    // into the production API: only these tests explicitly migrate that padding.
    std::fill(sk.begin() + static_cast<std::ptrdiff_t>(4 * p.weight),
              sk.begin() + static_cast<std::ptrdiff_t>(p.dimension), Byte{0});
}

void verify_pke(const std::filesystem::path& path, lac::ParameterSet set, lac::Backend backend) {
    const auto& p = lac::parameters(set);
    VectorReader reader(path);
    check_header(reader);
    std::size_t count = 0;
    while (!reader.done()) {
        auto sk = reader.field(p.secret_key_bytes, "sk");
        const auto pk = reader.field(p.public_key_bytes, "pk");
        const auto expected = reader.field(p.message_bytes, "message");
        const auto ct = reader.field(p.ciphertext_bytes, "ciphertext");
        canonicalize_legacy_key(p, sk, pk);
        Bytes recovered(p.message_bytes);
        require_ok(lac::testing::pke_decrypt(set, backend, sk, ct, recovered), "legacy PKE decrypt");
        require(recovered == expected, "legacy PKE plaintext mismatch at record " + std::to_string(count));
        ++count;
    }
    require(count == 10, "expected exactly ten legacy PKE vectors");
}

void verify_kem(const std::filesystem::path& path, lac::ParameterSet set, lac::Backend backend) {
    const auto& p = lac::parameters(set);
    lac::Kem kem(set, backend);
    VectorReader reader(path);
    check_header(reader);
    std::size_t count = 0;
    while (!reader.done()) {
        auto sk = reader.field(p.secret_key_bytes, "sk");
        const auto pk = reader.field(p.public_key_bytes, "pk");
        const auto ct = reader.field(p.ciphertext_bytes, "ciphertext");
        const auto old_secret = reader.field(p.message_bytes, "legacy shared secret");
        canonicalize_legacy_key(p, sk, pk);

        Bytes message(p.message_bytes), rebuilt(p.ciphertext_bytes), v1_secret(p.message_bytes);
        require_ok(lac::testing::pke_decrypt(set, backend, sk, ct, message), "legacy KEM underlying PKE decrypt");
        const auto old_hash = sha256({message});
        require(equal(old_secret, std::span(old_hash).first(p.message_bytes)),
                "legacy H(message) mismatch at record " + std::to_string(count));
        const auto seed = sha256({message, std::span(pk).first(lac::seed_bytes)});
        require_ok(lac::testing::pke_encrypt_seed(set, backend, pk, message, seed, rebuilt),
                   "legacy KEM re-encryption");
        require(rebuilt == ct, "legacy ciphertext re-encryption mismatch at record " + std::to_string(count));

        // V1 intentionally changes the shared-secret transcript. Matching the
        // old H(message) would be a regression, not backwards compatibility.
        const auto expected_v1 = sha256({message, ct});
        require_ok(kem.decapsulate(sk, ct, v1_secret), "V1 legacy ciphertext decapsulation");
        require(equal(v1_secret, std::span(expected_v1).first(p.message_bytes)),
                "V1 transcript mismatch at record " + std::to_string(count));
        require(v1_secret != old_secret, "V1 accidentally retained the legacy secret transcript");
        ++count;
    }
    require(count == 10, "expected exactly ten legacy KEM vectors");
}
} // namespace

int main(int argc, char** argv) {
    try {
        require(argc <= 2, "usage: vector_tests [test-data-directory]");
        const std::filesystem::path default_directory =
#ifdef LAC_TEST_DATA_DIR
            LAC_TEST_DATA_DIR;
#else
            std::filesystem::path(__FILE__).parent_path() / "data";
#endif
        const std::filesystem::path directory = argc == 2
            ? std::filesystem::path(argv[1]) : default_directory;
        struct Fixture { lac::ParameterSet set; const char* directory; };
        constexpr std::array fixtures{
            Fixture{lac::ParameterSet::Light, "LAC_LIGHT"},
            Fixture{lac::ParameterSet::Lac192, "LAC192"},
            Fixture{lac::ParameterSet::Lac256, "LAC256"}};
        for (const auto fixture : fixtures) {
            for (const auto backend : {lac::Backend::Portable, lac::Backend::Auto}) {
                try {
                    verify_pke(directory / fixture.directory / "PKE_VEC_INFO.dat", fixture.set, backend);
                    verify_kem(directory / fixture.directory / "KEM_VEC_INFO.dat", fixture.set, backend);
                } catch (const std::exception& error) {
                    throw std::runtime_error(std::string(fixture.directory) + ": " + error.what());
                }
            }
            std::cout << "PASS " << fixture.directory
                      << ": 10 PKE + 10 KEM legacy vectors, portable and automatic backends\n";
        }
        std::cout << "PASS 60 distinct legacy records; V1 transcript independently verified.\n"
                     "LAC128 has no supplied vector file and is covered by generated API/differential tests.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
