#pragma once

#include "parameters.hpp"
#include <memory>
#include <span>
#include <string_view>

namespace lac {
enum class Status { Ok, InvalidArgument, InvalidKey, CryptoFailure };
std::string_view status_message(Status status) noexcept;

// Empty source selects OpenSSL RAND_priv_bytes_ex. Custom sources are useful
// for platform entropy adapters and deterministic tests; never reuse test seeds.
struct RandomSource {
    using Fill = bool (*)(std::span<Byte>, void*) noexcept;
    Fill fill = nullptr;
    void* context = nullptr;
};

// Research implementation PQC-LAC-KEM-v1. See docs/KEM_DESIGN.md for the
// explicit transcript and differences from the supplied legacy DLL.
// One instance owns reusable workspaces: use a separate instance per thread.
class Kem final {
public:
    explicit Kem(ParameterSet set = ParameterSet::Light,
                 Backend backend = Backend::Auto, RandomSource random = {});
    ~Kem();
    Kem(const Kem&) = delete;
    Kem& operator=(const Kem&) = delete;
    Kem(Kem&&) noexcept;
    Kem& operator=(Kem&&) noexcept;

    [[nodiscard]] const Parameters& params() const noexcept;
    [[nodiscard]] std::string_view backend_name() const noexcept;

    // Exact-size, disjoint buffers are required. On failure, correctly-sized
    // output buffers are cleared. Public keys and serialized secret indices
    // are validated before any polynomial access.
    // A moved-from object returns InvalidArgument and clears every supplied
    // output span, regardless of its size.
    [[nodiscard]] Status keypair(std::span<Byte> public_key,
                                 std::span<Byte> secret_key) noexcept;
    [[nodiscard]] Status encapsulate(std::span<const Byte> public_key,
                                     std::span<Byte> ciphertext,
                                     std::span<Byte> shared_secret) noexcept;
    // A valid-size, invalid ciphertext returns Ok with a deterministic rejection
    // secret. The API deliberately exposes no ciphertext-validity flag.
    [[nodiscard]] Status decapsulate(std::span<const Byte> secret_key,
                                     std::span<const Byte> ciphertext,
                                     std::span<Byte> shared_secret) noexcept;
private:
    friend struct TestingAccess;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace lac
