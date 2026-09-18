#pragma once
// Internal compatibility-test hooks. Not part of the application API.
#include "kem.hpp"
namespace lac::testing {
Status pke_decrypt(ParameterSet set, Backend backend,
                   std::span<const Byte> secret_key, std::span<const Byte> ciphertext,
                   std::span<Byte> message);
Status pke_encrypt_seed(ParameterSet set, Backend backend,
                       std::span<const Byte> public_key, std::span<const Byte> message,
                       std::span<const Byte> seed, std::span<Byte> ciphertext);
}
