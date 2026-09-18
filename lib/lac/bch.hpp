// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include "parameters.hpp"
#include <span>

namespace lac::detail {
// Fixed-workspace BCH codec for the three non-LIGHT parameter sets.
// Tables are immutable; each operation has independent stack scratch memory.
// A LIGHT/unknown set constructs successfully but encode/decode return false.
// This implementation is NOT claimed to be constant time: field and remainder
// lookups have data-dependent addresses. Loops are bounded by public parameters.
class BchCodec final {
public:
    explicit BchCodec(ParameterSet set) noexcept : set_(set) {}

    // Exact sizes: LAC128 16->24, LAC192 32->41, LAC256 32->53 bytes.
    // Correctly sized outputs are cleared on failure. encode permits overlap.
    [[nodiscard]] bool encode(std::span<const Byte> message,
                              std::span<Byte> code) const noexcept;
    // The 15 unused parity padding bits in LAC256 are ignored, as in the
    // original format. True means BCH decoding succeeded, NOT authentication.
    [[nodiscard]] bool decode(std::span<const Byte> code,
                              std::span<Byte> message) const noexcept;
private:
    ParameterSet set_;
};
} // namespace lac::detail
