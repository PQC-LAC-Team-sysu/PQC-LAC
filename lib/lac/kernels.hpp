#pragma once
#include "parameters.hpp"
#include <array>
#include <span>

namespace lac::detail {
struct PolyWorkspace {
    alignas(32) std::array<Byte, 2 * max_dimension> extended{};
    alignas(32) std::array<std::uint16_t, max_dimension> positive{};
    alignas(32) std::array<std::uint16_t, max_dimension> negative{};
};
using Multiply = void (*)(std::span<const Byte>, std::span<const std::uint16_t>,
                         std::size_t, std::span<const Byte>, std::span<Byte>,
                         PolyWorkspace&) noexcept;
void multiply_portable(std::span<const Byte> a, std::span<const std::uint16_t> positions,
                       std::size_t weight, std::span<const Byte> noise,
                       std::span<Byte> output, PolyWorkspace& workspace) noexcept;
bool avx2_available() noexcept;
#ifdef LAC_HAVE_AVX2
void multiply_avx2(std::span<const Byte> a, std::span<const std::uint16_t> positions,
                  std::size_t weight, std::span<const Byte> noise,
                  std::span<Byte> output, PolyWorkspace& workspace) noexcept;
#endif
} // namespace lac::detail
