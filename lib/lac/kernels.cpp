#include "kernels.hpp"
#include <algorithm>
#if defined(_MSC_VER) && defined(LAC_HAVE_AVX2)
#include <intrin.h>
#endif

namespace lac::detail {
void multiply_portable(std::span<const Byte> a, std::span<const std::uint16_t> positions,
                       std::size_t weight, std::span<const Byte> noise,
                       std::span<Byte> output, PolyWorkspace& w) noexcept {
    const std::size_t n = a.size();
    const std::size_t count = output.size();
    for (std::size_t i = 0; i < n; ++i) {
        w.extended[i] = static_cast<Byte>(modulus - a[i]);
        w.extended[n + i] = a[i];
    }
    std::fill_n(w.positive.begin(), count, 0);
    std::fill_n(w.negative.begin(), count, 0);
    for (std::size_t i = 0; i < weight; ++i) {
        const auto* plus = w.extended.data() + n - positions[i];
        const auto* minus = w.extended.data() + n - positions[weight + i];
        for (std::size_t j = 0; j < count; ++j) {
            w.positive[j] = static_cast<std::uint16_t>(w.positive[j] + plus[j]);
            w.negative[j] = static_cast<std::uint16_t>(w.negative[j] + minus[j]);
        }
    }
    // Each unsigned accumulator is at most 192*251 = 48192. A signed 16-bit
    // interpretation would be wrong for high-valued/adversarial polynomials.
    for (std::size_t j = 0; j < count; ++j) {
        const std::int32_t value = static_cast<std::int32_t>(w.positive[j]) -
            static_cast<std::int32_t>(w.negative[j]) + 256 * modulus +
            (noise.empty() ? 0 : noise[j]);
        output[j] = static_cast<Byte>(value % modulus);
    }
}

bool avx2_available() noexcept {
#if defined(LAC_HAVE_AVX2) && (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER)
    return __builtin_cpu_supports("avx2") != 0;
#elif defined(LAC_HAVE_AVX2) && defined(_MSC_VER)
    int registers[4]{};
    __cpuid(registers, 0);
    if (registers[0] < 7) return false;
    __cpuidex(registers, 1, 0);
    if ((registers[2] & (1 << 27)) == 0 || (registers[2] & (1 << 28)) == 0) return false;
    if ((_xgetbv(0) & 6) != 6) return false;
    __cpuidex(registers, 7, 0);
    return (registers[1] & (1 << 5)) != 0;
#else
    return false;
#endif
}
} // namespace lac::detail
