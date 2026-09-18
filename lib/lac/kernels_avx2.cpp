#include "kernels.hpp"
#include <algorithm>
#include <immintrin.h>

namespace lac::detail {
void multiply_avx2(std::span<const Byte> a, std::span<const std::uint16_t> positions,
                  std::size_t weight, std::span<const Byte> noise,
                  std::span<Byte> output, PolyWorkspace& w) noexcept {
    const std::size_t n = a.size(), count = output.size();
    const auto q = _mm256_set1_epi8(static_cast<char>(modulus));
    for (std::size_t i = 0; i < n; i += 32) {
        const auto input = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a.data() + i));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(w.extended.data() + i),
                            _mm256_sub_epi8(q, input));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(w.extended.data() + n + i), input);
    }
    std::fill_n(w.positive.begin(), count, 0);
    std::fill_n(w.negative.begin(), count, 0);
    for (std::size_t i = 0; i < weight; ++i) {
        const auto* plus = w.extended.data() + n - positions[i];
        const auto* minus = w.extended.data() + n - positions[weight + i];
        std::size_t j = 0;
        // 16-byte reads exactly cover all four parameter sets' tails.
        for (; j + 16 <= count; j += 16) {
            const auto p = _mm256_cvtepu8_epi16(
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(plus + j)));
            const auto m = _mm256_cvtepu8_epi16(
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(minus + j)));
            const auto ps = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(w.positive.data() + j));
            const auto ms = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(w.negative.data() + j));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(w.positive.data() + j), _mm256_add_epi16(ps, p));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(w.negative.data() + j), _mm256_add_epi16(ms, m));
        }
        for (; j < count; ++j) {
            w.positive[j] = static_cast<std::uint16_t>(w.positive[j] + plus[j]);
            w.negative[j] = static_cast<std::uint16_t>(w.negative[j] + minus[j]);
        }
    }
    for (std::size_t j = 0; j < count; ++j) {
        const std::int32_t value = static_cast<std::int32_t>(w.positive[j]) -
            static_cast<std::int32_t>(w.negative[j]) + 256 * modulus +
            (noise.empty() ? 0 : noise[j]);
        output[j] = static_cast<Byte>(value % modulus);
    }
}
} // namespace lac::detail
