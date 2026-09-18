#include "../lib/lac/kernels.hpp"
#include <algorithm>
#include <array>
#include <iostream>
#include <random>
#include <vector>

int main() {
    std::mt19937 generator(0x1ac);
    lac::detail::PolyWorkspace workspace;
    for (auto set : {lac::ParameterSet::Light, lac::ParameterSet::Lac128,
                     lac::ParameterSet::Lac192, lac::ParameterSet::Lac256}) {
        const auto& p = lac::parameters(set);
        std::vector<lac::Byte> a(p.dimension), noise(p.dimension), result(p.dimension), fast(p.dimension);
        std::vector<std::uint16_t> positions(p.dimension);
        for (std::size_t i = 0; i < p.dimension; ++i) positions[i] = static_cast<std::uint16_t>(i);
        std::shuffle(positions.begin(), positions.end(), generator);
        for (int trial = 0; trial < 4; ++trial) {
            for (std::size_t i = 0; i < p.dimension; ++i) {
                a[i] = static_cast<lac::Byte>(trial == 0 ? 250 : trial == 1 ? 0 : generator() % 251);
                noise[i] = static_cast<lac::Byte>(generator() % 251);
            }
            for (const auto count : {p.dimension, p.c2_coefficients, std::size_t{17}}) {
                const auto out = std::span(result).first(count);
                const auto indices = std::span(positions).first(2 * p.weight);
                lac::detail::multiply_portable(a, indices, p.weight, noise, out, workspace);
                // Independent negacyclic reference, one contribution per signed term.
                for (std::size_t j = 0; j < count; ++j) {
                    int total = noise[j];
                    for (std::size_t i = 0; i < 2 * p.weight; ++i) {
                        const int coefficient_sign = i < p.weight ? 1 : -1;
                        const auto position = positions[i];
                        const auto index = (j + p.dimension - position) % p.dimension;
                        const int wrap_sign = j >= position ? 1 : -1;
                        total += coefficient_sign * wrap_sign * a[index];
                    }
                    const auto expected = static_cast<lac::Byte>((total % 251 + 251) % 251);
                    if (out[j] != expected) {
                        std::cerr << p.name << " portable convolution mismatch at " << j << '\n';
                        return 1;
                    }
                }
#ifdef LAC_HAVE_AVX2
                if (lac::detail::avx2_available()) {
                    auto avx_output = std::span(fast).first(count);
                    lac::detail::multiply_avx2(a, indices, p.weight, noise, avx_output, workspace);
                    if (!std::equal(out.begin(), out.end(), avx_output.begin())) {
                        std::cerr << "AVX2 mismatch\n";
                        return 1;
                    }
                }
#endif
            }
        }
    }
    std::cout << "Independent negacyclic convolution: all parameter sets and tails passed\n";
}
