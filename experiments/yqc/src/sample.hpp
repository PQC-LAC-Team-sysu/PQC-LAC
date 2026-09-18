#ifndef LAC_SAMPLE_HPP
#define LAC_SAMPLE_HPP

#include "params.hpp"
#include "poly.hpp"
//  采样：从 PRF 生成多项式系数
//
//  三种分布：
//   1. sample_uniform     ：a ∈ R_q，系数均匀分布在 [0, Q-1]
//   2. sample_sparse      ：s, e, r, e1 ∈ R，固定汉明重量
//   3. sample_sparse_len  ：e2，长度 C2_BYTES 的固定汉明重量
//
//  相比原代码的改进：
//   - 用 C++ std::vector 做洗牌，逻辑更清晰
//   - 用多个 nonce 派生不同的子流，不用在循环里改 seed
//   - 显式检查所有边界（len 上界、剩余个数）

namespace lac {

    // 均匀采样：输出 N 个系数在 [0, Q-1]
    Status sample_uniform(const uint8_t* seed, Poly& out);

    // 固定汉明重量采样：输出 N 个小系数
    Status sample_sparse(const uint8_t* seed, SmallPoly& out);

    // 长 len 版本的固定汉明重量采样（用于 e2）
    // 输出 out[0..len-1]，-1 编码为 Q-1
    Status sample_sparse_len(const uint8_t* seed, uint8_t* out, int len);

} // namespace lac

#endif // LAC_SAMPLE_HPP