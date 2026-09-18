#ifndef LAC_POLY_HPP
#define LAC_POLY_HPP

#include "params.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace lac {

// 系数在 Z_q 里的多项式（用 uint8_t 存，因为 Q < 256）
using Poly = std::array<uint8_t, N>;

// 系数在 {-1, 0, 1} 里的稀疏小多项式
using SmallPoly = std::array<int8_t, N>;

// 错误码
enum class Status {
    OK = 0,
    ERR_NULL,
    ERR_LENGTH,
    ERR_OVERFLOW
};

// 多项式乘法：result = a * s mod (x^N + 1, Q)
//   a: 系数在 Z_q
//   s: 系数在 {-1, 0, 1}
//   返回 OK 或错误码
Status poly_mul(const Poly& a, const SmallPoly& s, Poly& result);

// result = a * s + e mod (x^N + 1, Q)
Status poly_aff(const Poly& a, const SmallPoly& s, const Poly& e, Poly& result);

// 截取前 len 个系数（用于 c2）
Status poly_truncate(const Poly& src, Poly& dst, int len);

// 压缩：丢弃每个系数低 4 bit，两个系数打包进 1 字节
//   输入：vec_num 个系数
//   输出：vec_num/2 字节
Status poly_compress(const uint8_t* in, int vec_num, std::vector<uint8_t>& out);

// 解压：把压缩后的字节还原成 vec_num 个系数，低 4 bit 设为 0x08
Status poly_decompress(const uint8_t* in, int vec_num, std::vector<uint8_t>& out);

} // namespace lac

#endif // LAC_POLY_HPP