#include "poly.hpp"
#include <cstring>

namespace lac {

Status poly_mul(const Poly& a, const SmallPoly& s, Poly& result)
{
    // 临时数组存 2N 长度，最后把 x^N 折叠成 -1
    alignas(32) int32_t tmp[2 * N];
    std::memset(tmp, 0, sizeof(tmp));

    for (int i = 0; i < N; ++i) {
        int32_t si = s[i];
        if (si == 0) continue;
        for (int j = 0; j < N; ++j) {
            tmp[i + j] += si * static_cast<int32_t>(a[j]);
        }
    }

    for (int k = 0; k < N; ++k) {
        // 折叠：x^N = -1
        int32_t v = tmp[k] - tmp[k + N];
        // 修正 2：原代码用 % 处理负数依赖编译器行为，这里显式取模
        v %= Q;
        if (v < 0) v += Q;
        result[k] = static_cast<uint8_t>(v);
    }
    return Status::OK;
}

//  poly_aff: result = a * s + e mod (x^N + 1, Q)
Status poly_aff(const Poly& a, const SmallPoly& s, const Poly& e, Poly& result)
{
    Poly as;
    Status st = poly_mul(a, s, as);
    if (st != Status::OK) return st;

    for (int i = 0; i < N; ++i) {
        int32_t v = static_cast<int32_t>(as[i]) + static_cast<int32_t>(e[i]);
        v %= Q;
        if (v < 0) v += Q;
        result[i] = static_cast<uint8_t>(v);
    }
    return Status::OK;
}

//  poly_truncate: 截取前 len 个系数
//
//  Bug 修正 3：
//    原代码没有边界检查，len 大于 N 时会越界读。
//    这里检查 len <= N。
Status poly_truncate(const Poly& src, Poly& dst, int len)
{
    if (len < 0 || len > N) return Status::ERR_LENGTH;
    std::memset(dst.data(), 0, dst.size());
    for (int i = 0; i < len; ++i) dst[i] = src[i];
    return Status::OK;
}

//  poly_compress: 丢弃每个系数低 4 bit，2 个系数打包成 1 字节
//
//  输入：vec_num 个系数
//  输出：vec_num / 2 个字节
//  要求：vec_num 必须是偶数
Status poly_compress(const uint8_t* in, int vec_num, std::vector<uint8_t>& out)
{
    if (in == nullptr) return Status::ERR_NULL;
    if (vec_num < 0 || vec_num > 2 * N || (vec_num & 1) != 0)
        return Status::ERR_LENGTH;

    out.resize(vec_num / 2);
    for (int i = 0; i < vec_num / 2; ++i) {
        uint8_t lo = (in[2 * i]     >> 4) & 0x0F;  // 高 4 bit 保留
        uint8_t hi = (in[2 * i + 1]     ) & 0xF0;  // 低 4 bit 丢弃
        out[i] = lo ^ hi;
    }
    return Status::OK;
}
//  poly_decompress: 把压缩后的字节还原成 vec_num 个系数
//  低 4 bit 补 0x08（这是原代码的行为，四舍五入到中点）
Status poly_decompress(const uint8_t* in, int vec_num, std::vector<uint8_t>& out)
{
    if (in == nullptr) return Status::ERR_NULL;
    if (vec_num < 0 || vec_num > 2 * N || (vec_num & 1) != 0)
        return Status::ERR_LENGTH;

    out.resize(vec_num);
    for (int i = 0; i < vec_num / 2; ++i) {
        uint8_t byte = in[i];
        out[2 * i]     = ((byte << 4) & 0xF0) ^ 0x08;
        out[2 * i + 1] = ((byte     ) & 0xF0) ^ 0x08;
    }
    return Status::OK;
}

} // namespace lac