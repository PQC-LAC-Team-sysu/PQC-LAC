#include "sample.hpp"
#include <cstring>
#include <numeric>
#include <vector>

extern "C" {
#include "aes256ctr.h"
}

namespace lac {

// 用 aes256ctr_prf 从 seed 派生字节流
// nonce 用来在同一个 seed 下派生不同的子流
static void prf_bytes(uint8_t* out, int len, const uint8_t* seed, uint8_t nonce)
{
    aes256ctr_prf(out, static_cast<unsigned long long>(len), seed, nonce);
}

//  sample_uniform: 均匀采样 [0, Q-1] 上 N 个系数
//
//  方法：拒绝采样。生成字节，丢弃 >= Q 的，重来。
//  Q = 251，所以通过率约 251/256 ≈ 98%，效率还行。
//
//  Bug 修正：
//    原代码用一个 128 字节 buf，用完了再生成；这里也这样做，
//    但显式处理了两个缓冲区都空的情况，不会漏。
Status sample_uniform(const uint8_t* seed, Poly& out)
{
    if (seed == nullptr) return Status::ERR_NULL;

    constexpr int BUF_LEN = 256;
    uint8_t buf[BUF_LEN];
    int buf_pos = 0;

    prf_bytes(buf, BUF_LEN, seed, 0x00);

    for (int i = 0; i < N; ++i) {
        while (true) {
            if (buf_pos >= BUF_LEN) {
                // 缓冲区用完，重新生成
                prf_bytes(buf, BUF_LEN, buf, 0x01);
                buf_pos = 0;
            }
            uint8_t b = buf[buf_pos++];
            if (b < Q) {
                out[i] = b;
                break;
            }
            // b >= Q，丢弃，继续取下一个字节
        }
    }
    return Status::OK;
}

//  sample_sparse: 固定汉明重量采样（用于 s, e, r, e1）
//
//  输出 N 个系数：HAMMING_W 个 1，HAMMING_W 个 -1，其余 0
//
//  方法：Fisher-Yates 部分洗牌
//    把位置数组 [0, 1, ..., N-1] 洗前 2*HAMMING_W 个，
//    然后前 HAMMING_W 个位置填 1，接着 HAMMING_W 个填 -1
//
//  Bug 修正：
//    原代码在循环里 memcpy 更新 seed，逻辑绕；
//    这里用 PRF + 递增 nonce，不用改 seed。
Status sample_sparse(const uint8_t* seed, SmallPoly& out)
{
    if (seed == nullptr) return Status::ERR_NULL;

    // 位置数组
    std::vector<int> pos(N);
    std::iota(pos.begin(), pos.end(), 0);

    // 随机字节池
    constexpr int RND_BUF = 512;
    std::vector<uint8_t> rnd(RND_BUF);
    prf_bytes(rnd.data(), RND_BUF, seed, 0x10);

    int rnd_pos = 0;
    uint8_t nonce = 0x10;

    for (int i = 0; i < 2 * HAMMING_W; ++i) {
        // 需要 2 字节拼一个 16-bit 随机数
        if (rnd_pos + 2 > RND_BUF) {
            nonce++;
            prf_bytes(rnd.data(), RND_BUF, seed, nonce);
            rnd_pos = 0;
        }
        uint16_t r = (static_cast<uint16_t>(rnd[rnd_pos]) << 8) | rnd[rnd_pos + 1];
        rnd_pos += 2;

        // 在 [i, N-1] 里选一个位置 j 和 pos[i] 交换
        int remaining = N - i;
        int j = i + (r % remaining);

        int t = pos[i];
        pos[i] = pos[j];
        pos[j] = t;
    }

    std::memset(out.data(), 0, out.size());

    for (int i = 0; i < HAMMING_W; ++i) {
        out[pos[i]] = 1;
    }
    for (int i = HAMMING_W; i < 2 * HAMMING_W; ++i) {
        out[pos[i]] = -1;
    }

    return Status::OK;
}

//  sample_sparse_len: 长 len 的固定汉明重量采样（用于 e2）
//
//  Bug 修正：
//    原代码对 e2 用 gen_e，但 gen_e 内部按 DIM_N 处理，
//    然后外部只取前 C2_VEC_NUM 个，导致实际汉明重量不等于 NUM_ONE。
//    这里显式按 len 处理，汉明重量 = HAMMING_W 严格保证。
Status sample_sparse_len(const uint8_t* seed, uint8_t* out, int len)
{
    if (seed == nullptr || out == nullptr) return Status::ERR_NULL;
    if (len <= 0 || len > 2 * N) return Status::ERR_LENGTH;
    if (2 * HAMMING_W > len) return Status::ERR_LENGTH;

    std::vector<int> pos(len);
    std::iota(pos.begin(), pos.end(), 0);

    constexpr int RND_BUF = 512;
    std::vector<uint8_t> rnd(RND_BUF);
    prf_bytes(rnd.data(), RND_BUF, seed, 0x20);

    int rnd_pos = 0;
    uint8_t nonce = 0x20;

    for (int i = 0; i < 2 * HAMMING_W; ++i) {
        if (rnd_pos + 2 > RND_BUF) {
            nonce++;
            prf_bytes(rnd.data(), RND_BUF, seed, nonce);
            rnd_pos = 0;
        }
        uint16_t r = (static_cast<uint16_t>(rnd[rnd_pos]) << 8) | rnd[rnd_pos + 1];
        rnd_pos += 2;

        int remaining = len - i;
        int j = i + (r % remaining);

        int t = pos[i];
        pos[i] = pos[j];
        pos[j] = t;
    }

    std::memset(out, 0, len);

    for (int i = 0; i < HAMMING_W; ++i) {
        out[pos[i]] = 1;
    }
    for (int i = HAMMING_W; i < 2 * HAMMING_W; ++i) {
        out[pos[i]] = static_cast<uint8_t>(Q - 1);
    }

    return Status::OK;
}

} // namespace lac