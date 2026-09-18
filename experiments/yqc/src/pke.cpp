#include "pke.hpp"
#include <cstring>
#include "random.hpp"

extern "C" {
#include "aes256ctr.h"
}

namespace lac {

// 内部工具：把 SmallPoly（系数在 {-1,0,1}）转成 Poly（系数在 Z_q）
//   -1 → Q-1，其余原样
static void small_to_poly(const SmallPoly& s, Poly& out)
{
    for (int i = 0; i < N; ++i) {
        int8_t v = s[i];
        out[i] = (v >= 0) ? static_cast<uint8_t>(v)
                          : static_cast<uint8_t>(Q + v);
    }
}

// 内部工具：从主种子派生三个子种子
//   原代码用 pseudo_random_bytes(seeds, 96, master_seed)
//   等价于用 AES-CTR PRF 扩展 96 字节
static void derive_three_seeds(const uint8_t master_seed[SEED_BYTES],
                               uint8_t seeds[3 * SEED_BYTES])
{
    aes256ctr_prf(seeds, 3 * SEED_BYTES, master_seed, 0x00);
}

//  PublicKey / SecretKey / Ciphertext 的序列化
void PublicKey::to_bytes(uint8_t out[PK_BYTES]) const
{
    std::memcpy(out, seed_a.data(), SEED_BYTES);
    std::memcpy(out + SEED_BYTES, b.data(), N);
}

Status PublicKey::from_bytes(const uint8_t in[PK_BYTES])
{
    if (in == nullptr) return Status::ERR_NULL;
    std::memcpy(seed_a.data(), in, SEED_BYTES);
    std::memcpy(b.data(), in + SEED_BYTES, N);
    return Status::OK;
}

void SecretKey::to_bytes(uint8_t out[N]) const
{
    for (int i = 0; i < N; ++i) {
        out[i] = static_cast<uint8_t>(s[i] + 1);  // 编码到 {0,1,2}
    }
}

Status SecretKey::from_bytes(const uint8_t in[N])
{
    if (in == nullptr) return Status::ERR_NULL;
    for (int i = 0; i < N; ++i) {
        s[i] = static_cast<int8_t>(static_cast<int>(in[i]) - 1);
    }
    return Status::OK;
}

void Ciphertext::to_bytes(uint8_t out[CT_BYTES]) const
{
    std::memcpy(out, c1.data(), N);
    if (!c2_compressed.empty()) {
        std::memcpy(out + N, c2_compressed.data(), c2_compressed.size());
    }
}

Status Ciphertext::from_bytes(const uint8_t in[CT_BYTES])
{
    if (in == nullptr) return Status::ERR_NULL;
    std::memcpy(c1.data(), in, N);
    c2_compressed.resize(C2_BYTES / 2);
    std::memcpy(c2_compressed.data(), in + N, C2_BYTES / 2);
    return Status::OK;
}

//  密钥生成
//
//  流程：
//   1. 从 master_seed 派生 96 字节，分成三个 32 字节子种子
//   2. 用子种子 1 均匀采样 a ∈ R_q
//   3. 用子种子 2 稀疏采样 s
//   4. 用子种子 3 稀疏采样 e
//   5. b = a*s + e
Status pke_keygen_from_seed(const uint8_t master_seed[SEED_BYTES],
                            PublicKey& pk, SecretKey& sk)
{
    if (master_seed == nullptr) return Status::ERR_NULL;

    uint8_t seeds[3 * SEED_BYTES];
    derive_three_seeds(master_seed, seeds);

    // seed_a 存进公钥
    std::memcpy(pk.seed_a.data(), seeds, SEED_BYTES);

    // a = sample_uniform(seeds[0..31])
    Poly a;
    Status st = sample_uniform(seeds, a);
    if (st != Status::OK) return st;

    // s = sample_sparse(seeds[32..63])
    st = sample_sparse(seeds + SEED_BYTES, sk.s);
    if (st != Status::OK) return st;

    // e = sample_sparse(seeds[64..95])
    SmallPoly e_small;
    st = sample_sparse(seeds + 2 * SEED_BYTES, e_small);
    if (st != Status::OK) return st;

    Poly e_poly;
    small_to_poly(e_small, e_poly);

    // b = a*s + e
    st = poly_aff(a, sk.s, e_poly, pk.b);
    if (st != Status::OK) return st;

    return Status::OK;
}

    Status pke_keygen(PublicKey& pk, SecretKey& sk)
{
    uint8_t master_seed[SEED_BYTES];
    Status st = random_bytes(master_seed, SEED_BYTES);
    if (st != Status::OK) return st;
    return pke_keygen_from_seed(master_seed, pk, sk);
}
//  加密
//
//  流程：
//   1. a = sample_uniform(pk.seed_a)
//   2. 从 seed 派生 r, e1, e2
//   3. c1 = a*r + e1
//   4. code = ecc_encode(m)
//   5. d2_encode(code, e2)     // 把 code 写进 e2
//   6. c2 = pk.b*r + e2
//   7. 压缩 c2 存储
Status pke_encrypt(const PublicKey& pk,
                   const uint8_t m[MSG_BYTES],
                   const uint8_t seed[SEED_BYTES],
                   Ciphertext& c)
{
    if (m == nullptr || seed == nullptr) return Status::ERR_NULL;

    // a = sample_uniform(pk.seed_a)
    Poly a;
    Status st = sample_uniform(pk.seed_a.data(), a);
    if (st != Status::OK) return st;

    // 派生 r, e1, e2 的种子
    uint8_t seeds[3 * SEED_BYTES];
    derive_three_seeds(seed, seeds);

    // r = sample_sparse(seeds[0..31])
    SmallPoly r;
    st = sample_sparse(seeds, r);
    if (st != Status::OK) return st;

    // e1 = sample_sparse(seeds[32..63])
    SmallPoly e1_small;
    st = sample_sparse(seeds + SEED_BYTES, e1_small);
    if (st != Status::OK) return st;

    Poly e1_poly;
    small_to_poly(e1_small, e1_poly);

    // c1 = a*r + e1
    st = poly_aff(a, r, e1_poly, c.c1);
    if (st != Status::OK) return st;

    // 编码消息
    uint8_t code[CODE_BYTES];
    st = ecc_encode(m, code);
    if (st != Status::OK) return st;

    // e2 = sample_sparse_len(seeds[64..95], C2_BYTES)
    // 注意：e2_poly 是长度 N 的 Poly，后 N-C2_BYTES 个补 0
    Poly e2_poly{};
    st = sample_sparse_len(seeds + 2 * SEED_BYTES, e2_poly.data(), C2_BYTES);
    if (st != Status::OK) return st;

    // d2_encode：把 code 的每个 bit 写到 e2 的两个位置上
    st = d2_encode(code, e2_poly.data());
    if (st != Status::OK) return st;

    // c2 = pk.b * r + e2
    Poly c2_poly;
    st = poly_aff(pk.b, r, e2_poly, c2_poly);
    if (st != Status::OK) return st;

    // 压缩 c2 的前 C2_BYTES 个系数
    st = poly_compress(c2_poly.data(), C2_BYTES, c.c2_compressed);
    if (st != Status::OK) return st;

    return Status::OK;
}
//  解密
//
//  流程：
//   1. 解压 c2
//   2. u = c1 * s
//   3. D2 解码：用 c2 和 u 的差恢复 code
//   4. ecc_decode(code, m)
Status pke_decrypt(const SecretKey& sk, const Ciphertext& c,
                   uint8_t m[MSG_BYTES])
{
    if (m == nullptr) return Status::ERR_NULL;

    // 解压 c2
    std::vector<uint8_t> c2(C2_BYTES);
    Status st = poly_decompress(c.c2_compressed.data(), C2_BYTES, c2);
    if (st != Status::OK) return st;

    // u = c1 * s
    Poly u;
    st = poly_mul(c.c1, sk.s, u);
    if (st != Status::OK) return st;

    // D2 解码：输入 (c2, u)，输出 code
    uint8_t code[CODE_BYTES];
    st = d2_decode(c2.data(), u.data(), code);
    if (st != Status::OK) return st;

    // ECC 解码
    st = ecc_decode(code, m);
    if (st != Status::OK) return st;

    return Status::OK;
}

} // namespace lac