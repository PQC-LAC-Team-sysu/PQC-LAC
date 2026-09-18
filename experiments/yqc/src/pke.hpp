#ifndef LAC_PKE_HPP
#define LAC_PKE_HPP

#include "params.hpp"
#include "poly.hpp"
#include "sample.hpp"
#include "ecc.hpp"
#include <array>
#include <vector>

namespace lac {

// 公钥 = seed_a (32 字节) || b (N 字节) = 544 字节
struct PublicKey {
    std::array<uint8_t, SEED_BYTES> seed_a;
    Poly b;

    void to_bytes(uint8_t out[PK_BYTES]) const;
    Status from_bytes(const uint8_t in[PK_BYTES]);
};

// 私钥 = s (N 字节)
struct SecretKey {
    SmallPoly s;

    void to_bytes(uint8_t out[N]) const;
    Status from_bytes(const uint8_t in[N]);
};

// 密文 = c1 (N 字节) || c2_compressed (C2_BYTES/2 字节) = 664 字节
struct Ciphertext {
    Poly c1;
    std::vector<uint8_t> c2_compressed;

    void to_bytes(uint8_t out[CT_BYTES]) const;
    Status from_bytes(const uint8_t in[CT_BYTES]);
};

// 密钥生成：从一个 32 字节的主种子派生所有随机性
//   （这样测试可重复；真实使用时用 random_bytes 生成 master_seed）
Status pke_keygen_from_seed(const uint8_t master_seed[SEED_BYTES],
                            PublicKey& pk, SecretKey& sk);

// 密钥生成：自动生成主种子
Status pke_keygen(PublicKey& pk, SecretKey& sk);

// 加密：m 是 16 字节明文，seed 是 32 字节随机种子
//   同样的 (pk, m, seed) 总是产生同样的密文（确定性）
Status pke_encrypt(const PublicKey& pk,
                   const uint8_t m[MSG_BYTES],
                   const uint8_t seed[SEED_BYTES],
                   Ciphertext& c);
// 解密
Status pke_decrypt(const SecretKey& sk, const Ciphertext& c,
                   uint8_t m[MSG_BYTES]);

} // namespace lac

#endif