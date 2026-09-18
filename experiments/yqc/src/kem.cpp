#include "kem.hpp"
#include <cstring>
#include <vector>

extern "C" {
#include <openssl/sha.h>
}

namespace lac {

//  G: {0,1}^* → {0,1}^32
//  H: {0,1}^* → {0,1}^16
static void G(const uint8_t* in, size_t inlen, uint8_t out[SEED_BYTES])
{
    SHA256(in, inlen, out);
}

static void H(const uint8_t* in, size_t inlen, uint8_t out[MSG_BYTES])
{
    uint8_t tmp[32];
    SHA256(in, inlen, tmp);
    std::memcpy(out, tmp, MSG_BYTES);
}

//  kem_keygen = pke_keygen
Status kem_keygen(PublicKey& pk, SecretKey& sk)
{
    return pke_keygen(pk, sk);
}

//  封装
Status kem_encaps(const PublicKey& pk,
                  const uint8_t rand_seed[SEED_BYTES],
                  KemCiphertext& ct,
                  uint8_t ss[MSG_BYTES])
{
    if (rand_seed == nullptr || ss == nullptr) return Status::ERR_NULL;

    // m ← 用 SHA256(rand_seed) 取前 16 字节作为随机消息
    //   （这不是文档描述的标准采样，但完全等价于从随机分布中抽 16 字节）
    uint8_t hash[32];
    SHA256(rand_seed, SEED_BYTES, hash);

    uint8_t m[MSG_BYTES];
    std::memcpy(m, hash, MSG_BYTES);

    // seed ← G(m)
    uint8_t pke_seed[SEED_BYTES];
    G(m, MSG_BYTES, pke_seed);

    // c ← PKE.Enc(pk, m; seed)
    Status st = pke_encrypt(pk, m, pke_seed, ct.ct);
    if (st != Status::OK) return st;

    // K ← H(m || c)
    std::vector<uint8_t> buf(MSG_BYTES + CT_BYTES);
    std::memcpy(buf.data(), m, MSG_BYTES);
    ct.to_bytes(buf.data() + MSG_BYTES);
    H(buf.data(), buf.size(), ss);

    return Status::OK;
}

//  解封装
Status kem_decaps(const SecretKey& sk,
                  const PublicKey& pk,
                  const KemCiphertext& ct,
                  uint8_t ss[MSG_BYTES])
{
    if (ss == nullptr) return Status::ERR_NULL;

    // m ← PKE.Dec(sk, c)
    uint8_t m[MSG_BYTES];
    Status st = pke_decrypt(sk, ct.ct, m);
    if (st != Status::OK) return st;

    // K ← H(m || c)
    std::vector<uint8_t> buf(MSG_BYTES + CT_BYTES);
    std::memcpy(buf.data(), m, MSG_BYTES);
    ct.to_bytes(buf.data() + MSG_BYTES);
    H(buf.data(), buf.size(), ss);

    // seed ← G(m)
    uint8_t pke_seed[SEED_BYTES];
    G(m, MSG_BYTES, pke_seed);

    // c' ← PKE.Enc(pk, m; seed)
    Ciphertext ct2;
    st = pke_encrypt(pk, m, pke_seed, ct2);
    if (st != Status::OK) return st;

    // 比较 c' 和 c
    uint8_t c_bytes[CT_BYTES], c2_bytes[CT_BYTES];
    ct.to_bytes(c_bytes);
    ct2.to_bytes(c2_bytes);

    if (std::memcmp(c_bytes, c2_bytes, CT_BYTES) != 0) {
        // 验证失败：K ← H(H(sk) || c)
        uint8_t sk_bytes[N];
        uint8_t sk_hash[32];
        sk.to_bytes(sk_bytes);
        SHA256(sk_bytes, N, sk_hash);

        std::vector<uint8_t> buf2(32 + CT_BYTES);
        std::memcpy(buf2.data(),      sk_hash, 32);
        std::memcpy(buf2.data() + 32, c_bytes, CT_BYTES);
        H(buf2.data(), buf2.size(), ss);
    }

    return Status::OK;
}

} // namespace lac