#include "ake.hpp"
#include <cstring>
#include <vector>
#include "random.hpp"
extern "C" {
#include <openssl/sha.h>
}

namespace lac {
//  K = H(pk_a || pk_b || pk_e || c_b2 || k1 || k2 || k3)
static void derive_session_key(const PublicKey& pk_a,
                               const PublicKey& pk_b,
                               const PublicKey& pk_e,
                               const Ciphertext& c_b2,
                               const uint8_t k1[MSG_BYTES],
                               const uint8_t k2[MSG_BYTES],
                               const uint8_t k3[MSG_BYTES],
                               uint8_t K[MSG_BYTES])
{
    std::vector<uint8_t> buf;
    buf.resize(PK_BYTES * 3 + CT_BYTES + MSG_BYTES * 3);

    size_t off = 0;
    pk_a.to_bytes(buf.data() + off); off += PK_BYTES;
    pk_b.to_bytes(buf.data() + off); off += PK_BYTES;
    pk_e.to_bytes(buf.data() + off); off += PK_BYTES;
    c_b2.to_bytes(buf.data() + off); off += CT_BYTES;
    std::memcpy(buf.data() + off, k1, MSG_BYTES); off += MSG_BYTES;
    std::memcpy(buf.data() + off, k2, MSG_BYTES); off += MSG_BYTES;
    std::memcpy(buf.data() + off, k3, MSG_BYTES); off += MSG_BYTES;

    uint8_t hash[32];
    SHA256(buf.data(), buf.size(), hash);
    std::memcpy(K, hash, MSG_BYTES);
}

//  Alice 第一步
    Status ake_alice_init(const PublicKey& pk_b, AkeAliceState& state)
{
    // 生成临时密钥对
    Status st = pke_keygen(state.pk_e, state.sk_e);
    if (st != Status::OK) return st;

    // 用 Bob 长期公钥封装 k1
    uint8_t rand_seed[SEED_BYTES];
    st = random_bytes(rand_seed, SEED_BYTES);
    if (st != Status::OK) return st;

    KemCiphertext kem_ct;
    st = kem_encaps(pk_b, rand_seed, kem_ct, state.k1);
    if (st != Status::OK) return st;

    state.c_a = kem_ct.ct;
    return Status::OK;
}

//  Bob 应答
    Status ake_bob_respond(const PublicKey& pk_b,
                           const SecretKey& sk_b,
                           const PublicKey& pk_a,
                           const PublicKey& pk_e,
                           const Ciphertext& c_a,
                           AkeBobOutput& out)
{
    // k2 = KEM.Encaps(pk_a)
    uint8_t rand_seed2[SEED_BYTES];
    Status st = random_bytes(rand_seed2, SEED_BYTES);
    if (st != Status::OK) return st;

    KemCiphertext kem_ct;
    uint8_t k2[MSG_BYTES];
    st = kem_encaps(pk_a, rand_seed2, kem_ct, k2);
    if (st != Status::OK) return st;
    out.c_b1 = kem_ct.ct;

    // k3 = PKE.Enc(pk_e, m3)
    uint8_t m3[MSG_BYTES];
    st = random_bytes(m3, MSG_BYTES);
    if (st != Status::OK) return st;

    uint8_t enc_seed3[SEED_BYTES];
    SHA256(m3, MSG_BYTES, enc_seed3);
    st = pke_encrypt(pk_e, m3, enc_seed3, out.c_b2);
    if (st != Status::OK) return st;

    uint8_t k3[MSG_BYTES];
    std::memcpy(k3, m3, MSG_BYTES);

    // 用 sk_b 解封装 c_a 得到 k1
    KemCiphertext c_a_kem;
    c_a_kem.ct = c_a;
    uint8_t k1[MSG_BYTES];
    st = kem_decaps(sk_b, pk_b, c_a_kem, k1);
    if (st != Status::OK) return st;

    // K = H(...)
    derive_session_key(pk_a, pk_b, pk_e, out.c_b2, k1, k2, k3, out.K);

    return Status::OK;
}

//  Alice 完成
Status ake_alice_finish(const PublicKey& pk_a,
                        const SecretKey& sk_a,
                        const PublicKey& pk_b,
                        const AkeAliceState& state,
                        const AkeBobOutput& bob_out,
                        uint8_t K[MSG_BYTES])
{
    if (K == nullptr) return Status::ERR_NULL;

    // k2 = KEM.Decaps(sk_a, c_b1)
    KemCiphertext c_b1_kem;
    c_b1_kem.ct = bob_out.c_b1;
    uint8_t k2[MSG_BYTES];
    Status st = kem_decaps(sk_a, pk_a, c_b1_kem, k2);
    if (st != Status::OK) return st;

    // k3 = PKE.Dec(sk_e, c_b2)
    uint8_t k3[MSG_BYTES];
    st = pke_decrypt(state.sk_e, bob_out.c_b2, k3);
    if (st != Status::OK) return st;

    // K = H(...)
    derive_session_key(pk_a, pk_b, state.pk_e, bob_out.c_b2,
                       state.k1, k2, k3, K);

    return Status::OK;
}

} // namespace lac