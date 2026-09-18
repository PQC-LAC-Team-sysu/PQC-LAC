#include "kex.hpp"
#include <cstring>
#include <vector>
#include <cstdlib>
#include "random.hpp"
extern "C" {
#include <openssl/sha.h>
}

namespace lac {

    static void H_kex(const uint8_t* in, size_t len, uint8_t out[MSG_BYTES])
    {
        uint8_t tmp[32];
        SHA256(in, len, tmp);
        std::memcpy(out, tmp, MSG_BYTES);
    }

    Status kex_alice_init(KexAliceState& state)
    {
        return pke_keygen(state.pk, state.sk);
    }

    Status kex_bob_respond(const PublicKey& pk_a,
                           Ciphertext& c,
                           uint8_t K[MSG_BYTES])
    {
        if (K == nullptr) return Status::ERR_NULL;

        // m ← 随机 16 字节
        uint8_t m[MSG_BYTES];
        Status st = random_bytes(m, MSG_BYTES);
        if (st != Status::OK) return st;

        // 加密种子：从 m 派生
        uint8_t enc_seed[SEED_BYTES];
        SHA256(m, MSG_BYTES, enc_seed);

        // c = PKE.Enc(pk_a, m)
        st = pke_encrypt(pk_a, m, enc_seed, c);
        if (st != Status::OK) return st;

        // K = H(pk_a || m)
        std::vector<uint8_t> buf(PK_BYTES + MSG_BYTES);
        pk_a.to_bytes(buf.data());
        std::memcpy(buf.data() + PK_BYTES, m, MSG_BYTES);
        H_kex(buf.data(), buf.size(), K);

        return Status::OK;
    }

    Status kex_alice_finish(const KexAliceState& state,
                            const Ciphertext& c,
                            uint8_t K[MSG_BYTES])
    {
        if (K == nullptr) return Status::ERR_NULL;

        // m = PKE.Dec(sk_a, c)
        uint8_t m[MSG_BYTES];
        Status st = pke_decrypt(state.sk, c, m);
        if (st != Status::OK) return st;

        // K = H(pk_a || m)
        std::vector<uint8_t> buf(PK_BYTES + MSG_BYTES);
        state.pk.to_bytes(buf.data());
        std::memcpy(buf.data() + PK_BYTES, m, MSG_BYTES);
        H_kex(buf.data(), buf.size(), K);

        return Status::OK;
    }

} // namespace lac