#ifndef LAC_KEM_HPP
#define LAC_KEM_HPP

#include "params.hpp"
#include "pke.hpp"

namespace lac {

    // KEM 密文 = PKE 密文
    struct KemCiphertext {
        Ciphertext ct;

        void to_bytes(uint8_t out[CT_BYTES]) const { ct.to_bytes(out); }
        Status from_bytes(const uint8_t in[CT_BYTES]) { return ct.from_bytes(in); }
    };

    // 与 PKE 密钥生成相同
    Status kem_keygen(PublicKey& pk, SecretKey& sk);

    // 封装
    //   rand_seed: 调用方提供的 32 字节随机种子（可重复以得到确定性密文）
    //   输出：ct, ss
    Status kem_encaps(const PublicKey& pk,
                      const uint8_t rand_seed[SEED_BYTES],
                      KemCiphertext& ct,
                      uint8_t ss[MSG_BYTES]);

    // 解封装
    Status kem_decaps(const SecretKey& sk,
                      const PublicKey& pk,
                      const KemCiphertext& ct,
                      uint8_t ss[MSG_BYTES]);

} // namespace lac

#endif