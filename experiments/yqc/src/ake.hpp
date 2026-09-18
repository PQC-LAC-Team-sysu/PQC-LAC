#ifndef LAC_AKE_HPP
#define LAC_AKE_HPP

#include "params.hpp"
#include "pke.hpp"
#include "kem.hpp"
//  LAC.AKE（FSXY 认证密钥交换）
//
//  协议：
//    Alice（发起方）：
//      1. 生成临时密钥对 (pk_e, sk_e)
//      2. k1 = KEM.Encaps(pk_b)             ← 用 Bob 长期 pk
//         发送 (pk_e, c_a)
//
//    Bob（应答方）：
//      1. k2 = KEM.Encaps(pk_a)             ← 用 Alice 长期 pk
//      2. k3 = PKE.Enc(pk_e, m3)            ← 用 Alice 临时 pk
//         发送 (c_b1, c_b2)
//
//    Alice（完成方）：
//      1. k2 = KEM.Decaps(sk_a, c_b1)
//      2. k3 = PKE.Dec(sk_e, c_b2)
//
//    双方计算相同会话密钥：
//      K = H(pk_a || pk_b || pk_e || c_b2 || k1 || k2 || k3)
namespace lac {

    struct AkeAliceState {
        PublicKey  pk_e;   // 临时公钥
        SecretKey  sk_e;   // 临时私钥
        Ciphertext c_a;    // Alice 发给 Bob 的密文
        uint8_t    k1[MSG_BYTES];
    };

    // Alice 第一步：生成临时密钥对，用 Bob 长期公钥封装 k1
    Status ake_alice_init(const PublicKey& pk_b,
                          AkeAliceState& state);

    // Bob：收到后，用 Alice 长期 pk 和临时 pk 各封装一次，计算会话密钥
    struct AkeBobOutput {
        Ciphertext c_b1;   // KEM.Encaps(pk_a)
        Ciphertext c_b2;   // PKE.Enc(pk_e)
        uint8_t    K[MSG_BYTES];
    };

    Status ake_bob_respond(const PublicKey& pk_b,
                           const SecretKey& sk_b,
                           const PublicKey& pk_a,
                           const PublicKey& pk_e,
                           const Ciphertext& c_a,
                           AkeBobOutput& out);

    // Alice：收到 Bob 的密文，计算会话密钥
    Status ake_alice_finish(const PublicKey& pk_a,
                            const SecretKey& sk_a,
                            const PublicKey& pk_b,
                            const AkeAliceState& state,
                            const AkeBobOutput& bob_out,
                            uint8_t K[MSG_BYTES]);

} // namespace lac

#endif