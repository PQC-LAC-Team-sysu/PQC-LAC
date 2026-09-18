#ifndef LAC_KEX_HPP
#define LAC_KEX_HPP

#include "params.hpp"
#include "pke.hpp"
//  LAC.KEX（被动安全的密钥交换）
//
//  从 LAC.PKE 直接转换：
//    Alice: 生成 (pk_A, sk_A)，发送 pk_A
//    Bob:   收到 pk_A，随机选 m，c = PKE.Enc(pk_A, m)
//           会话密钥 K_B = H(pk_A || m)，发送 c
//    Alice: 收到 c，m = PKE.Dec(sk_A, c)
//           会话密钥 K_A = H(pk_A || m)
//
//  安全性：IND-CPA PKE → 被动安全 KEX

namespace lac {

    struct KexAliceState {
        PublicKey  pk;
        SecretKey  sk;
    };

    // Alice 第一步：生成临时密钥对
    Status kex_alice_init(KexAliceState& state);

    // Bob：收到 Alice 的 pk，生成密文 c 和会话密钥 K
    Status kex_bob_respond(const PublicKey& pk_a,
                           Ciphertext& c,
                           uint8_t K[MSG_BYTES]);

    // Alice 第二步：收到 c，得到会话密钥 K
    Status kex_alice_finish(const KexAliceState& state,
                            const Ciphertext& c,
                            uint8_t K[MSG_BYTES]);

} // namespace lac

#endif