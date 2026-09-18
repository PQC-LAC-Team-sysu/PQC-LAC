#include <cstdio>
#include <cstring>
#include <vector>
#include "src/params.hpp"
#include "src/poly.hpp"
#include "src/sample.hpp"
#include "src/ecc.hpp"
#include "src/pke.hpp"
#include "src/kem.hpp"
#include "src/kex.hpp"
#include "src/ake.hpp"
using namespace lac;

int main() {
    // ---------- 之前的测试 ----------
    {
        Poly a{}; SmallPoly s{}; Poly r{};
        a[0] = 1; s[0] = 1;
        poly_mul(a, s, r);
        printf("Test 1: %s\n", r[0] == 1 ? "pass" : "FAIL");
    }
    {
        Poly a{}; SmallPoly s{}; Poly r{};
        a[N - 1] = 1; s[1] = 1;
        poly_mul(a, s, r);
        printf("Test 2: %s\n", r[0] == Q - 1 ? "pass" : "FAIL");
    }

    // ---------- 新增：采样测试 ----------
    uint8_t seed[SEED_BYTES];
    for (int i = 0; i < SEED_BYTES; ++i) seed[i] = static_cast<uint8_t>(i);

    // 测试 3：sample_uniform 的系数必须在 [0, Q-1]
    {
        Poly a;
        sample_uniform(seed, a);
        bool ok = true;
        for (int i = 0; i < N; ++i) {
            if (a[i] >= Q) { ok = false; break; }
        }
        printf("Test 3: uniform in [0, Q-1] %s\n", ok ? "pass" : "FAIL");
    }

    // 测试 4：sample_sparse 的汉明重量
    {
        SmallPoly s;
        sample_sparse(seed, s);
        int cnt1 = 0, cntm1 = 0;
        for (int i = 0; i < N; ++i) {
            if (s[i] == 1) cnt1++;
            else if (s[i] == -1) cntm1++;
        }
        bool ok = (cnt1 == HAMMING_W) && (cntm1 == HAMMING_W);
        printf("Test 4: hamming weight cnt1=%d cntm1=%d %s\n",
               cnt1, cntm1, ok ? "pass" : "FAIL");
    }

    // 测试 5：sample_sparse_len (e2) 的汉明重量
    {
        std::vector<uint8_t> e2(C2_BYTES);
        sample_sparse_len(seed, e2.data(), C2_BYTES);
        int cnt1 = 0, cntm1 = 0;
        for (int i = 0; i < C2_BYTES; ++i) {
            if (e2[i] == 1) cnt1++;
            else if (e2[i] == Q - 1) cntm1++;
        }
        bool ok = (cnt1 == HAMMING_W) && (cntm1 == HAMMING_W);
        printf("Test 5: e2 hamming weight cnt1=%d cntm1=%d %s\n",
               cnt1, cntm1, ok ? "pass" : "FAIL");
    }
    // ---------- ECC 测试 ----------

    // 测试 6：ecc 编码/解码无错误
    {
        uint8_t msg[MSG_BYTES];
        for (int i = 0; i < MSG_BYTES; ++i) msg[i] = static_cast<uint8_t>(0xA0 + i);

        uint8_t code[CODE_BYTES];
        ecc_encode(msg, code);

        uint8_t msg2[MSG_BYTES];
        ecc_decode(code, msg2);

        bool ok = std::memcmp(msg, msg2, MSG_BYTES) == 0;
        printf("Test 6: ECC no error %s\n", ok ? "pass" : "FAIL");
    }

    // 测试 7：1 bit 错误能被纠正
    {
        uint8_t msg[MSG_BYTES];
        for (int i = 0; i < MSG_BYTES; ++i) msg[i] = 0x55;

        uint8_t code[CODE_BYTES];
        ecc_encode(msg, code);

        // 在第 3 字节的 bit 2 位置翻转 1 bit
        code[3] ^= (1 << 2);

        uint8_t msg2[MSG_BYTES];
        ecc_decode(code, msg2);

        bool ok = std::memcmp(msg, msg2, MSG_BYTES) == 0;
        printf("Test 7: ECC 1-bit error %s\n", ok ? "pass" : "FAIL");
    }

    // 测试 8：D2 编码/解码无噪声
    {
        uint8_t code[CODE_BYTES];
        for (int i = 0; i < CODE_BYTES; ++i) code[i] = 0xAB;

        uint8_t e2[C2_BYTES] = {0};   // 无噪声
        d2_encode(code, e2);

        uint8_t out[C2_BYTES] = {0};  // 理想情况下 out = 0（无噪声）
        uint8_t code2[CODE_BYTES];
        d2_decode(e2, out, code2);

        bool ok = std::memcmp(code, code2, CODE_BYTES) == 0;
        printf("Test 8: D2 round-trip %s\n", ok ? "pass" : "FAIL");
    }
    // ---------- PKE 测试 ----------

    // 测试 9：PKE 往返
    {
        uint8_t master_seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; ++i) master_seed[i] = static_cast<uint8_t>(i);

        PublicKey pk;
        SecretKey sk;
        pke_keygen_from_seed(master_seed, pk, sk);

        uint8_t msg[MSG_BYTES];
        for (int i = 0; i < MSG_BYTES; ++i) msg[i] = static_cast<uint8_t>(0x10 + i);

        uint8_t enc_seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; ++i) enc_seed[i] = static_cast<uint8_t>(0x80 + i);

        Ciphertext ct;
        Status st = pke_encrypt(pk, msg, enc_seed, ct);
        if (st != Status::OK) {
            printf("Test 9: encrypt failed, status=%d\n", (int)st);
        } else {
            uint8_t dec_msg[MSG_BYTES];
            st = pke_decrypt(sk, ct, dec_msg);
            if (st != Status::OK) {
                printf("Test 9: decrypt failed, status=%d\n", (int)st);
            } else {
                bool ok = std::memcmp(msg, dec_msg, MSG_BYTES) == 0;
                printf("Test 9: PKE round-trip %s\n", ok ? "pass" : "FAIL");
                if (!ok) {
                    printf("  msg:  ");
                    for (int i = 0; i < MSG_BYTES; ++i) printf("%02x", msg[i]);
                    printf("\n  dec:  ");
                    for (int i = 0; i < MSG_BYTES; ++i) printf("%02x", dec_msg[i]);
                    printf("\n");
                }
            }
        }
    }

    // 测试 10：PKE 密钥/密文大小
    {
        printf("  PK_BYTES=%d  SK_BYTES=%d  CT_BYTES=%d  MSG_BYTES=%d\n",
               PK_BYTES, SK_BYTES, CT_BYTES, MSG_BYTES);
    }
    // 测试 11：PKE 1000 次往返，统计错误率
    {
        uint8_t master_seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; ++i) master_seed[i] = 0x5A;

        PublicKey pk;
        SecretKey sk;
        pke_keygen_from_seed(master_seed, pk, sk);

        int errors = 0;
        const int N_TRIALS = 1000;

        for (int t = 0; t < N_TRIALS; ++t) {
            uint8_t msg[MSG_BYTES];
            uint8_t enc_seed[SEED_BYTES];
            for (int i = 0; i < MSG_BYTES; ++i)  msg[i]      = static_cast<uint8_t>(t + i);
            for (int i = 0; i < SEED_BYTES; ++i) enc_seed[i] = static_cast<uint8_t>(t * 7 + i);

            Ciphertext ct;
            uint8_t dec_msg[MSG_BYTES];
            pke_encrypt(pk, msg, enc_seed, ct);
            pke_decrypt(sk, ct, dec_msg);

            if (std::memcmp(msg, dec_msg, MSG_BYTES) != 0) errors++;
        }
        printf("Test 11: PKE 1000 trials, errors = %d, rate = %.2e\n",
               errors, static_cast<double>(errors) / N_TRIALS);
    }
    // ---------- KEM 测试 ----------

    // 测试 12：KEM 往返
    {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; ++i) seed[i] = static_cast<uint8_t>(0xC0 + i);

        PublicKey pk;
        SecretKey sk;
        kem_keygen(pk, sk);

        KemCiphertext ct;
        uint8_t ss_enc[MSG_BYTES], ss_dec[MSG_BYTES];

        Status st = kem_encaps(pk, seed, ct, ss_enc);
        if (st != Status::OK) {
            printf("Test 12: encaps failed status=%d\n", (int)st);
        } else {
            st = kem_decaps(sk, pk, ct, ss_dec);
            if (st != Status::OK) {
                printf("Test 12: decaps failed status=%d\n", (int)st);
            } else {
                bool ok = std::memcmp(ss_enc, ss_dec, MSG_BYTES) == 0;
                printf("Test 12: KEM round-trip %s\n", ok ? "pass" : "FAIL");
            }
        }
    }

    // 测试 13：篡改密文，解封装结果应完全不同
    {
        uint8_t seed[SEED_BYTES] = {0};
        PublicKey pk;
        SecretKey sk;
        kem_keygen(pk, sk);

        KemCiphertext ct, ct2;
        uint8_t ss1[MSG_BYTES], ss2[MSG_BYTES];

        kem_encaps(pk, seed, ct, ss1);

        // 篡改
        ct2 = ct;
        ct2.ct.c1[0] ^= 0x01;

        kem_decaps(sk, pk, ct2, ss2);

        bool ok = std::memcmp(ss1, ss2, MSG_BYTES) != 0;
        printf("Test 13: KEM tampered ciphertext -> different key %s\n",
               ok ? "pass" : "FAIL");
    }
    // ---------- KEX 测试 ----------
    {
        KexAliceState alice;
        kex_alice_init(alice);

        Ciphertext c;
        uint8_t K_bob[MSG_BYTES];
        kex_bob_respond(alice.pk, c, K_bob);

        uint8_t K_alice[MSG_BYTES];
        kex_alice_finish(alice, c, K_alice);

        bool ok = std::memcmp(K_alice, K_bob, MSG_BYTES) == 0;
        printf("Test 14: KEX shared key %s\n", ok ? "pass" : "FAIL");
    }

    // ---------- AKE 测试 ----------
    {
        PublicKey pk_a, pk_b;
        SecretKey sk_a, sk_b;
        pke_keygen(pk_a, sk_a);
        pke_keygen(pk_b, sk_b);

        AkeAliceState alice;
        ake_alice_init(pk_b, alice);

        AkeBobOutput bob_out;
        ake_bob_respond(pk_b, sk_b, pk_a, alice.pk_e, alice.c_a, bob_out);

        uint8_t K_alice[MSG_BYTES];
        ake_alice_finish(pk_a, sk_a, pk_b, alice, bob_out, K_alice);

        bool ok = std::memcmp(K_alice, bob_out.K, MSG_BYTES) == 0;
        printf("Test 15: AKE session key %s\n", ok ? "pass" : "FAIL");
    }
    return 0;
}