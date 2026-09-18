#include "ecc.hpp"
#include <cstring>
#include <cstdlib>
#include <cstdint>

extern "C" {
#include "bch.h"
}

// 按级别选择 BCH 参数表
extern "C" {
#include "bch.h"
// ecc_bch 定义在 bch.c（通过 include bch-light/128/192/256.h 引入）
// 这里只声明 extern
extern struct bch_control ecc_bch;
}
namespace lac {

constexpr int RATIO = Q / 2;

//  LAC_LIGHT：二维奇偶校验
#if defined(LAC_LIGHT)

Status parity_compute(const uint8_t data[MSG_BYTES],
                      uint8_t col_out[2],
                      uint8_t& row_out)
{
    if (data == nullptr || col_out == nullptr) return Status::ERR_NULL;

    uint16_t x[8];
    std::memcpy(x, data, 16);

    uint16_t col = 0;
    for (int i = 0; i < 8; ++i) col ^= x[i];

    uint8_t row = 0;
    for (int i = 0; i < 8; ++i) {
        uint16_t y = x[i];
        y ^= y >> 1;
        y ^= y >> 2;
        y = static_cast<uint16_t>((y & 0x1111u) * 0x1111u);
        row = static_cast<uint8_t>(row ^ (((y >> 12) & 1) << i));
    }

    col_out[0] = static_cast<uint8_t>(col & 0xFF);
    col_out[1] = static_cast<uint8_t>((col >> 8) & 0xFF);
    row_out    = row;
    return Status::OK;
}

Status parity_correct(uint8_t data[MSG_BYTES],
                      const uint8_t col_parity[2],
                      uint8_t row_parity)
{
    if (data == nullptr || col_parity == nullptr) return Status::ERR_NULL;

    uint16_t x[8];
    std::memcpy(x, data, 16);

    uint8_t col_now[2], row_now;
    parity_compute(data, col_now, row_now);

    uint16_t col_xor = static_cast<uint16_t>(col_now[0] ^ col_parity[0])
                     | (static_cast<uint16_t>(col_now[1] ^ col_parity[1]) << 8);
    uint8_t  row_xor = static_cast<uint8_t>(row_now ^ row_parity);

    for (int i = 0; i < 8; ++i) {
        if ((row_xor >> i) & 1) x[i] ^= col_xor;
    }

    std::memcpy(data, x, 16);
    return Status::OK;
}

Status ecc_encode(const uint8_t msg[MSG_BYTES], uint8_t code[CODE_BYTES])
{
    if (msg == nullptr || code == nullptr) return Status::ERR_NULL;
    std::memcpy(code, msg, MSG_BYTES);
    uint8_t col[2], row;
    parity_compute(msg, col, row);
    code[16] = col[0];
    code[17] = col[1];
    code[18] = row;
    return Status::OK;
}

Status ecc_decode(const uint8_t code[CODE_BYTES], uint8_t msg[MSG_BYTES])
{
    if (code == nullptr || msg == nullptr) return Status::ERR_NULL;
    uint8_t data[16];
    std::memcpy(data, code, 16);
    parity_correct(data, code + 16, code[18]);
    std::memcpy(msg, data, MSG_BYTES);
    return Status::OK;
}

//  LAC128 / LAC192 / LAC256：BCH
#else

// BCH 用到堆上的 elp / poly_2t，需要 init 一次
    static struct bch_control* get_bch()
{
    static bool inited = false;
    if (!inited) {
        ecc_bch.elp = reinterpret_cast<struct gf_poly*>(
            std::malloc((ecc_bch.t + 1) * sizeof(struct gf_poly_deg1)));
        if (ecc_bch.elp) {
            std::memset(ecc_bch.elp, 0,
                        (ecc_bch.t + 1) * sizeof(struct gf_poly_deg1));
        }
        for (int i = 0; i < 4; ++i) {
            ecc_bch.poly_2t[i] = reinterpret_cast<struct gf_poly*>(
                std::malloc(GF_POLY_SZ(2 * ecc_bch.t)));
            if (ecc_bch.poly_2t[i]) {
                std::memset(ecc_bch.poly_2t[i], 0,
                            GF_POLY_SZ(2 * ecc_bch.t));
            }
        }
        inited = true;
    }
    return &ecc_bch;
}

Status ecc_encode(const uint8_t msg[MSG_BYTES], uint8_t code[CODE_BYTES])
{
    if (msg == nullptr || code == nullptr) return Status::ERR_NULL;

    struct bch_control* bch = get_bch();

    uint8_t ecc[ECC_BYTES];
    std::memset(ecc, 0, sizeof(ecc));

    // BCH 的输入数据长度固定为 DATA_LEN
    constexpr int DATA_LEN = MSG_BYTES;
    uint8_t data[DATA_LEN];
    std::memcpy(data, msg, MSG_BYTES);

    encode_bch(bch, data, DATA_LEN, ecc);

    std::memcpy(code, msg, MSG_BYTES);
    std::memcpy(code + MSG_BYTES, ecc, ECC_BYTES);
    return Status::OK;
}

Status ecc_decode(const uint8_t code[CODE_BYTES], uint8_t msg[MSG_BYTES])
{
    if (code == nullptr || msg == nullptr) return Status::ERR_NULL;

    struct bch_control* bch = get_bch();

    constexpr int DATA_LEN = MSG_BYTES;
    uint8_t data[DATA_LEN];
    std::memcpy(data, code, MSG_BYTES);

    uint8_t ecc[ECC_BYTES];
    std::memcpy(ecc, code + MSG_BYTES, ECC_BYTES);

    constexpr int MAX_ERROR = 32;
    unsigned int errloc[MAX_ERROR];
    int nerr = decode_bch(bch, data, DATA_LEN, ecc, nullptr, nullptr, errloc);

    // 纠正错误
    if (nerr > 0) {
        for (int i = 0; i < nerr && i < MAX_ERROR; ++i) {
            if (errloc[i] < DATA_LEN * 8) {
                data[errloc[i] / 8] ^= static_cast<uint8_t>(1u << (errloc[i] % 8));
            }
        }
    }

    std::memcpy(msg, data, MSG_BYTES);
    return Status::OK;
}

#endif // LAC_LIGHT
//  D2 编码 / 解码（所有级别共用）
Status d2_encode(const uint8_t code[CODE_BYTES], uint8_t e2[C2_BYTES])
{
    if (code == nullptr || e2 == nullptr) return Status::ERR_NULL;
    for (int i = 0; i < CODE_BITS; ++i) {
        int bit = (code[i / 8] >> (i % 8)) & 1;
        if (bit) {
            e2[i]             = static_cast<uint8_t>(e2[i] + RATIO);
            e2[i + CODE_BITS] = static_cast<uint8_t>(e2[i + CODE_BITS] + RATIO);
        }
    }
    return Status::OK;
}

Status d2_decode(const uint8_t c2[C2_BYTES],
                 const uint8_t out[C2_BYTES],
                 uint8_t code[CODE_BYTES])
{
    if (c2 == nullptr || out == nullptr || code == nullptr)
        return Status::ERR_NULL;

    std::memset(code, 0, CODE_BYTES);
    constexpr int center = Q / 2;
    constexpr int bound  = Q / 2;

    for (int i = 0; i < CODE_BITS; ++i) {
        int t1 = (static_cast<int>(c2[i])              - static_cast<int>(out[i])              + Q) % Q;
        int t2 = (static_cast<int>(c2[i + CODE_BITS])  - static_cast<int>(out[i + CODE_BITS])  + Q) % Q;

        if (t1 < center) t1 = center - t1 + center;
        if (t2 < center) t2 = center - t2 + center;

        int combined = t1 + t2 - Q;
        if (combined < bound) {
            code[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
        }
    }
    return Status::OK;
}

} // namespace lac