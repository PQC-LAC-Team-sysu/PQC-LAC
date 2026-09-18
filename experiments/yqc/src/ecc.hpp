#ifndef LAC_ECC_HPP
#define LAC_ECC_HPP

#include "params.hpp"
#include "poly.hpp"

namespace lac {

    // CODE_BYTES / CODE_BITS / C2_BYTES 全部由 params.hpp 提供
    // 二维奇偶校验（仅 LAC_LIGHT 用）
    Status parity_compute(const uint8_t data[MSG_BYTES],
                          uint8_t col_out[2],
                          uint8_t& row_out);

    Status parity_correct(uint8_t data[MSG_BYTES],
                          const uint8_t col_parity[2],
                          uint8_t row_parity);

    // 消息 → 码字
    //   LAC_LIGHT  走 parity + D2
    //   LAC128/192/256 走 BCH + D2
    Status ecc_encode(const uint8_t msg[MSG_BYTES], uint8_t code[CODE_BYTES]);
    Status ecc_decode(const uint8_t code[CODE_BYTES], uint8_t msg[MSG_BYTES]);
    // D2 编码 / 解码（所有级别共用）
    Status d2_encode(const uint8_t code[CODE_BYTES], uint8_t e2[C2_BYTES]);
    Status d2_decode(const uint8_t c2[C2_BYTES],
                     const uint8_t out[C2_BYTES],
                     uint8_t code[CODE_BYTES]);

} // namespace lac

#endif