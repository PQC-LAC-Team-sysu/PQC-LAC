#ifndef LAC_RANDOM_HPP
#define LAC_RANDOM_HPP

#include "poly.hpp"
#include <cstdint>

namespace lac {

    // 生成 len 字节密码学安全随机数
    Status random_bytes(uint8_t* out, int len);

} // namespace lac

#endif