#ifndef LAC_PARAMS_HPP
#define LAC_PARAMS_HPP

namespace lac {

// 安全级别：CMake 通过 -DLAC_LIGHT / -DLAC128 / -DLAC192 / -DLAC256 选择
#if !defined(LAC_LIGHT) && !defined(LAC128) \
 && !defined(LAC192) && !defined(LAC256)
#define LAC_LIGHT
#endif
//  各级别参数
#if defined(LAC_LIGHT)

    constexpr int N          = 512;
    constexpr int Q          = 251;
    constexpr int MSG_BYTES  = 16;
    constexpr int ECC_BYTES  = 3;       // 2 列 + 1 行
    constexpr int HAMMING_W  = 64;
    constexpr const char* NAME = "LAC-LIGHT";

#elif defined(LAC128)

    constexpr int N          = 512;
    constexpr int Q          = 251;
    constexpr int MSG_BYTES  = 16;
    constexpr int ECC_BYTES  = 8;       // BCH(255,128,17)
    constexpr int HAMMING_W  = 128;
    constexpr const char* NAME = "LAC128";

#elif defined(LAC192)

    constexpr int N          = 1024;
    constexpr int Q          = 251;
    constexpr int MSG_BYTES  = 32;
    constexpr int ECC_BYTES  = 9;       // BCH(511,256,17)
    constexpr int HAMMING_W  = 128;
    constexpr const char* NAME = "LAC192";

#elif defined(LAC256)

    constexpr int N          = 1024;
    constexpr int Q          = 251;
    constexpr int MSG_BYTES  = 32;
    constexpr int ECC_BYTES  = 21;      // BCH(511,256,41)
    constexpr int HAMMING_W  = 192;
    constexpr const char* NAME = "LAC256";

#endif

//  派生常量
constexpr int SEED_BYTES = 32;
constexpr int CODE_BYTES = MSG_BYTES + ECC_BYTES;
constexpr int CODE_BITS  = CODE_BYTES * 8;
constexpr int C2_BYTES   = 2 * CODE_BITS;
constexpr int PK_BYTES   = SEED_BYTES + N;
constexpr int SK_BYTES   = N + PK_BYTES;
constexpr int CT_BYTES   = N + C2_BYTES / 2;

//  编译期检查
static_assert(Q > 0 && Q < 256, "Q must fit in a byte");
static_assert(N > 0 && (N & (N - 1)) == 0, "N must be a power of two");
static_assert(PK_BYTES == SEED_BYTES + N, "PK size mismatch");
static_assert(SK_BYTES == N + PK_BYTES, "SK size mismatch");
static_assert(CT_BYTES == N + C2_BYTES / 2, "CT size mismatch");

} // namespace lac

#endif // LAC_PARAMS_HPP