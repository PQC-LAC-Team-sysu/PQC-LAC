//#define TEST_ROW_ERROR_RATE
//#define LINUX
#define WIN

// 安全级别由 CMake 通过 -DLAC_LIGHT / -DLAC128 / -DLAC192 / -DLAC256 选择
// 如果都没传，默认 LAC_LIGHT
#if !defined(LAC_LIGHT) && !defined(LAC128) && !defined(LAC192) && !defined(LAC256)
#define LAC_LIGHT
#endif

#define Q 251
#define BIG_Q 257024

#if defined(LAC_LIGHT)
#define STRENGTH "LAC_LIGHT"
#define DIM_N 512
#define SEED_LEN 32
#define PK_LEN 544
#define MESSAGE_LEN 16
#define CIPHER_LEN 664
#define C2_VEC_NUM 304
#define NUM_ONE 64
#define HASH_TYPE "SHA256"
#define SAMPLE_LEN 245
#endif