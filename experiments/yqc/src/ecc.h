#include "lac_param.h"

#if defined(LAC_LIGHT)
//bch(511,264,33)
#define DATA_LEN 16//MESSAGE_LEN+
#define DATABUF_LEN 24//CODE_LEN-ECC_LEN
#define ECCBUF_LEN 32
#define ECC_LEN 8
#define MAX_ERROR 8
#define CODE_LEN 32
#define LOG_CODE_LEN 8
#endif

#if defined(LAC128)
//bch(511,264,33)
#define DATA_LEN 16//MESSAGE_LEN+
#define DATABUF_LEN 24//CODE_LEN-ECC_LEN
#define ECCBUF_LEN 32
#define ECC_LEN 8
#define MAX_ERROR 8
#define CODE_LEN 32
#define LOG_CODE_LEN 8
#endif

#if defined(LAC192)
//bch(511,264,33)
#define DATA_LEN 32
#define DATABUF_LEN 48
#define ECCBUF_LEN 64
#define ECC_LEN 9
#define MAX_ERROR 8
#define CODE_LEN 64
#define LOG_CODE_LEN 9
#endif

#if defined(LAC256)
//D2+bch(511,264,33)
#define DATA_LEN 32
#define DATABUF_LEN 48
#define ECCBUF_LEN 64
#define ECC_LEN 21
#define MAX_ERROR 18
#define CODE_LEN 64 
#define LOG_CODE_LEN 9
#endif

//error correction encode
int ecc_enc(const unsigned char *d, unsigned char *c);

//error corrction decode
int ecc_dec(unsigned char *d, const unsigned char *c);

