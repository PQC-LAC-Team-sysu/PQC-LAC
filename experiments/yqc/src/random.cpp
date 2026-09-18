#include "random.hpp"

extern "C" {
#include <openssl/rand.h>
}

namespace lac {

    Status random_bytes(uint8_t* out, int len)
    {
        if (out == nullptr) return Status::ERR_NULL;
        if (len <= 0)       return Status::ERR_LENGTH;

        if (RAND_bytes(out, len) != 1) {
            // OpenSSL 没成功，可能是熵池还没准备好
            return Status::ERR_OVERFLOW;
        }
        return Status::OK;
    }

} // namespace lac