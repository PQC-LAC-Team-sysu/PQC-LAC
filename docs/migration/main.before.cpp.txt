#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstdio>
#include <cstring>

int main() {
    const char* msg = "hello PQC";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int a;
    // 方式一：直接调用 SHA256（简单 API）
    SHA256(reinterpret_cast<const unsigned char*>(msg), std::strlen(msg), digest);

    std::printf("SHA-256(\"%s\") = ", msg);
    for (unsigned char c : digest) std::printf("%02x", c);
    std::printf("\n");

    // 方式二：EVP 高层 API（推荐用法，验证 libcrypto 完整）
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, msg, std::strlen(msg));
    unsigned int len = 0;
    unsigned char digest2[EVP_MAX_MD_SIZE];
    EVP_DigestFinal_ex(ctx, digest2, &len);
    EVP_MD_CTX_free(ctx);

    std::printf("EVP SHA-256        = ");
    for (unsigned int i = 0; i < len; ++i) std::printf("%02x", digest2[i]);
    std::printf("\n");

    return 0;
}