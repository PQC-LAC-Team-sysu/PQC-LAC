# YQC 的 LAC 独立实现

本目录是对 LAC 四大模块（PKE / KEM / KEX / AKE）的一份 C++ 重写，与团队 `lib/lac/` 下的实现相互独立，作为对照与参考。

## 特点

- C++ 风格：`namespace` + `constexpr` + `std::array` + `Status` 枚举
- 修复原代码的若干问题：
    - `ALIGNED` 用 `alignas` 替代 `__declspec`（MinGW 下生效）
    - `cpu_to_be32` 使用 `uint32_t` 和显式掩码
    - `poly_compress/decompress` 增加边界检查
    - `poly_mul` 显式处理负系数取模
    - KEM 的 `K = H(m ‖ c)` 与设计文档一致
    - 使用 OpenSSL `RAND_bytes` 作为密码学安全随机源
- 支持四个安全级别：LAC_LIGHT / LAC128 / LAC192 / LAC256
- 15 项测试覆盖多项式、采样、纠错码、PKE、KEM、KEX、AKE

## 构建

在仓库根目录或本目录内都可以单独构建：

```sh
cd experiments/yqc
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4