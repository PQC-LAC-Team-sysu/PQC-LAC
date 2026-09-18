# PQC-LAC：C++20 / OpenSSL KEM 实验工程

本工程将所提供的 LAC C/DLL 实现重构为可在 CLion 中构建的 C++20 库，支持 `LAC_LIGHT / LAC128 / LAC192 / LAC256`。OpenSSL 3 提供随机数、AES-256-CTR 扩展和 SHA-256；LAC 的采样、多项式运算、纠错和 KEM 流程在本工程实现。

**版本为 `PQC-LAC-KEM-v1`。保留原 PKE 密文格式，但修复后的共享密钥派生与旧 DLL 不兼容。通信双方必须一起升级。** 这是研究和应用验证代码，尚无完整恒定时间实现、安全证明或目标设备部署评估。

## 在当前 CLion 工程运行

1. 使用已经配置成功的 **Debug-WSL** 工具链，重新加载 CMake。
2. 运行 **PQC**：依次检查四组参数的密钥生成、封装、解封装和篡改拒绝。
3. 运行 CTest 或单独的 `kem_tests`、`vector_tests` 等测试目标。
4. 性能测试使用 **Release** 配置，运行 `kem_bench 1000 all`。

原来的 OpenSSL 演示保留为 `examples/openssl_demo.cpp`，对应目标 `openssl_demo`。原 `main.cpp`、CMake 配置和 README 的迁移前副本存于 `docs/migration/`。现有 `lib/pqc_rand.*` 占位文件保留，KEM 使用受检查的 OpenSSL 随机源。

在 WSL 中进入工程目录，也可使用：

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=/home/wisif/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build-release -j 4
ctest --test-dir build-release --output-on-failure
./build-release/PQC
./build-release/kem_bench 1000 all > benchmark.csv
./build-release/kem_stress 10000 auto
```

`VCPKG` 路径是当前机器配置；其他机器应改成自己的路径，或让 `find_package(OpenSSL)` 使用系统安装。普通 Windows 构建同样需要与其编译器、架构一致的 OpenSSL，不能使用 WSL 的 Linux 库。

## 接口与目录

公共头文件是 `lib/lac/kem.hpp`，库目标是 `lac`。使用方只需 `target_link_libraries(your_target PRIVATE lac)`。

```cpp
lac::Kem kem(lac::ParameterSet::Lac192); // 默认自动选择可用后端
const auto& p = kem.params();
std::vector<lac::Byte> pk(p.public_key_bytes), sk(p.secret_key_bytes);
std::vector<lac::Byte> ct(p.ciphertext_bytes);
std::vector<lac::Byte> sent(p.message_bytes), received(p.message_bytes);
// 每一步都检查 Status；完整例子见 main.cpp。
auto status = kem.keypair(pk, sk);
```

三个操作依次为 `keypair(pk, sk)`、`encapsulate(pk, ct, secret)`、`decapsulate(sk, ct, secret)`。KEM 仅建立共享秘密，应用还需协议身份认证、密钥派生、带认证的数据加密和防重放。

| 路径 | 用途 |
|---|---|
| `lib/lac/kem.*` | 类型化接口、参数、采样、PKE 与 KEM 流程 |
| `lib/lac/crypto.*` | OpenSSL EVP 和随机数，复用上下文 |
| `lib/lac/kernels*.cpp` | 通用/AVX2 稀疏多项式乘法和运行时选择 |
| `lib/lac/bch*` | 无可变全局状态的 BCH 编解码及只读表 |
| `tests/` | 底层已知答案、独立参考、错误路径、向量和压力测试 |
| `benchmarks/kem_bench.cpp` | 包含实际随机数调用的端到端计时 |
| `docs/KEM_DESIGN.md` | 原理、数据格式、优化与安全边界 |
| `docs/VALIDATION.md` | 实测验证记录、性能和复现方法 |

## 构建选项

| 选项 | 默认 | 含义 |
|---|---|---|
| `LAC_ENABLE_AVX2` | ON | 在支持的 x86 编译目标加入 AVX2 文件；执行前检查 CPU 支持 |
| `LAC_BUILD_TESTING` | ON | 测试、压力工具及内部 PKE 测试入口 |
| `LAC_ENABLE_SANITIZERS` | OFF | GCC/Clang 地址检查、未定义行为检查 |
| `LAC_TEST_LEGACY_AES` | OFF | 在可用的 x86 工具链中链接原 AES-NI，仅用于字节流对照测试 |

`Backend::Portable` 强制通用实现；`Backend::Auto` 自动选择；强制不可用的 `Backend::Avx2` 会在构造时抛异常。可用 `-DLAC_ENABLE_AVX2=OFF` 构建完全不包含本工程 AVX2 内核的版本。OpenSSL 自身的硬件选择由 OpenSSL 管理。

每个 `Kem` 对象拥有可复用工作区，不能并发调用同一个对象；多线程每线程使用独立实例。对象不可复制，可以移动。调用方负责安全保存及清除自己的私钥和共享秘密，例子使用 `OPENSSL_cleanse`。

## 来源

原 LAC 源码与测试向量来自本次提供的项目。BCH 衍生文件保留原作者及 GPL-2.0-only 声明；原 AES-NI 对照代码保留 Public Domain 声明。现有根目录 MIT `LICENSE` 不覆盖第三方文件的独立许可，详见 `THIRD_PARTY_NOTICES.md`。
