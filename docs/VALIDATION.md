# 验证和初步性能记录

记录日期：2026-09-18。这里记录实际执行结果，原始输出保存在 `results/`。这不是安全认证或论文最终实验。

## 环境

- CPU：AMD Ryzen 5 7640HS with Radeon 760M Graphics，WSL 可见 12 个逻辑处理器，支持 AVX2。
- Ubuntu / WSL2，内核 `6.6.87.2-microsoft-standard-WSL2`。
- GCC/G++ 13.3.0，CMake 3.28.3，C++20。
- vcpkg 的 OpenSSL 3.6.4（25 Aug 2026），链接 `OpenSSL::Crypto`。
- Debug/ASan 使用 vcpkg debug libcrypto，Release 使用 release libcrypto。
- Release 使用 CMake/GCC 的 `-O3 -DNDEBUG`；AVX2 选项仅用于本工程 AVX2 文件，未全局打开 `-march=native`。

## 正确性检查

| 构建/检查 | 结果 | 原始记录 |
|---|---|---|
| Release，自动后端，可选原 AES-NI 对照 | CTest 6/6 通过 | `results/release-ctest.txt` |
| Debug + ASan/UBSan，泄漏检查，UB 立即失败 | CTest 6/6 通过 | `results/asan-ctest.txt` |
| Release，`LAC_ENABLE_AVX2=OFF` | CTest 6/6 通过 | `results/portable-ctest.txt` |

六项检查分别为：

1. `crypto_tests`：AES/SHA 已知答案、独立 ECB 计数器参考、0..4097 边界中的选定长度、缓冲区别名、复用和清除；启用时与原 AES-NI 逐字节对照。
2. `bch_tests`：原校验向量、生成表指纹、全部 929 个有效码位的逐位翻转、纠错能力范围内多位错误、超过 bit 255 的位置、填充/边界和并发。
3. `kernel_tests`：独立模运算卷积参考与通用/AVX2 输出对照，含零、多项式边界值和尾块。
4. `kem_tests`：四参数往返、独立成功/拒绝散列、错误长度、非法公私钥、随机源失败、重叠、输出清除、后端互操作、对象移动和独立实例并发。
5. `vector_tests`：60 条不同的原始向量（每组 LIGHT/192/256 各 10 PKE + 10 KEM），分别在通用与自动后端执行。核对 PKE 解密、旧共享秘密、确定性密文重加密及 v1 共享秘密。
6. `kem_stress_smoke`：每参数 32 轮固定测试样本，包含全随机非法密文和单 bit 故障。

原项目没有提供 LAC128 向量文件；该参数覆盖来自独立多项式/BCH 检验、新生成测试和后端差分，不冒充外部官方 KAT。

ASan/UBSan 检查覆盖本工程编译的代码；预编译的 OpenSSL 本身没有被本次构建重新插桩。测试通过不证明所有输入、所有平台或所有侧信道安全。

## 压力与故障实验

分别运行 `kem_stress 10000 auto` 和 `kem_stress 10000 portable`。

| 每一种后端 | 正常往返 | 单 bit 故障 | 全随机密文 | 不一致 |
|---|---:|---:|---:|---:|
| LAC_LIGHT | 10000 | 5000 | 5000 | 0 |
| LAC128 | 10000 | 5000 | 5000 | 0 |
| LAC192 | 10000 | 5000 | 5000 | 0 |
| LAC256 | 10000 | 5000 | 5000 | 0 |

两后端合计执行 8 万次正常往返和 8 万次故障解封装。它们使用相同的固定测试随机序列，故不是 8 万个独立随机样本；不同样本数为 4 万。每轮更换密钥。故障实验独立计算 `Trunc(SHA256(SHA256(sk)||ct))` 核对结果，而非仅要求“不同于正常秘密”。原始计数与 seed 见 `results/stress-auto.csv` 和 `results/stress-portable.csv`。

固定 seed 和测试随机源仅为复现测试，不可用于真实密钥。零次观察到失败不能证明文献级的极低解密失败率。

## 初步性能

调用 `kem_bench 1000 all`；每项预热 8 次后测量 1000 次，表格为 **median，微秒**。每次计时包括 API 的输入检查、OpenSSL 随机数（适用时）、计算和内部清除；结果正确性核验和 CSV 输出在计时区间之外。

| 参数 | KeyGen 通用 / AVX2 | Encaps 通用 / AVX2 | Decaps 通用 / AVX2 |
|---|---:|---:|---:|
| LAC_LIGHT | 26.169 / 22.519 | 30.480 / 27.254 | 44.710 / 34.933 |
| LAC128 | 27.625 / 19.517 | 40.398 / 30.099 | 61.007 / 48.787 |
| LAC192 | 43.541 / 18.239 | 43.483 / 25.377 | 78.108 / 44.301 |
| LAC256 | 33.449 / 23.676 | 55.413 / 37.007 | 100.659 / 74.099 |

min、p95 和非法密文解封装计时在 `results/benchmark.csv`。这次测量中 AVX2 的 LAC192 封装 median 约为通用版的 58%，解封装约为 57%；这是本次单机观察值，不是跨平台保证。

对象构造与首次 provider 初始化不计入测量。重复封装和解封装固定使用同一公钥，可命中公共 `a` 缓存；KeyGen 每次生成新密钥。通用路径仍可能被 GCC 自动向量化，因此不能把它称为“纯标量基线”。

未固定 CPU 频率和亲和性，未关闭主机其他应用；WSL 调度、频率变化以及按顺序测不同后端会影响结果，部分 p95 明显波动。没有对旧 C/DLL 做同条件计时，也没有把本次结果外推为 MCU 性能。论文应补充重复独立测量、随机交错顺序、冷启动和目标板实验。

## 复现检查构建

在工程根目录的 WSL 终端中：

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE=/home/wisif/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DLAC_ENABLE_SANITIZERS=ON -DLAC_TEST_LEGACY_AES=ON
cmake --build build-asan -j 4
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ASAN_OPTIONS=detect_leaks=1 \
  ctest --test-dir build-asan --output-on-failure

cmake -S . -B build-portable -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=/home/wisif/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DLAC_ENABLE_AVX2=OFF
cmake --build build-portable -j 4
ctest --test-dir build-portable --output-on-failure
./build-portable/kem_stress 10000 portable
```

## CLion 工程集成验证

实际工程：`C:/Users/22126/CLionProjects/PQC-LAC`。

在现有 `cmake-build-debug-wsl` 中重新配置并构建全部目标，退出码为 0；随后在该目录运行 CTest，**6/6 通过**。实际运行 `PQC`，四参数的往返和篡改拒绝检查均通过，退出码为 0。使用的是 CLion 当前 Debug-WSL 配置的目录与编译工具链；本次从终端调用，没有通过 IDE 界面点击运行。

- `results/clion-wsl-build.txt`：工程内最终构建输出。
- `results/clion-wsl-ctest.txt`：工程内 CTest 输出。
- `results/clion-wsl-demo.txt`：主程序输出。

跨 Windows/WSL 文件系统构建时，gmake 对若干刚生成依赖文件报告毫秒级至约 0.45 秒的未来时间戳和 `Clock skew detected` 警告。全部目标成功生成并通过上述实际运行检查；没有修改系统时间。原生 WSL `/tmp` 中的独立验证构建没有出现该警告。若后续增量构建受时间戳影响，可将构建目录放入 WSL 原生文件系统。

迁移前的主程序、CMake、README 副本在 `docs/migration/`；原 OpenSSL 示例额外保留为可构建目标。未修改 `.idea` 工具链设置、根许可证及 `lib/pqc_rand.*`，未创建 Git 提交。
