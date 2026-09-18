#include "lac/kem.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<lac::Byte>;
std::uint64_t checksum = 0;

void require_ok(lac::Status status) {
    if (status != lac::Status::Ok)
        throw std::runtime_error(std::string(lac::status_message(status)));
}

void consume(std::span<const lac::Byte> bytes) {
    for (const auto value : bytes) checksum = (checksum * 257) ^ value;
}

template<class Operation, class Observe>
void measure(const lac::Parameters& p, std::string_view backend, std::string_view operation,
             std::size_t iterations, Operation&& execute, Observe&& observe) {
    constexpr std::size_t warmup_iterations = 8;
    for (std::size_t i = 0; i < warmup_iterations; ++i) {
        require_ok(execute());
        observe();
    }
    std::vector<double> times(iterations);
    for (std::size_t i = 0; i < iterations; ++i) {
        const auto begin = Clock::now();
        const auto status = execute();
        const auto end = Clock::now();
        require_ok(status);
        times[i] = std::chrono::duration<double, std::micro>(end - begin).count();
        observe();
    }
    std::sort(times.begin(), times.end());
    const auto median = iterations % 2 == 0
        ? (times[iterations / 2 - 1] + times[iterations / 2]) / 2
        : times[iterations / 2];
    const auto p95_index = (95 * iterations + 99) / 100 - 1;
    std::cout << p.name << ',' << backend << ',' << operation << ',' << iterations << ','
              << std::fixed << std::setprecision(3) << times.front() << ',' << median << ','
              << times[p95_index] << '\n';
}

void benchmark(lac::ParameterSet set, lac::Backend backend, std::size_t iterations) {
    lac::Kem kem(set, backend);
    const auto& p = kem.params();
    Bytes pk(p.public_key_bytes), sk(p.secret_key_bytes), ct(p.ciphertext_bytes);
    Bytes ss(p.message_bytes), recovered(p.message_bytes);

    // Object construction, first-use provider setup and buffer allocation are
    // excluded. Calls include public API validation and the production RNG.
    measure(p, kem.backend_name(), "keypair", iterations,
            [&] { return kem.keypair(pk, sk); }, [&] { consume(pk); consume(sk); });
    measure(p, kem.backend_name(), "encapsulate", iterations,
            [&] { return kem.encapsulate(pk, ct, ss); }, [&] { consume(ct); consume(ss); });
    require_ok(kem.decapsulate(sk, ct, recovered));
    if (ss != recovered) throw std::runtime_error("benchmark roundtrip verification failed");
    measure(p, kem.backend_name(), "decapsulate", iterations,
            [&] { return kem.decapsulate(sk, ct, recovered); }, [&] {
                if (ss != recovered) throw std::runtime_error("decapsulation output changed");
                consume(recovered);
            });
    Bytes invalid = ct;
    invalid[0] = 255;
    Bytes rejection(p.message_bytes);
    require_ok(kem.decapsulate(sk, invalid, rejection));
    if (rejection == ss) throw std::runtime_error("invalid ciphertext retained valid shared secret");
    measure(p, kem.backend_name(), "decapsulate_reject", iterations,
            [&] { return kem.decapsulate(sk, invalid, recovered); }, [&] {
                if (recovered != rejection) throw std::runtime_error("rejection is not deterministic");
                consume(recovered);
            });
}
} // namespace

int main(int argc, char** argv) {
    try {
        std::size_t iterations = 500;
        if (argc > 3 || (argc > 1 && std::string_view(argv[1]) == "--help")) {
            std::cout << "Usage: kem_bench [iterations: 1..1000000] [all|portable|auto]\n"
                         "CSV times are microseconds; 8 warmup calls per operation.\n"
                         "Run a Release build on an otherwise idle machine.\n";
            return argc > 3 ? 1 : 0;
        }
        if (argc > 1) {
            const std::string_view value(argv[1]);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), iterations);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                iterations == 0 || iterations > 1000000)
                throw std::runtime_error("iterations must be an integer from 1 through 1000000");
        }
        const std::string_view selection = argc > 2 ? argv[2] : "all";
        if (selection != "all" && selection != "portable" && selection != "auto")
            throw std::runtime_error("backend must be all, portable or auto");
        std::cerr << OpenSSL_version(OPENSSL_VERSION) << '\n';
        std::cerr << "Warm reusable contexts; random generation included; timings exclude validation of results.\n";
        std::cout << "parameter,backend,operation,iterations,min_us,median_us,p95_us\n";
        constexpr std::array sets{lac::ParameterSet::Light, lac::ParameterSet::Lac128,
                                  lac::ParameterSet::Lac192, lac::ParameterSet::Lac256};
        for (const auto set : sets) {
            if (selection != "auto") benchmark(set, lac::Backend::Portable, iterations);
            if (selection != "portable") benchmark(set, lac::Backend::Auto, iterations);
        }
        std::cerr << "Result checksum: " << checksum << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Benchmark failed: " << error.what() << '\n';
        return 1;
    }
}
