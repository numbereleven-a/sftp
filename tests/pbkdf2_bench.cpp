// pbkdf2_bench.cpp — measures deriveKeyPbkdf2() speed using the project's
// LanPairInternal.h primitives. Build with the same compiler settings.
#include "LanPairInternal.h"
#include <chrono>
#include <cstdio>

int main() {
    using clock = std::chrono::steady_clock;
    const std::string password = "bench-password-123";
    std::vector<uint8_t> salt(16, 0xAB);

    auto t0 = clock::now();
    auto key = lanpair_internal::deriveKeyPbkdf2(password, salt, 32);
    auto t1 = clock::now();
    if (!key) { printf("derive failed\n"); return 1; }
    const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    printf("deriveKeyPbkdf2(120k iters) took %.0f ms\n", ms);
    return 0;
}
