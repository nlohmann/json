//
// Created by Andrea Cocito on 05/10/25.
//
#include "doctest.h"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#if defined(__APPLE__)
    #include <mach/mach.h>
    #include <sys/resource.h>
#elif defined(__unix__) || defined(__linux__)
    #include <sys/resource.h>
    #include <unistd.h>
#endif

using nlohmann::ordered_json;

namespace
{

// ---- timing & memory helpers ------------------------------------------------

using clock_tp = std::chrono::steady_clock::time_point;

inline clock_tp now()
{
    return std::chrono::steady_clock::now();
}

struct CpuTimes
{
    long long user_us = 0;
    long long sys_us  = 0;
};

inline CpuTimes cpu_now()
{
    CpuTimes t{};
#if defined(__APPLE__) || defined(__unix__) || defined(__linux__)
    rusage ru {};
    getrusage(RUSAGE_SELF, &ru);
    t.user_us = static_cast<long long>(ru.ru_utime.tv_sec) * 1000000LL + ru.ru_utime.tv_usec;
    t.sys_us  = static_cast<long long>(ru.ru_stime.tv_sec) * 1000000LL + ru.ru_stime.tv_usec;
#endif
    return t;
}

inline std::size_t current_rss_bytes()
{
#if defined(__APPLE__)
    mach_task_basic_info info {};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS)
    {
        return static_cast<std::size_t>(info.resident_size);
    }
    return 0;
#elif defined(__linux__)
    // ru_maxrss is in kilobytes on Linux — it's *peak* RSS, not current.
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    return static_cast<std::size_t>(ru.ru_maxrss) * 1024ULL;
#elif defined(__unix__)
    // Fallback POSIX: ru_maxrss unit is implementation-defined. Treat as bytes if huge, else KB.
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    std::size_t v = static_cast<std::size_t>(ru.ru_maxrss);
    if (v < (1ULL << 20))
    {
        v *= 1024ULL;    // heuristic: likely KB
    }
    return v;
#else
    return 0; // unsupported platform
#endif
}

inline std::string fmt_bytes(std::size_t b)
{
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double val = static_cast<double>(b);
    int u = 0;
    while (val >= 1024.0 && u < 4)
    {
        val /= 1024.0;
        ++u;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << val << ' ' << units[u];
    return oss.str();
}

struct PhaseTimer
{
    clock_tp  w0 = now();
    CpuTimes  c0 = cpu_now();
    std::size_t rss0 = current_rss_bytes();

    void print(const char* label)
    {
        auto w1 = now();
        CpuTimes c1 = cpu_now();
        std::size_t rss1 = current_rss_bytes();

        const double wall_ms = std::chrono::duration<double, std::milli>(w1 - w0).count();
        const double cpu_ms  = static_cast<double>((c1.user_us - c0.user_us) + (c1.sys_us - c0.sys_us)) / 1000.0;

        std::cout << std::left << std::setw(28) << label
                  << " | wall: " << std::setw(10) << std::fixed << std::setprecision(3) << wall_ms << " ms"
                  << " | cpu: "  << std::setw(10) << std::fixed << std::setprecision(3) << cpu_ms  << " ms"
                  << " | RSS: "  << fmt_bytes(rss1)
#if !defined(__APPLE__)
                  << " (peak on this platform)"
#endif
                  << '\n';
        // reset for next phase
        w0 = w1;
        c0 = c1;
        rss0 = rss1;
    }
};

// ---- random data helpers ----------------------------------------------------

inline std::string random_hex32(std::mt19937_64& rng)
{
    static const char* hex = "0123456789abcdef";
    // 16 random bytes -> 32 hex chars
    char out[32];
    for (int i = 0; i < 4; ++i)
    {
        uint64_t x = rng();
        // take 16 hex chars from 64 bits (we need 32 total -> 4*8 nibbles)
        for (int n = 0; n < 8; ++n)
        {
            out[i * 8 + (7 - n)] = hex[(x & 0xFULL)];
            x >>= 4;
        }
    }
    return std::string(out, out + 32);
}

inline std::vector<std::string> make_keys(std::size_t N, std::mt19937_64& rng)
{
    std::vector<std::string> v;
    v.reserve(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        v.push_back(random_hex32(rng));
    }
    return v;
}

inline std::vector<std::size_t> shuffled_indices(std::size_t N, std::mt19937_64& rng)
{
    std::vector<std::size_t> idx(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        idx[i] = i;
    }
    std::shuffle(idx.begin(), idx.end(), rng);
    return idx;
}

} // namespace

TEST_CASE("ordered_map perf: fill, access, erase")
{
    // N: default 20000; override with env NLOHMANN_OM_BENCH_N
    std::size_t N = 20000;
    if (const char* env = std::getenv("NLOHMANN_OM_BENCH_N"))
    {
        try
        {
            N = static_cast<std::size_t>(std::stoull(env));
        }
        catch (...) { /* keep default */ }
    }
    // RNG seed: fixed by default for repeatability; override with env NLOHMANN_OM_BENCH_SEED
    uint64_t seed = 0xC0FFEE123456789ULL;
    if (const char* s = std::getenv("NLOHMANN_OM_BENCH_SEED"))
    {
        try
        {
            seed = std::stoull(s);
        }
        catch (...) {}
    }
    std::mt19937_64 rng(seed);

    std::cout << "[ordered_map perf] N=" << N << "  seed=" << seed << "\n";

    PhaseTimer T;

    // (a) make base keys and 3 random orders
    auto keys   = make_keys(N, rng);
    auto order1 = shuffled_indices(N, rng);
    auto order2 = shuffled_indices(N, rng);
    auto order3 = shuffled_indices(N, rng);
    T.print("a) generated keys & shuffles");

    // (b) fill ordered_json j with j[keys[order1[i]]] = i
    ordered_json j = ordered_json::object();
    for (std::size_t i = 0; i < N; ++i)
    {
        j[keys[order1[i]]] = static_cast<int>(i);
    }
    // sanity
    CHECK(j.size() == N);
    T.print("b) filled object");

    // (c) access in random order and sum results
    volatile std::uint64_t sum = 0;
    for (std::size_t i = 0; i < N; ++i)
    {
        const auto& k = keys[order2[i]];
        sum += static_cast<std::uint64_t>(j[k].get<int>());
    }
    // keep compiler from optimizing away
    std::cout << "    sum=" << sum << "\n";
    T.print("c) random access");

    // (d) erase in random order
    std::size_t removed = 0;
    for (std::size_t i = 0; i < N; ++i)
    {
        const auto& k = keys[order3[i]];
        removed += j.erase(k);
    }
    CHECK(removed == N);
    CHECK(j.empty());
    T.print("d) random erase");
}
