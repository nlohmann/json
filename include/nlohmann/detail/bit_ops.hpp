//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // uint64_t

#include <nlohmann/detail/abi_macros.hpp>

// Portable bit-level helpers for the number and string scanners. They use
// compiler builtins where available and plain C++ otherwise, so they need no
// platform headers and work regardless of byte order.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// number of leading zero bits of x (x != 0)
inline int count_leading_zeros(std::uint64_t x) noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_clzll(x);
#else
    int n = 0;
    for (int shift = 32; shift != 0; shift >>= 1)
    {
        if ((x >> (64 - shift)) == 0)
        {
            n += shift;
            x <<= shift;
        }
    }
    return n;
#endif
}

/// the 128-bit product of two 64-bit numbers
struct uint128_parts
{
    std::uint64_t low;
    std::uint64_t high;
};

inline uint128_parts full_multiplication(std::uint64_t a, std::uint64_t b) noexcept
{
#if defined(__SIZEOF_INT128__)
    __extension__ using uint128 = unsigned __int128;
    const uint128 r = static_cast<uint128>(a) * b;
    return {static_cast<std::uint64_t>(r), static_cast<std::uint64_t>(r >> 64u)};
#else
    const std::uint64_t a_lo = a & 0xFFFFFFFFu;
    const std::uint64_t a_hi = a >> 32u;
    const std::uint64_t b_lo = b & 0xFFFFFFFFu;
    const std::uint64_t b_hi = b >> 32u;
    const std::uint64_t lo_lo = a_lo * b_lo;
    const std::uint64_t hi_lo = a_hi * b_lo;
    const std::uint64_t lo_hi = a_lo * b_hi;
    const std::uint64_t hi_hi = a_hi * b_hi;
    const std::uint64_t cross = (lo_lo >> 32u) + (hi_lo & 0xFFFFFFFFu) + lo_hi;
    return {(cross << 32u) | (lo_lo & 0xFFFFFFFFu), (hi_lo >> 32u) + (cross >> 32u) + hi_hi};
#endif
}

/// eight bytes as a little-endian word (compilers fold this into one load on
/// little-endian targets)
inline std::uint64_t read_eight_bytes(const char* p) noexcept
{
    const auto* b = reinterpret_cast<const unsigned char*>(p); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    return static_cast<std::uint64_t>(b[0]) | (static_cast<std::uint64_t>(b[1]) << 8u)
           | (static_cast<std::uint64_t>(b[2]) << 16u) | (static_cast<std::uint64_t>(b[3]) << 24u)
           | (static_cast<std::uint64_t>(b[4]) << 32u) | (static_cast<std::uint64_t>(b[5]) << 40u)
           | (static_cast<std::uint64_t>(b[6]) << 48u) | (static_cast<std::uint64_t>(b[7]) << 56u);
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
