//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // uint64_t
#include <cstring> // memcpy
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64)) && (!defined(__SIZEOF_INT128__) || (!defined(__GNUC__) && !defined(__clang__)))
    #include <intrin0.h> // __umulh, _umul128, _BitScanForward64, _BitScanReverse64
#endif

#ifdef _MSC_VER
    #include <cstdlib> // _byteswap_ushort, _byteswap_ulong, _byteswap_uint64
#endif
#if defined(_MSC_VER) && !defined(__clang__) && (defined(_M_IX86) || defined(_M_ARM))
    #include <intrin.h> // _BitScanForward, _BitScanReverse
#endif

#include <nlohmann/detail/macro_scope.hpp> // JSON_HEDLEY_ALWAYS_INLINE, NLOHMANN_JSON_NAMESPACE_BEGIN

#if defined(__cpp_lib_bit_cast) || defined(__cpp_lib_bitops) || defined(__cpp_lib_byteswap)
    #include <bit> // bit_cast, byteswap, countl_zero, countr_zero
#endif

// Portable bit-level helpers for the number and string scanners. They use
// compiler builtins or platform-specific intrinsics where available, the
// C++20 <bit> functions next, and plain C++ otherwise, so they work regardless
// of byte order. (The builtins and intrinsics come first: MSVC's
// std::countl_zero checks for LZCNT at run time unless AVX2 is enabled.)

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// number of leading zero bits of x (x != 0)
inline int count_leading_zeros(std::uint64_t x) noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_clzll(x);
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
    unsigned long index = 0; // NOLINT(runtime/int): the type _BitScan*64 takes
    _BitScanReverse64(&index, x);
    return 63 - static_cast<int>(index);
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_ARM))
    unsigned long index = 0; // NOLINT(runtime/int): the type _BitScan* takes
    if (_BitScanReverse(&index, static_cast<unsigned long>(x >> 32u))) // NOLINT(runtime/int)
    {
        return 31 - static_cast<int>(index);
    }
    _BitScanReverse(&index, static_cast<unsigned long>(x)); // NOLINT(runtime/int)
    return 63 - static_cast<int>(index);
#elif defined(__cpp_lib_bitops)
    return std::countl_zero(x);
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

/// number of trailing zero bits of x (x != 0)
inline int count_trailing_zeros(std::uint64_t x) noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_ctzll(x);
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
    unsigned long index = 0; // NOLINT(runtime/int): the type _BitScan*64 takes
    _BitScanForward64(&index, x);
    return static_cast<int>(index);
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_ARM))
    unsigned long index = 0; // NOLINT(runtime/int): the type _BitScan* takes
    if (_BitScanForward(&index, static_cast<unsigned long>(x))) // NOLINT(runtime/int)
    {
        return static_cast<int>(index);
    }
    _BitScanForward(&index, static_cast<unsigned long>(x >> 32u)); // NOLINT(runtime/int)
    return 32 + static_cast<int>(index);
#elif defined(__cpp_lib_bitops)
    return std::countr_zero(x);
#else
    int n = 0;
    for (int shift = 32; shift != 0; shift >>= 1)
    {
        if ((x << (64 - shift)) == 0)
        {
            n += shift;
            x >>= shift;
        }
    }
    return n;
#endif
}

/// the object representation of @a from as a @a To (std::bit_cast in C++20)
template<typename To, typename From>
JSON_HEDLEY_ALWAYS_INLINE To bit_cast(const From& from) noexcept
{
    static_assert(sizeof(To) == sizeof(From), "bit_cast needs types of the same size");
#if defined(__cpp_lib_bit_cast)
    return std::bit_cast<To>(from);
#else
    To to {};
    std::memcpy(&to, &from, sizeof(To));
    return to;
#endif
}

/// x with its bytes in reverse order (std::byteswap in C++23); compilers lower
/// it to a single bswap/rev/movbe
inline std::uint16_t byteswap(std::uint16_t x) noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap16(x);
#elif defined(_MSC_VER)
    return _byteswap_ushort(x);
#elif defined(__cpp_lib_byteswap)
    return std::byteswap(x);
#else
    return static_cast<std::uint16_t>((x >> 8u) | (x << 8u));
#endif
}

/// x with its bytes in reverse order (std::byteswap in C++23)
inline std::uint32_t byteswap(std::uint32_t x) noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#elif defined(_MSC_VER)
    return _byteswap_ulong(x);
#elif defined(__cpp_lib_byteswap)
    return std::byteswap(x);
#else
    return ((x & 0x000000FFu) << 24u) | ((x & 0x0000FF00u) << 8u)
           | ((x & 0x00FF0000u) >> 8u) | ((x & 0xFF000000u) >> 24u);
#endif
}

/// x with its bytes in reverse order (std::byteswap in C++23)
inline std::uint64_t byteswap(std::uint64_t x) noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(x);
#elif defined(_MSC_VER)
    return _byteswap_uint64(x);
#elif defined(__cpp_lib_byteswap)
    return std::byteswap(x);
#else
    x = ((x & 0x00000000FFFFFFFFull) << 32u) | ((x & 0xFFFFFFFF00000000ull) >> 32u);
    x = ((x & 0x0000FFFF0000FFFFull) << 16u) | ((x & 0xFFFF0000FFFF0000ull) >> 16u);
    x = ((x & 0x00FF00FF00FF00FFull) << 8u) | ((x & 0xFF00FF00FF00FF00ull) >> 8u);
    return x;
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
#elif defined(_MSC_VER) && defined(_M_X64)
    std::uint64_t high = 0;
    const std::uint64_t low = _umul128(a, b, &high);
    return {low, high};
#elif defined(_MSC_VER) && defined(_M_ARM64)
    return {a * b, __umulh(a, b)};
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

/// eight bytes as a little-endian word (a single load on little-endian
/// targets; always inlined, as GCC otherwise calls it in the number loops)
JSON_HEDLEY_ALWAYS_INLINE std::uint64_t read_eight_bytes(const unsigned char* b) noexcept
{
#if JSON_LITTLE_ENDIAN_TARGET
    // the byte order already matches
    std::uint64_t result = 0;
    std::memcpy(&result, b, sizeof(result));
    return result;
#else
    return static_cast<std::uint64_t>(b[0]) | (static_cast<std::uint64_t>(b[1]) << 8u)
           | (static_cast<std::uint64_t>(b[2]) << 16u) | (static_cast<std::uint64_t>(b[3]) << 24u)
           | (static_cast<std::uint64_t>(b[4]) << 32u) | (static_cast<std::uint64_t>(b[5]) << 40u)
           | (static_cast<std::uint64_t>(b[6]) << 48u) | (static_cast<std::uint64_t>(b[7]) << 56u);
#endif
}

/// eight bytes as a little-endian word
JSON_HEDLEY_ALWAYS_INLINE std::uint64_t read_eight_bytes(const char* p) noexcept
{
    return read_eight_bytes(reinterpret_cast<const unsigned char*>(p)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
