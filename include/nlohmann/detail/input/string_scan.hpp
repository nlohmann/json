//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // uint32_t, uint64_t, uint8_t
#include <cstring> // memcpy

#include <nlohmann/detail/bit_ops.hpp>
#include <nlohmann/detail/input/simd_scan.hpp>
#include <nlohmann/detail/macro_scope.hpp>

// Optional SIMD backend for bulk UTF-8 validation. This is an opt-in external
// dependency: nlohmann/json itself stays header-only and the C++11 scalar
// validator below is always available; defining JSON_USE_SIMDUTF additionally
// requires the simdutf headers on the include path and linking the simdutf
// library. See string_bulk_run().
//
// simdutf.h itself requires C++17 - it rejects older standards with an #error -
// so the backend is only compiled in from C++17 on. Below that the macro has no
// effect and the scalar validator is used; it accepts and rejects exactly the
// same input, so only throughput differs. macro_scope.hpp is included above to
// have JSON_HAS_CPP_17 available for this test.
#if defined(JSON_USE_SIMDUTF) && defined(JSON_HAS_CPP_17)
    #include <simdutf.h>
#endif

// This file contains the byte-level string-scanning helpers used by the lexer's
// contiguous fast path. They operate purely on raw bytes (no dependency on the
// lexer's template parameters) so they are free functions, keeping the lexer
// itself focused on the state machine; see lexer::get_after_string_run().

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

// classify a single byte as needing individual string handling: the closing
// quote, an escape, a control character, or a non-ASCII (UTF-8)
// lead/continuation byte. Ordinary bytes (0x20..0x7F except '"' and '\\') are
// copied verbatim, which the bulk scanner does 8 bytes at a time.
inline bool is_string_special(unsigned char c) noexcept
{
    return c == '\"' || c == '\\' || c < 0x20u || c >= 0x80u;
}

// SWAR helper: return a word whose high bit is set in every byte of @a v that
// is_string_special(); zero if the 8 bytes are all ordinary.
inline std::uint64_t swar_string_special(std::uint64_t v) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
    const std::uint64_t q = v ^ 0x2222222222222222ull; // '"'  (0x22)
    const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull; // '\\' (0x5C)
    // The usual test for a zero byte is (x - ones) & ~x & high. The `& ~x`
    // only removes bytes from 0x80, and `v & high` flags those anyway, so it
    // can be dropped. Clang finds this reduction itself; GCC does not.
    return ((q - ones) | (b - ones) | (v - 0x2020202020202020ull) | v) & high;
}

// return the index of the first is_string_special() byte in [data, data+n), or
// n if every byte is ordinary; scans 8 bytes at a time
JSON_HEDLEY_ALWAYS_INLINE std::size_t find_string_special(const unsigned char* data, std::size_t n) noexcept
{
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        const std::uint64_t special = swar_string_special(read_eight_bytes(data + i));
        if (special != 0)
        {
            // the lowest flagged byte is the first special one: the borrows of
            // the subtractions can only flag bytes above a true hit
            return i + (static_cast<std::size_t>(count_trailing_zeros(special)) / 8);
        }
    }
    for (; i < n; ++i)
    {
        if (is_string_special(data[i]))
        {
            return i;
        }
    }
    return n;
}

// return the index of the first 0x00 byte in [data, data+n), or n if there is
// none; scans 8 bytes at a time (BSON's C-style strings)
JSON_HEDLEY_ALWAYS_INLINE std::size_t find_zero_byte(const unsigned char* data, std::size_t n) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        const std::uint64_t v = read_eight_bytes(data + i);
        const std::uint64_t zero = (v - ones) & ~v & high;
        if (zero != 0)
        {
            // the lowest flagged byte is the first zero byte (see
            // find_string_special())
            return i + (static_cast<std::size_t>(count_trailing_zeros(zero)) / 8);
        }
    }
    for (; i < n; ++i)
    {
        if (data[i] == 0x00)
        {
            return i;
        }
    }
    return n;
}

// classify a byte as one the serializer must NOT copy verbatim when
// ensure_ascii is requested: the closing quote, an escape, a control character
// (< 0x20), DEL (0x7F), or any non-ASCII byte (>= 0x80). Everything else -
// printable ASCII except '"' and '\\' - is emitted unchanged. Note this differs
// from is_string_special() only in that 0x7F is also a stop (it is escaped as
// \u007f under ensure_ascii).
constexpr bool is_ascii_copyable(unsigned char c) noexcept
{
    return c >= 0x20u && c < 0x7Fu && c != '"' && c != '\\';
}

// return the index of the first byte in [data, data+n) that is NOT
// is_ascii_copyable(), or n if every byte can be copied verbatim; scans 8 bytes
// at a time. Used by the serializer's ensure_ascii fast path.
inline std::size_t find_ascii_copyable_run(const unsigned char* data, std::size_t n) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        const std::uint64_t v = read_eight_bytes(data + i);
        const std::uint64_t q = v ^ 0x2222222222222222ull; // '"'  (0x22)
        const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull; // '\\' (0x5C)
        const std::uint64_t d = v ^ 0x7F7F7F7F7F7F7F7Full; // DEL  (0x7F)
        // (see swar_string_special(): the bytes from 0x80 are stops anyway)
        const std::uint64_t stop = ((q - ones) | (b - ones) | (d - ones) | (v - 0x2020202020202020ull) | v) & high;
        if (stop != 0)
        {
            // the lowest flagged byte is the first one to stop at (see
            // find_string_special())
            return i + (static_cast<std::size_t>(count_trailing_zeros(stop)) / 8);
        }
    }
    for (; i < n; ++i)
    {
        if (!is_ascii_copyable(data[i]))
        {
            return i;
        }
    }
    return n;
}

// four bytes as a little-endian word (a single load on little-endian targets)
JSON_HEDLEY_ALWAYS_INLINE std::uint32_t read_four_bytes(const unsigned char* b) noexcept
{
#if JSON_LITTLE_ENDIAN_TARGET
    std::uint32_t result = 0;
    std::memcpy(&result, b, sizeof(result));
    return result;
#else
    return static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8u)
           | (static_cast<std::uint32_t>(b[2]) << 16u) | (static_cast<std::uint32_t>(b[3]) << 24u);
#endif
}

// 4-KiB bitmask lookup table indexed by ((c0 << 2) | ((c1 >> 4) & 3)):
// - 0x00000000u for ASCII lead bytes (0x00..0x7F)
// - 0x0000C000u / 0x00C0C000u / 0xC0C0C000u continuation-check masks for valid
//   2-, 3-, and 4-byte RFC 3629 lead + second-byte-nibble combinations
// - 0x00000080u for invalid leads, overlong ranges, surrogates, and > U+10FFFF
template<typename Dummy = void>
struct utf8_prefix_table
{
    static const std::array<std::uint32_t, 1024> masks;
};

template<typename Dummy>
const std::array<std::uint32_t, 1024> utf8_prefix_table<Dummy>::masks =
{
    {
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x00..0x01
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x02..0x03
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x04..0x05
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x06..0x07
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x08..0x09
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x0A..0x0B
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x0C..0x0D
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x0E..0x0F
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x10..0x11
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x12..0x13
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x14..0x15
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x16..0x17
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x18..0x19
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x1A..0x1B
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x1C..0x1D
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x1E..0x1F
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x20..0x21
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x22..0x23
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x24..0x25
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x26..0x27
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x28..0x29
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x2A..0x2B
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x2C..0x2D
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x2E..0x2F
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x30..0x31
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x32..0x33
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x34..0x35
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x36..0x37
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x38..0x39
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x3A..0x3B
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x3C..0x3D
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x3E..0x3F
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x40..0x41
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x42..0x43
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x44..0x45
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x46..0x47
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x48..0x49
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x4A..0x4B
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x4C..0x4D
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x4E..0x4F
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x50..0x51
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x52..0x53
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x54..0x55
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x56..0x57
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x58..0x59
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x5A..0x5B
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x5C..0x5D
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x5E..0x5F
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x60..0x61
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x62..0x63
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x64..0x65
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x66..0x67
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x68..0x69
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x6A..0x6B
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x6C..0x6D
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x6E..0x6F
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x70..0x71
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x72..0x73
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x74..0x75
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x76..0x77
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x78..0x79
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x7A..0x7B
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x7C..0x7D
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, // 0x7E..0x7F
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x80..0x81
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x82..0x83
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x84..0x85
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x86..0x87
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x88..0x89
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x8A..0x8B
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x8C..0x8D
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x8E..0x8F
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x90..0x91
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x92..0x93
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x94..0x95
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x96..0x97
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x98..0x99
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x9A..0x9B
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x9C..0x9D
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0x9E..0x9F
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xA0..0xA1
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xA2..0xA3
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xA4..0xA5
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xA6..0xA7
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xA8..0xA9
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xAA..0xAB
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xAC..0xAD
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xAE..0xAF
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xB0..0xB1
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xB2..0xB3
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xB4..0xB5
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xB6..0xB7
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xB8..0xB9
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xBA..0xBB
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xBC..0xBD
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xBE..0xBF
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xC0..0xC1
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xC2..0xC3
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xC4..0xC5
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xC6..0xC7
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xC8..0xC9
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xCA..0xCB
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xCC..0xCD
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xCE..0xCF
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xD0..0xD1
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xD2..0xD3
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xD4..0xD5
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xD6..0xD7
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xD8..0xD9
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xDA..0xDB
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xDC..0xDD
        0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, 0x0000C000u, // 0xDE..0xDF
        0x00000080u, 0x00000080u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, // 0xE0..0xE1
        0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, // 0xE2..0xE3
        0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, // 0xE4..0xE5
        0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, // 0xE6..0xE7
        0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, // 0xE8..0xE9
        0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, // 0xEA..0xEB
        0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00000080u, 0x00000080u, // 0xEC..0xED
        0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, 0x00C0C000u, // 0xEE..0xEF
        0x00000080u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, // 0xF0..0xF1
        0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, 0xC0C0C000u, // 0xF2..0xF3
        0xC0C0C000u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xF4..0xF5
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xF6..0xF7
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xF8..0xF9
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xFA..0xFB
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, // 0xFC..0xFD
        0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u, 0x00000080u // 0xFE..0xFF
    }
};

// Validate one UTF-8 sequence at the front of [data, data+avail). Returns its
// length (2..4) only when the bytes form a *well-formed* sequence using exactly
// the same ranges as scan_string()'s per-byte switch, so the bulk path accepts
// the exact same sequences as the byte path and leaves any ill-formed or
// truncated byte for the byte path to diagnose. ASCII bytes (< 0x80) are handled
// by the caller and never passed here.
inline std::size_t validate_one_utf8(const unsigned char* data, std::size_t avail) noexcept
{
    const auto& table = utf8_prefix_table<>::masks;
    if (avail >= 4)
    {
        const std::uint32_t w = read_four_bytes(data);
        const std::uint32_t m = table[((w & 0xFFu) << 2u) | ((w >> 12u) & 3u)];
        if ((((w ^ 0x80808080u) & (m | 0x80u)) | (m & 0x80u)) == 0)
        {
            return static_cast<std::size_t>(((0xE5000000u >> ((w >> 3u) & 0x1Eu)) & 3u) + 1u);
        }
        return 0;
    }
    if (avail < 2)
    {
        return 0;
    }
    const std::uint32_t c0 = data[0];
    const std::uint32_t c1 = data[1];
    if (c0 - 0xC2u <= 0xDFu - 0xC2u)
    {
        return ((c1 & 0xC0u) == 0x80u) ? 2u : 0u;
    }
    if (avail == 3 && (c0 - 0xE0u <= 0xEFu - 0xE0u))
    {
        const std::uint32_t idx = (c0 << 2u) | ((c1 >> 4u) & 3u);
        const std::uint32_t w = c0 | (c1 << 8u) | (static_cast<std::uint32_t>(data[2]) << 16u);
        return (((w ^ 0x80808000u) & table[idx]) == 0) ? 3u : 0u;
    }
    return 0; // invalid, incomplete, or must be diagnosed by the byte path
}

// Advance @a pos through consecutive non-ASCII UTF-8 sequences using paired
// 64-bit little-endian loads and utf8_prefix_table. Returns false as soon as an
// ill-formed sequence is detected (with @a pos pointing to the offending byte),
// or true when an ASCII run is reached or fewer than 8 bytes remain.
JSON_HEDLEY_ALWAYS_INLINE bool valid_utf8_paired_loop(const unsigned char* data, std::size_t n, std::size_t& pos) noexcept
{
    constexpr std::uint64_t high = 0x8080808080808080ull;
    const auto& table = utf8_prefix_table<>::masks;
    while (pos + 8 <= n)
    {
        const std::uint64_t w8 = read_eight_bytes(data + pos);
        const auto w0 = static_cast<std::uint32_t>(w8);
        if ((w0 & 0x80808080u) == 0)
        {
            if ((w8 & high) == 0)
            {
                pos += 8;
                return true;
            }
            pos += static_cast<std::size_t>(count_trailing_zeros(w8 & high)) / 8u;
            continue;
        }
        const std::uint32_t idx0 = ((w0 & 0xFFu) << 2u) | ((w0 >> 12u) & 3u);
        if (((w0 ^ 0x80808000u) & table[idx0]) != 0)
        {
            return false;
        }
        // shift count in bits (0, 8, 16, or 24) for 1..4-byte sequence length
        const auto bit_s0 = static_cast<std::uint32_t>((0x728000000ull >> ((w0 >> 3u) & 0x1Eu)) & 0x18u);
        const auto w1 = static_cast<std::uint32_t>((w8 >> 8u) >> bit_s0);
        const std::size_t len0 = static_cast<std::size_t>(bit_s0 >> 3u) + 1u;
        if ((w1 & 0x80808080u) == 0)
        {
            pos += len0 + 4u;
            return true;
        }
        const std::uint32_t idx1 = ((w1 & 0xFFu) << 2u) | ((w1 >> 12u) & 3u);
        if (((w1 ^ 0x80808000u) & table[idx1]) != 0)
        {
            pos += len0;
            return false;
        }
        pos += len0 + static_cast<std::size_t>(((0xE5000000u >> ((w1 >> 3u) & 0x1Eu)) & 3u) + 1u);
    }
    return true;
}

// Return the length of the longest prefix of [data, data+n) that consists of
// ASCII characters and complete well-formed UTF-8 sequences; n if all of it is
// valid UTF-8. Unlike scalar_string_bulk_run(), quotes, escapes, and control
// characters are ordinary characters here. ASCII runs skip 16/64 bytes at a
// time with SSE2 or 8/32 bytes with SWAR, and non-ASCII runs decode two
// sequences per 64-bit load via utf8_prefix_table.
inline std::size_t valid_utf8_prefix(const unsigned char* data, std::size_t n) noexcept
{
    const auto& table = utf8_prefix_table<>::masks;
    std::size_t pos = 0;

#if JSON_SCAN_SSE2
    while (pos + 16 <= n)
    {
        const __m128i v0 = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(data + pos))); // NOLINT(bugprone-casting-through-void)
        const auto mask = static_cast<unsigned int>(_mm_movemask_epi8(v0));
        if (mask == 0)
        {
            pos += 16;
            while (pos + 64 <= n)
            {
                const __m128i a0 = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(data + pos))); // NOLINT(bugprone-casting-through-void)
                const __m128i a1 = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(data + pos + 16))); // NOLINT(bugprone-casting-through-void)
                const __m128i a2 = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(data + pos + 32))); // NOLINT(bugprone-casting-through-void)
                const __m128i a3 = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(data + pos + 48))); // NOLINT(bugprone-casting-through-void)
                const __m128i or01 = _mm_or_si128(a0, a1);
                const __m128i or23 = _mm_or_si128(a2, a3);
                if (_mm_movemask_epi8(_mm_or_si128(or01, or23)) != 0)
                {
                    break;
                }
                pos += 64;
            }
            continue;
        }

        pos += static_cast<std::size_t>(count_trailing_zeros(static_cast<std::uint64_t>(mask)));
        if (!valid_utf8_paired_loop(data, n, pos))
        {
            return pos;
        }
    }
#else
    constexpr std::uint64_t high = 0x8080808080808080ull;
    while (pos + 8 <= n)
    {
        const std::uint64_t w0_init = read_eight_bytes(data + pos);
        if ((w0_init & high) == 0)
        {
            pos += 8;
            while (pos + 32 <= n)
            {
                const std::uint64_t a0 = read_eight_bytes(data + pos);
                const std::uint64_t a1 = read_eight_bytes(data + pos + 8);
                const std::uint64_t a2 = read_eight_bytes(data + pos + 16);
                const std::uint64_t a3 = read_eight_bytes(data + pos + 24);
                if (((a0 | a1 | a2 | a3) & high) != 0)
                {
                    break;
                }
                pos += 32;
            }
            continue;
        }

        pos += static_cast<std::size_t>(count_trailing_zeros(w0_init & high)) / 8u;
        if (!valid_utf8_paired_loop(data, n, pos))
        {
            return pos;
        }
    }
#endif

    while (pos + 4 <= n)
    {
        const std::uint32_t w = read_four_bytes(data + pos);
        if ((w & 0x80808080u) == 0)
        {
            pos += 4;
            continue;
        }
        const std::uint32_t idx = ((w & 0xFFu) << 2u) | ((w >> 12u) & 3u);
        if (((w ^ 0x80808000u) & table[idx]) != 0)
        {
            return pos;
        }
        pos += static_cast<std::size_t>(((0xE5000000u >> ((w >> 3u) & 0x1Eu)) & 3u) + 1u);
    }

    while (pos < n)
    {
        if (data[pos] < 0x80u)
        {
            ++pos;
            continue;
        }

        const std::size_t seq = validate_one_utf8(data + pos, n - pos);
        if (seq == 0)
        {
            break; // ill-formed or truncated
        }
        pos += seq;
    }
    return pos;
}

/*!
@brief whether [data, data+n) is valid UTF-8, for checking whole strings

The same answer as valid_utf8_prefix(data, n) == n. Short ASCII strings, the
most common keys and values, are decided in one test, and long strings are
checked 16 bytes at a time where the vector check is available.
*/
inline bool valid_utf8_string(const unsigned char* data, std::size_t n) noexcept
{
    constexpr std::uint64_t high = 0x8080808080808080ull;
    if (n <= 16)
    {
        // two overlapping words cover 8 to 16 bytes, one partial word fewer
        std::uint64_t first = 0;
        std::uint64_t last = 0;
        if (n >= 8)
        {
            std::memcpy(&first, data, sizeof(first));
            std::memcpy(&last, data + n - 8, sizeof(last));
        }
        else if (n != 0)
        {
            std::memcpy(&first, data, n);
        }
        if (((first | last) & high) == 0)
        {
            return true;
        }
    }
#if JSON_SCAN_VECTOR_UTF8
    else if (n >= 32
#if JSON_SCAN_SSSE3_DISPATCH
             && cpu_has_ssse3()
#endif
            )
    {
        const unsigned char* block = vector_utf8_valid_blocks(data, data + n);
        // the rest from the start of a sequence that may be cut at block
        for (int i = 1; i <= 3 && block - i >= data; ++i)
        {
            const unsigned char c = block[-i];
            if (c < 0x80)
            {
                break;
            }
            if (c >= 0xC0)
            {
                block -= i;
                break;
            }
        }
        const auto checked = static_cast<std::size_t>(block - data);
        return checked + valid_utf8_prefix(block, n - checked) == n;
    }
#endif
    return valid_utf8_prefix(data, n) == n;
}

#if JSON_SCAN_VECTOR_UTF8
/// the end of scan_string_vector from block, where the vector loop stopped
/// (ill-formed UTF-8, or fewer than 16 bytes left): one byte or sequence at a
/// time, from the start of a sequence that crosses into the block
inline const unsigned char* scan_string_finish(const unsigned char* p, const unsigned char* block, const unsigned char* e) noexcept
{
    for (int i = 1; i <= 3 && block - i >= p; ++i)
    {
        const unsigned char c = block[-i];
        if (c < 0x80)
        {
            break;
        }
        if (c >= 0xC0)
        {
            const int len = 2 + static_cast<int>(c >= 0xE0) + static_cast<int>(c >= 0xF0);
            if (len > i)
            {
                block -= i;
            }
            break;
        }
    }
    for (p = block; p != e;)
    {
        if (*p < 0x80)
        {
            if (is_string_special(*p))
            {
                return p;
            }
            ++p;
            continue;
        }
        const std::size_t n = validate_one_utf8(p, static_cast<std::size_t>(e - p));
        if (n == 0)
        {
            return p;
        }
        p += n;
    }
    return p;
}

/// the rest of a string from p (a character boundary), with the vector UTF-8
/// check and the scalar check for the end of the block where it stopped
inline const unsigned char* scan_string_vector(const unsigned char* p, const unsigned char* e) noexcept
{
    const unsigned char* block = p;
    if (vector_utf8_run(p, e, block))
    {
        return block;
    }
    return scan_string_finish(p, block, e);
}
#endif

#if JSON_SCAN_VECTOR
/// the end of the run of plain string characters at @a p: the first quote,
/// backslash, control character, or non-ASCII byte, or @a e. The first words
/// are checked with SWAR (one; four with NEON, where the vector mask costs
/// more), as most keys and short values end there; longer runs continue 16
/// bytes at a time.
JSON_HEDLEY_ALWAYS_INLINE const unsigned char* plain_run_end(const unsigned char* p, const unsigned char* e) noexcept
{
    constexpr int prefix_words = JSON_SCAN_NEON ? 4 : 1;
    for (int words = prefix_words; words > 0 && e - p >= 8; --words)
    {
        const std::uint64_t special = swar_string_special(read_eight_bytes(p));
        if (special != 0)
        {
            return p + (static_cast<std::size_t>(count_trailing_zeros(special)) / 8);
        }
        p += 8;
    }
    // the vector loop only for 16 bytes or more: the serializer passes a
    // string without its closing quote, so most of its runs end at e, and a
    // call of the out-of-line NEON loop for a shorter rest made dump() up to
    // 10% slower
    if (e - p >= 16)
    {
        p = vector_plain_run_long(p, e);
        if (e - p >= 16)
        {
            return p; // the vector loop stopped at a special byte
        }
    }
    return p + find_string_special(p, static_cast<std::size_t>(e - p));
}
#endif

// Computation of the bulk run length: the number of leading bytes in
// [data, data+n) that are ordinary ASCII or complete well-formed UTF-8
// sequences, stopping before the first byte that needs individual handling (the
// closing quote, an escape, a control character, or an ill-formed/truncated
// sequence). ASCII is skipped 16 bytes at a time with SSE2 and 8 bytes at a
// time otherwise; runs of non-ASCII text use the vector UTF-8 check where
// available.
JSON_HEDLEY_ALWAYS_INLINE std::size_t scalar_string_bulk_run(const unsigned char* data, std::size_t n) noexcept
{
    const unsigned char* const e = data + n;
    const unsigned char* p = data;
    while (p != e)
    {
#if JSON_SCAN_VECTOR
        p = plain_run_end(p, e);
#else
        p += find_string_special(p, static_cast<std::size_t>(e - p));
#endif
        if (p == e || *p < 0x80u)
        {
            break; // end of buffer, or a quote/escape/control byte
        }
#if JSON_SCAN_VECTOR_UTF8
#if JSON_SCAN_SSSE3_DISPATCH
        if (JSON_HEDLEY_LIKELY(cpu_has_ssse3()))
#endif
        {
            return static_cast<std::size_t>(scan_string_vector(p, e) - data);
        }
#endif
#if !JSON_SCAN_VECTOR_UTF8 || JSON_SCAN_SSSE3_DISPATCH
        // a run of multi-byte sequences (e.g. CJK text) is validated sequence
        // by sequence without searching for the next special byte in between
        do
        {
            const std::size_t seq = validate_one_utf8(p, static_cast<std::size_t>(e - p));
            if (seq == 0)
            {
                return static_cast<std::size_t>(p - data); // ill-formed or truncated: let the byte path diagnose it
            }
            p += seq;
        }
        while (p != e && *p >= 0x80u);
#endif
    }
    return static_cast<std::size_t>(p - data);
}

#if defined(JSON_USE_SIMDUTF) && defined(JSON_HAS_CPP_17)
// Index of the first quote/escape/control byte in [data, data+n) (non-ASCII
// bytes are *not* stops here - the whole run is handed to simdutf), or n.
inline std::size_t find_string_delimiter(const unsigned char* data, std::size_t n) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        const std::uint64_t v = read_eight_bytes(data + i);
        const std::uint64_t q = v ^ 0x2222222222222222ull;
        const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull;
        const std::uint64_t hit = ((q - ones) & ~q & high)
                                  | ((b - ones) & ~b & high)
                                  | ((v - 0x2020202020202020ull) & ~v & high);
        if (hit != 0)
        {
            // the lowest flagged byte is the first delimiter (see find_string_special())
            return i + (static_cast<std::size_t>(count_trailing_zeros(hit)) / 8);
        }
    }
    for (; i < n; ++i)
    {
        const unsigned char c = data[i];
        if (c == '\"' || c == '\\' || c < 0x20u)
        {
            return i;
        }
    }
    return n;
}
#endif

// Backend-dispatched bulk run length. With JSON_USE_SIMDUTF the run up to the
// next delimiter is validated in one shot by simdutf; on the rare failure the
// scalar helper recomputes the exact valid prefix so the byte path still
// produces the precise diagnostic. Without it, the pure scalar path is used.
JSON_HEDLEY_ALWAYS_INLINE std::size_t string_bulk_run(const unsigned char* data, std::size_t n) noexcept
{
#if defined(JSON_USE_SIMDUTF) && defined(JSON_HAS_CPP_17)
    const std::size_t run = find_string_delimiter(data, n);
    if (run != 0 && simdutf::validate_utf8(reinterpret_cast<const char*>(data), run))
    {
        return run;
    }
#endif
    return scalar_string_bulk_run(data, n);
}

#if JSON_SCAN_NEON && !(defined(JSON_USE_SIMDUTF) && defined(JSON_HAS_CPP_17))
/// scalar_string_bulk_run() from @a start on, out of line (see
/// lexer_string_bulk_run())
JSON_HEDLEY_NEVER_INLINE inline std::size_t string_bulk_run_from(const unsigned char* data, std::size_t start, std::size_t n) noexcept
{
    return start + scalar_string_bulk_run(data + start, n - start);
}
#endif

// string_bulk_run() for the lexer. The run must be the longest one: the lexer
// would only lose speed with a shorter run, but contiguous_parser rejects a
// string whose run ends at a byte other than a quote or a backslash, so a
// shorter run would reject valid input there. With NEON, only the first four words are
// checked inline (most keys and short values end there), and longer runs and
// non-ASCII text continue out of line. The lexer's scan function runs once per
// token, and the vector code inlined into it needs more registers, which every
// token pays for: 5% of json::accept() on jeopardy.json with Apple Clang on
// Apple M1, even though no string of that file reaches the vector code. The
// serializer keeps string_bulk_run() inline, which is faster there.
JSON_HEDLEY_ALWAYS_INLINE std::size_t lexer_string_bulk_run(const unsigned char* data, std::size_t n) noexcept
{
#if JSON_SCAN_NEON && !(defined(JSON_USE_SIMDUTF) && defined(JSON_HAS_CPP_17))
    std::size_t i = 0;
    for (int words = 4; words > 0 && n - i >= 8; --words)
    {
        const std::uint64_t special = swar_string_special(read_eight_bytes(data + i));
        if (special != 0)
        {
            const std::size_t pos = i + (static_cast<std::size_t>(count_trailing_zeros(special)) / 8);
            return data[pos] < 0x80u ? pos : string_bulk_run_from(data, pos, n);
        }
        i += 8;
    }
    return string_bulk_run_from(data, i, n);
#else
    return string_bulk_run(data, n);
#endif
}

// Decode the 4 hex digits at [data, data+4) - the digits following a `\u`
// escape - into a codepoint 0x0000..0xFFFF via one table lookup per byte
// (after yyjson's read_hex_u16), or return -1 if any of the 4 bytes is not a
// hex digit ('0'..'9', 'A'..'F', 'a'..'f'). The caller must already have
// checked that 4 bytes are available; used by lexer::get_codepoint()'s
// contiguous fast path. On -1 it falls back to the byte-at-a-time loop, which
// stops at the first invalid digit, so the reported error and position are
// unaffected by this fast path.
inline int hex_codepoint(const unsigned char* data) noexcept
{
    static const std::array<std::uint8_t, 256> hex_digit_table = // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    {
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 00..0F
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 10..1F
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 20..2F
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 30..3F ('0'..'9')
            0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 40..4F ('A'..'F')
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 50..5F
            0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 60..6F ('a'..'f')
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 70..7F
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 80..8F
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 90..9F
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // A0..AF
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // B0..BF
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // C0..CF
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // D0..DF
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // E0..EF
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF  // F0..FF
        }
    };

    const std::uint8_t d0 = hex_digit_table[data[0]];
    const std::uint8_t d1 = hex_digit_table[data[1]];
    const std::uint8_t d2 = hex_digit_table[data[2]];
    const std::uint8_t d3 = hex_digit_table[data[3]];
    // every valid digit is <= 0xF; the combined OR only exceeds it if at
    // least one of the four bytes was not a hex digit (looked up as 0xFF)
    if ((d0 | d1 | d2 | d3) > 0x0F)
    {
        return -1;
    }
    return (d0 << 12) | (d1 << 8) | (d2 << 4) | d3;
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
