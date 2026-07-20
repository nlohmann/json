//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint64_t
#include <cstring> // memcpy

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
// itself focused on the state machine; see lexer::scan_string_bulk().

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
    const std::uint64_t has_quote     = (q - ones) & ~q & high;
    const std::uint64_t has_backslash = (b - ones) & ~b & high;
    const std::uint64_t has_control   = (v - 0x2020202020202020ull) & ~v & high; // < 0x20
    const std::uint64_t has_non_ascii = v & high;                                // >= 0x80
    return has_quote | has_backslash | has_control | has_non_ascii;
}

// return the index of the first is_string_special() byte in [data, data+n), or
// n if every byte is ordinary; scans 8 bytes at a time
inline std::size_t find_string_special(const unsigned char* data, std::size_t n) noexcept
{
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        std::uint64_t word = 0;
        std::memcpy(&word, data + i, sizeof(word));
        if (swar_string_special(word) != 0)
        {
            // a special byte is in this word; locate it (endian-agnostic)
            for (std::size_t j = 0; j < 8; ++j)
            {
                if (is_string_special(data[i + j]))
                {
                    return i + j;
                }
            }
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

// classify a byte as one the serializer must NOT copy verbatim when
// ensure_ascii is requested: the closing quote, an escape, a control character
// (< 0x20), DEL (0x7F), or any non-ASCII byte (>= 0x80). Everything else -
// printable ASCII except '"' and '\\' - is emitted unchanged. Note this differs
// from is_string_special() only in that 0x7F is also a stop (it is escaped as
// \u007f under ensure_ascii).
inline bool is_ascii_copyable(unsigned char c) noexcept
{
    return c >= 0x20u && c < 0x7Fu && c != '\"' && c != '\\';
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
        std::uint64_t v = 0;
        std::memcpy(&v, data + i, sizeof(v));
        const std::uint64_t q = v ^ 0x2222222222222222ull; // '"'  (0x22)
        const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull; // '\\' (0x5C)
        const std::uint64_t d = v ^ 0x7F7F7F7F7F7F7F7Full; // DEL  (0x7F)
        const std::uint64_t stop = ((q - ones) & ~q & high)   // == '"'
                                   | ((b - ones) & ~b & high)  // == '\\'
                                   | ((d - ones) & ~d & high)  // == 0x7F
                                   | ((v - 0x2020202020202020ull) & ~v & high) // < 0x20
                                   | (v & high);               // >= 0x80
        if (stop != 0)
        {
            for (std::size_t j = 0; j < 8; ++j)
            {
                if (!is_ascii_copyable(data[i + j]))
                {
                    return i + j;
                }
            }
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

// Validate one UTF-8 sequence at the front of [data, data+avail). Returns its
// length (2..4) only when the bytes form a *well-formed* sequence using exactly
// the same ranges as scan_string()'s per-byte switch, so the bulk path accepts
// precisely what the byte path accepts. Returns 0 for anything that is invalid,
// incomplete, or that the byte path must diagnose (the caller then defers to
// that path, keeping error messages unchanged). Lead bytes < 0x80 are handled
// by the caller and never passed here.
inline std::size_t validate_one_utf8(const unsigned char* data, std::size_t avail) noexcept
{
    const unsigned char c0 = data[0];
    if (c0 >= 0xC2 && c0 <= 0xDF)  // U+0080..U+07FF
    {
        if (avail >= 2 && data[1] >= 0x80 && data[1] <= 0xBF)
        {
            return 2;
        }
    }
    else if (c0 == 0xE0)  // U+0800..U+0FFF
    {
        if (avail >= 3 && data[1] >= 0xA0 && data[1] <= 0xBF && data[2] >= 0x80 && data[2] <= 0xBF)
        {
            return 3;
        }
    }
    else if ((c0 >= 0xE1 && c0 <= 0xEC) || c0 == 0xEE || c0 == 0xEF)  // U+1000..U+CFFF, U+E000..U+FFFF
    {
        if (avail >= 3 && data[1] >= 0x80 && data[1] <= 0xBF && data[2] >= 0x80 && data[2] <= 0xBF)
        {
            return 3;
        }
    }
    else if (c0 == 0xED)  // U+D000..U+D7FF (excludes surrogates)
    {
        if (avail >= 3 && data[1] >= 0x80 && data[1] <= 0x9F && data[2] >= 0x80 && data[2] <= 0xBF)
        {
            return 3;
        }
    }
    else if (c0 == 0xF0)  // U+10000..U+3FFFF
    {
        if (avail >= 4 && data[1] >= 0x90 && data[1] <= 0xBF && data[2] >= 0x80 && data[2] <= 0xBF && data[3] >= 0x80 && data[3] <= 0xBF)
        {
            return 4;
        }
    }
    else if (c0 >= 0xF1 && c0 <= 0xF3)  // U+40000..U+FFFFF
    {
        if (avail >= 4 && data[1] >= 0x80 && data[1] <= 0xBF && data[2] >= 0x80 && data[2] <= 0xBF && data[3] >= 0x80 && data[3] <= 0xBF)
        {
            return 4;
        }
    }
    else if (c0 == 0xF4)  // U+100000..U+10FFFF
    {
        if (avail >= 4 && data[1] >= 0x80 && data[1] <= 0x8F && data[2] >= 0x80 && data[2] <= 0xBF && data[3] >= 0x80 && data[3] <= 0xBF)
        {
            return 4;
        }
    }
    return 0; // invalid, incomplete, or must be diagnosed by the byte path
}

// Scalar (C++11) computation of the bulk run length: the number of leading
// bytes in [data, data+n) that are ordinary ASCII or complete well-formed UTF-8
// sequences, stopping before the first byte that needs individual handling (the
// closing quote, an escape, a control character, or an ill-formed/truncated
// sequence). ASCII is skipped 8 bytes at a time.
inline std::size_t scalar_string_bulk_run(const unsigned char* data, std::size_t n) noexcept
{
    std::size_t pos = 0;
    while (pos < n)
    {
        pos += find_string_special(data + pos, n - pos);
        if (pos >= n || data[pos] < 0x80u)
        {
            break; // end of buffer, or a quote/escape/control byte
        }
        const std::size_t seq = validate_one_utf8(data + pos, n - pos);
        if (seq == 0)
        {
            break; // ill-formed or truncated: let the byte path diagnose it
        }
        pos += seq;
    }
    return pos;
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
        std::uint64_t v = 0;
        std::memcpy(&v, data + i, sizeof(v));
        const std::uint64_t q = v ^ 0x2222222222222222ull;
        const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull;
        const std::uint64_t hit = ((q - ones) & ~q & high)
                                  | ((b - ones) & ~b & high)
                                  | ((v - 0x2020202020202020ull) & ~v & high);
        if (hit != 0)
        {
            for (std::size_t j = 0; j < 8; ++j)
            {
                const unsigned char c = data[i + j];
                if (c == '\"' || c == '\\' || c < 0x20u)
                {
                    return i + j;
                }
            }
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
inline std::size_t string_bulk_run(const unsigned char* data, std::size_t n) noexcept
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

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
