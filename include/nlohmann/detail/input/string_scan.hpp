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
#include <cstdint> // uint64_t, uint8_t
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
    const std::uint64_t has_quote     = (q - ones) & ~q & high;
    const std::uint64_t has_backslash = (b - ones) & ~b & high;
    const std::uint64_t has_control   = (v - 0x2020202020202020ull) & ~v & high; // < 0x20
    const std::uint64_t has_non_ascii = v & high;                                // >= 0x80
    return has_quote | has_backslash | has_control | has_non_ascii;
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
        const std::uint64_t stop = ((q - ones) & ~q & high)   // == '"'
                                   | ((b - ones) & ~b & high)  // == '\\'
                                   | ((d - ones) & ~d & high)  // == 0x7F
                                   | ((v - 0x2020202020202020ull) & ~v & high) // < 0x20
                                   | (v & high);               // >= 0x80
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

// Return the length of the longest prefix of [data, data+n) that consists of
// ASCII characters and complete well-formed UTF-8 sequences; n if all of it is
// valid UTF-8. Unlike scalar_string_bulk_run(), quotes, escapes, and control
// characters are ordinary characters here. ASCII is skipped 8 bytes at a time.
inline std::size_t valid_utf8_prefix(const unsigned char* data, std::size_t n) noexcept
{
    constexpr std::uint64_t high = 0x8080808080808080ull;
    std::size_t pos = 0;
    while (pos < n)
    {
        if (pos + 8 <= n)
        {
            std::uint64_t word = 0;
            std::memcpy(&word, data + pos, sizeof(word));
            if ((word & high) == 0)
            {
                pos += 8;
                continue;
            }
        }

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

// string_bulk_run() for the lexer. With NEON, only the first four words are
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
