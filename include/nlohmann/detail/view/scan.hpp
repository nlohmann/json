//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2020 YaoYuan <https://github.com/ibireme/yyjson>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint16_t, uint64_t
#include <cstring> // memcpy

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/simd.hpp>

// Scanning primitives of the view's parser. The unrolled checks at fixed
// offsets follow yyjson (https://github.com/ibireme/yyjson, MIT license): the
// loads do not depend on each other, so the CPU can run ahead. Words are read
// with read_eight_bytes(), so nothing here depends on the byte order.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// 1 for bytes that may appear verbatim in a string: 0x20..0x7F except '"' and '\\'
inline const std::uint8_t* string_plain() noexcept
{
    static const std::array<std::uint8_t, 256> table =
    {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x00..0x1F
            1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x20..0x3F ('"')
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, // 0x40..0x5F ('\\')
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x60..0x7F
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x80..0x9F
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xA0..0xBF
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xC0..0xDF
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xE0..0xFF
        }
    };
    return table.data();
}

NLOHMANN_VIEW_ALWAYS_INLINE bool is_digit(unsigned char c) noexcept
{
    return static_cast<unsigned char>(c - '0') <= 9;
}

/// two bytes as they are in memory (only compared with byte-symmetric patterns)
NLOHMANN_VIEW_ALWAYS_INLINE std::uint16_t load16(const unsigned char* p) noexcept
{
    std::uint16_t w = 0;
    std::memcpy(&w, p, 2);
    return w;
}

/// Advance over plain string bytes and well-formed UTF-8. Stops at a quote,
/// a backslash, a control character, ill-formed UTF-8, or the end. The first
/// bytes are checked one by one, so that the position advances by constants
/// in predicted branches: 16 for keys, whose lengths repeat from record to
/// record, and 8 for string values (Value) where a vector loop follows, as
/// their lengths vary more. Longer runs continue 16 bytes at a time with NEON
/// or SSE2, else eight bytes at a time. With SSE2, the run is checked 16 bytes
/// at a time from its first byte instead: on x86-64, one compare that finds
/// the end of most keys and short values is faster than a branch per byte (on
/// AArch64, where a NEON mask costs more and branches predict well, slower).
template<bool Value = false>
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* scan_string_run(const unsigned char* p, const unsigned char* e) noexcept
{
    const std::uint8_t* plain = string_plain();
    for (;;)
    {
#if NLOHMANN_VIEW_SSE2
        p = vector_plain_run(p, e);
#else
        if (e - p >= 16)
        {
#define NLOHMANN_VIEW_STEP(i) if (NLOHMANN_VIEW_LIKELY(plain[p[i]] != 0)) {} else { p += (i); goto stop; }
            NLOHMANN_VIEW_REPEAT_FIRST_8(NLOHMANN_VIEW_STEP)
#if NLOHMANN_VIEW_VECTOR
            if (!Value) // (a plain `!Value || !NLOHMANN_VIEW_VECTOR` is a constant condition for MSVC, C4127)
#endif
            {
                NLOHMANN_VIEW_REPEAT_SECOND_8(NLOHMANN_VIEW_STEP)
                p += 8;
            }
#undef NLOHMANN_VIEW_STEP
            p += 8;
#if NLOHMANN_VIEW_VECTOR
            p = vector_plain_run(p, e);
            if (p != e && plain[*p] == 0)
            {
                goto stop;
            }
#else
            while (e - p >= 8)
            {
                const std::uint64_t special = swar_string_special(read_eight_bytes(p));
                if (special != 0)
                {
                    p += count_trailing_zeros(special) / 8;
                    goto stop;
                }
                p += 8;
            }
#endif
            continue;
        }
#endif
        while (p != e && plain[*p] != 0)
        {
            ++p;
        }
        if (p == e)
        {
            return p;
        }
#if !NLOHMANN_VIEW_SSE2
stop:
#endif
        if (*p < 0x80)
        {
            return p; // quote, backslash, or control character
        }
#if NLOHMANN_VIEW_VECTOR_UTF8
#if NLOHMANN_VIEW_SSSE3_DISPATCH
        if (NLOHMANN_VIEW_LIKELY(cpu_has_ssse3()))
#endif
        {
            // non-ASCII: the vector check, out of line
            return scan_string_vector(p, e, plain);
        }
#endif
#if !NLOHMANN_VIEW_VECTOR_UTF8 || NLOHMANN_VIEW_SSSE3_DISPATCH
        // non-ASCII: a run of well-formed sequences (the library's check, so
        // that exactly what json::parse accepts is accepted)
        do
        {
            const std::size_t n = validate_one_utf8(p, static_cast<std::size_t>(e - p));
            if (n == 0)
            {
                return p;
            }
            p += n;
        }
        while (p != e && *p >= 0x80);
#endif
    }
}

/// advance over ASCII digits
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* skip_digits(const unsigned char* p, const unsigned char* e) noexcept
{
    while (e - p >= 16)
    {
#define NLOHMANN_VIEW_STEP(i) if (NLOHMANN_VIEW_LIKELY(is_digit(p[i]))) {} else { return p + (i); }
        NLOHMANN_VIEW_REPEAT16(NLOHMANN_VIEW_STEP)
#undef NLOHMANN_VIEW_STEP
        p += 16;
    }
    while (p != e && is_digit(*p))
    {
        ++p;
    }
    return p;
}

/// advance over the text of a line comment (after its "//") to the line
/// break or the end (with NulIsEnd also a null byte, which is left for the
/// caller to see, as in parse())
template<bool NulIsEnd = false>
inline const unsigned char* skip_line_comment(const unsigned char* p, const unsigned char* e) noexcept
{
    while (p != e && *p != '\n' && *p != '\r' && !(NulIsEnd && *p == 0))
    {
        ++p;
    }
    return p;
}

/// the "*/" that ends a block comment whose text starts at p (after its "/*");
/// if it is unterminated, the end (with NulIsEnd also a null byte), which is
/// where the caller reports the error
template<bool NulIsEnd = false>
inline const unsigned char* find_block_comment_end(const unsigned char* p, const unsigned char* e) noexcept
{
    while (p != e && !(NulIsEnd && *p == 0) && !(*p == '*' && p + 1 != e && p[1] == '/'))
    {
        ++p;
    }
    return p;
}

/// The digits of a fraction, whose number varies from one number to the next: skip_digits() with 16 bytes compared at
/// once and the end of the run taken from a bit mask (SSE2), instead of a compare and a branch for each digit. That
/// is about a third of the instructions for a fraction of 12 digits, and no branch that is mispredicted when the
/// lengths vary. Where there is no SSE2, skip_digits() is used.
#if NLOHMANN_VIEW_SSE2
// The last bytes of the input, one at a time. GCC unrolls this loop in every inlined copy of the function below, which
// makes the parse loop 4 KiB larger and slows down documents that have hardly any fractions; out of line, it does
// not. Clang does better with the loop inline (a call in the parse loop costs it more than the unrolling).
#if defined(__GNUC__) && !defined(__clang__)
inline NLOHMANN_VIEW_NOINLINE const unsigned char* skip_digits_tail(const unsigned char* p, const unsigned char* e) noexcept
{
    while (p != e && is_digit(*p))
    {
        ++p;
    }
    return p;
}
#else
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* skip_digits_tail(const unsigned char* p, const unsigned char* e) noexcept
{
    while (p != e && is_digit(*p))
    {
        ++p;
    }
    return p;
}
#endif

NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* skip_fraction_digits(const unsigned char* p, const unsigned char* e) noexcept
{
    while (e - p >= 16)
    {
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p))); // NOLINT(bugprone-casting-through-void)
        // a digit is above '/' and below ':' (signed compares: a byte with the top bit set is negative, and neither)
        const __m128i digits = _mm_and_si128(_mm_cmpgt_epi8(in, _mm_set1_epi8('/')), _mm_cmplt_epi8(in, _mm_set1_epi8(':')));
        const auto not_digit = static_cast<std::uint64_t>(~static_cast<unsigned>(_mm_movemask_epi8(digits)) & 0xFFFFu);
        if (not_digit != 0)
        {
            return p + count_trailing_zeros(not_digit);
        }
        p += 16;
    }
    return skip_digits_tail(p, e);
}
#else
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* skip_fraction_digits(const unsigned char* p, const unsigned char* e) noexcept
{
    return skip_digits(p, e);
}
#endif

/// powers of ten up to 10^19 as integers
inline std::uint64_t int_pow10(unsigned k) noexcept
{
    return ::nlohmann::detail::dtoa_impl::powers_of_ten()[k];
}

/// value of 0 < k < 8 digits at p in one step if [p, p + 8) lies below
/// limit, else one digit at a time (whole blocks of eight digits are read by
/// parse_upto19() directly)
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t parse_upto8(const unsigned char* p, unsigned k, const unsigned char* limit) noexcept
{
    if (NLOHMANN_VIEW_LIKELY(limit - p >= 8))
    {
        // move the k digits to the top and pad the vacated low bytes with '0'
        const unsigned shift = 8 * (8 - k);
        return parse_eight_digits((read_eight_bytes(p) << shift) | (0x3030303030303030u >> (8 * k)));
    }
    std::uint64_t v = 0;
    for (unsigned i = 0; i < k; ++i)
    {
        v = (v * 10) + static_cast<std::uint64_t>(p[i] - '0');
    }
    return v;
}

/// value of k <= 19 digits at p
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t parse_upto19(const unsigned char* p, unsigned k, const unsigned char* limit) noexcept
{
    std::uint64_t w = 0;
    while (k >= 8)
    {
        // (eight digits of the token: they lie below limit)
        w = (w * 100000000u) + parse_eight_digits(read_eight_bytes(p));
        p += 8;
        k -= 8;
    }
    if (k != 0)
    {
        w = (w * int_pow10(k)) + parse_upto8(p, k, limit);
    }
    return w;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
