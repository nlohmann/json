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
/// 16 bytes are checked one by one, so that the position advances by
/// constants in predicted branches (most strings are short); longer runs
/// continue eight bytes at a time.
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* scan_string_run(const unsigned char* p, const unsigned char* e) noexcept
{
    const std::uint8_t* plain = string_plain();
    for (;;)
    {
        if (e - p >= 16)
        {
#define NLOHMANN_VIEW_STEP(i) if (NLOHMANN_VIEW_LIKELY(plain[p[i]] != 0)) {} else { p += (i); goto stop; }
            NLOHMANN_VIEW_REPEAT16(NLOHMANN_VIEW_STEP)
#undef NLOHMANN_VIEW_STEP
            p += 16;
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
            continue;
        }
        while (p != e && plain[*p] != 0)
        {
            ++p;
        }
        if (p == e)
        {
            return p;
        }
stop:
        if (*p < 0x80)
        {
            return p; // quote, backslash, or control character
        }
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

/// powers of ten up to 10^19 as integers
inline std::uint64_t int_pow10(unsigned k) noexcept
{
    static const std::array<std::uint64_t, 20> table =
    {
        {
            1u, 10u, 100u, 1000u, 10000u, 100000u, 1000000u, 10000000u, 100000000u, 1000000000u,
            10000000000u, 100000000000u, 1000000000000u, 10000000000000u, 100000000000000u, 1000000000000000u,
            10000000000000000u, 100000000000000000u, 1000000000000000000u, 10000000000000000000u
        }
    };
    return table[k];
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
