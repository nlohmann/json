//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2021 The fast_float authors <https://github.com/fastfloat/fast_float>
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cfloat> // FLT_EVAL_METHOD
#include <clocale> // localeconv
#include <cstddef> // size_t
#include <cstdint> // int64_t, uint64_t
#include <cstdlib> // strtof, strtod, strtold
#include <cstring> // memcpy
#include <limits> // numeric_limits
#include <string> // string

#include <nlohmann/detail/bit_ops.hpp>
#include <nlohmann/detail/input/pow5_table.hpp>
#include <nlohmann/detail/macro_scope.hpp>

// std::from_chars lives in <charconv>, but being in C++17 mode does not
// guarantee the header exists: GCC 7 sets __cplusplus to C++17 yet ships no
// <charconv> (added in GCC 8; floating-point support in GCC 11). Guard the
// include with __has_include so such toolchains fall back to the scalar path.
#if defined(JSON_HAS_CPP_17) && defined(__has_include)
    #if __has_include(<charconv>)
        #include <charconv> // from_chars (only used when __cpp_lib_to_chars is defined)
        #include <system_error> // errc
    #endif
#endif

// This file contains the value-conversion helpers used by the lexer to turn an
// already-validated number token into a value, without the locale/errno
// overhead of std::strtoull/std::strtod where possible. They are free functions
// so the lexer stays focused on scanning (see lexer::convert_number()) and so
// that other parsers of JSON text can convert tokens exactly like it does.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief fast integer parser for an already-validated unsigned integer

The number scanner has already checked that [first, last) is a valid JSON
integer, so this only needs to accumulate the digits and detect overflow. This
avoids the locale/errno machinery of std::strtoull, which dominates
integer-heavy inputs.

@param[in]  first   pointer to the first character (a digit)
@param[in]  last    pointer past the last character
@param[out] value   the parsed value on success
@return true if the value fit into @a NumberUnsignedType; false on overflow, in
        which case the caller falls back to floating-point parsing (matching the
        previous std::strtoull behavior)
*/
template<typename NumberUnsignedType>
bool parse_integer_unsigned(const char* first, const char* last, NumberUnsignedType& value) noexcept
{
    // accumulate in the widest unsigned type used by the previous strtoull
    // path so the overflow behavior is unchanged for custom number types
    std::uint64_t x = 0;
    constexpr std::uint64_t cutoff = (std::numeric_limits<std::uint64_t>::max)() / 10u;
    constexpr std::uint64_t cutlim = (std::numeric_limits<std::uint64_t>::max)() % 10u;
    for (const char* p = first; p != last; ++p)
    {
        const auto digit = static_cast<std::uint64_t>(static_cast<unsigned char>(*p) - static_cast<unsigned char>('0'));
        if (JSON_HEDLEY_UNLIKELY(x > cutoff || (x == cutoff && digit > cutlim)))
        {
            return false;
        }
        x = (x * 10u) + digit;
    }
    value = static_cast<NumberUnsignedType>(x);
    // reject values that do not round-trip into a narrower NumberUnsignedType
    return static_cast<std::uint64_t>(value) == x;
}

/*!
@brief fast integer parser for an already-validated negative integer

@param[in]  first   pointer to the leading '-'
@param[in]  last    pointer past the last character
@param[out] value   the parsed (negative) value on success
@return true on success; false on overflow (caller falls back to float)
*/
template<typename NumberIntegerType>
bool parse_integer_signed(const char* first, const char* last, NumberIntegerType& value) noexcept
{
    // the state machine only reaches the signed path via a leading '-'
    JSON_ASSERT(first != last && *first == '-');
    std::uint64_t magnitude = 0;
    // |INT64_MIN| == INT64_MAX + 1; this is the largest admissible magnitude
    constexpr std::uint64_t limit = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1u;
    for (const char* p = first + 1; p != last; ++p)
    {
        const auto digit = static_cast<std::uint64_t>(static_cast<unsigned char>(*p) - static_cast<unsigned char>('0'));
        if (JSON_HEDLEY_UNLIKELY(magnitude > (limit - digit) / 10u))
        {
            return false;
        }
        magnitude = (magnitude * 10u) + digit;
    }
    const std::int64_t x = (magnitude == limit)
                           ? (std::numeric_limits<std::int64_t>::min)()
                           : -static_cast<std::int64_t>(magnitude);
    value = static_cast<NumberIntegerType>(x);
    // reject values that do not round-trip into a narrower NumberIntegerType
    return static_cast<std::int64_t>(value) == x;
}

/*!
@brief exact fast path for parsing a `double` (Clinger's algorithm)

For the common case - at most 19 significant digits, a decimal exponent in
[-22, 22], and a significand below 2^53 - the value equals significand *
10^exp computed in IEEE-754 double arithmetic, which is exact under
round-to-nearest because both operands are exactly representable. This is the
same fast path used by fast_float/simdjson; the general cases are left to
std::strtod. The parser only activates for number_float_t == double; float and
long double keep the std::strtof/std::strtold paths (see the templated overload
below).

@param[in]  first  pointer to the first character of the number
@param[in]  last   pointer past the last character
@param[out] out    the parsed value on success
@return true if the value was parsed exactly; false to fall back to strtod
*/
inline bool parse_float_fast(const char* first, const char* last, double& out) noexcept
{
#if defined(FLT_EVAL_METHOD) && FLT_EVAL_METHOD != 0
    // Clinger's fast path is only exact when double operations are evaluated in
    // true double precision. On platforms that keep intermediates in extended
    // precision (e.g. the x87 FPU on 32-bit x86, where FLT_EVAL_METHOD == 2) the
    // single significand * 10^scale step is double-rounded and can be 1 ULP off,
    // so decline and let the caller fall back to the correctly-rounded
    // std::from_chars / std::strtod path.
    static_cast<void>(first);
    static_cast<void>(last);
    static_cast<void>(out);
    return false;
#else
    static const std::array<double, 23> powers_of_ten =
    {
        {
            1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11,
            1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22
        }
    };

    const char* p = first;
    bool negative = false;
    if (p != last && (*p == '-' || *p == '+'))
    {
        negative = (*p == '-');
        ++p;
    }

    std::uint64_t significand = 0;
    int num_digits = 0;
    int fractional_digits = 0;
    bool seen_dot = false;
    bool any_digit = false;
    for (; p != last; ++p)
    {
        const char c = *p;
        if (c >= '0' && c <= '9')
        {
            any_digit = true;
            if (JSON_HEDLEY_UNLIKELY(num_digits >= 19))
            {
                return false; // significand may not fit into uint64_t
            }
            significand = (significand * 10u) + static_cast<std::uint64_t>(c - '0');
            ++num_digits;
            fractional_digits += static_cast<int>(seen_dot);
        }
        else if (c == '.')
        {
            if (JSON_HEDLEY_UNLIKELY(seen_dot))
            {
                return false;
            }
            seen_dot = true;
        }
        else if (c == 'e' || c == 'E')
        {
            ++p;
            break;
        }
        else
        {
            return false;
        }
    }
    if (JSON_HEDLEY_UNLIKELY(!any_digit))
    {
        return false;
    }

    int exponent = 0;
    if (p != last) // an exponent part remains
    {
        bool exp_negative = false;
        if (p != last && (*p == '-' || *p == '+'))
        {
            exp_negative = (*p == '-');
            ++p;
        }
        bool any_exp_digit = false;
        for (; p != last; ++p)
        {
            if (JSON_HEDLEY_UNLIKELY(*p < '0' || *p > '9'))
            {
                return false;
            }
            exponent = (exponent * 10) + (*p - '0');
            any_exp_digit = true;
            if (JSON_HEDLEY_UNLIKELY(exponent > 9999))
            {
                return false;
            }
        }
        if (JSON_HEDLEY_UNLIKELY(!any_exp_digit))
        {
            return false;
        }
        if (exp_negative)
        {
            exponent = -exponent;
        }
    }

    const int scale = exponent - fractional_digits;
    if (JSON_HEDLEY_UNLIKELY(significand >= (static_cast<std::uint64_t>(1) << 53)))
    {
        return false; // significand not exactly representable as double
    }

    auto result = static_cast<double>(significand);
    if (scale >= 0)
    {
        if (JSON_HEDLEY_UNLIKELY(scale > 22))
        {
            return false;
        }
        result *= powers_of_ten[static_cast<std::size_t>(scale)];
    }
    else
    {
        if (JSON_HEDLEY_UNLIKELY(-scale > 22))
        {
            return false;
        }
        result /= powers_of_ten[static_cast<std::size_t>(-scale)];
    }
    out = negative ? -result : result;
    return true;
#endif
}

/// fast float path is only exact for `double`; decline for float/long double
template<typename FloatType>
bool parse_float_fast(const char* /*first*/, const char* /*last*/, FloatType& /*out*/) noexcept
{
    return false;
}

/*!
@brief parse a float with std::from_chars (Eisel-Lemire) when available

std::from_chars is locale-independent, correctly rounded, and - via the
Eisel-Lemire algorithm in modern standard libraries - much faster than strtod
over the whole value range (not just the Clinger subset). It is used only when
__cpp_lib_to_chars indicates full floating-point support and only when it
consumes the entire token ([first, last)). An under-/overflow (result_out_of_range) also declines, so
the caller's strtod fallback supplies the well-defined ±inf/0 result the parser
expects (side-stepping the P4168 divergence between implementations).

@return true if the value was parsed exactly and fully; false to fall back
*/
template<typename FloatType>
bool parse_float_from_chars(const char* first, const char* last, FloatType& out) noexcept
{
    // JSON_HAS_CPP_17 must gate the use as well as the <charconv> include above:
    // some standard libraries (e.g. libstdc++ 15) define __cpp_lib_to_chars even
    // in C++14 mode, where <charconv> is not included.
#if defined(JSON_HAS_CPP_17) && defined(__cpp_lib_to_chars)
    const auto result = std::from_chars(first, last, out);
    return result.ec == std::errc() && result.ptr == last;
#else
    static_cast<void>(first);
    static_cast<void>(last);
    static_cast<void>(out);
    return false;
#endif
}

/// whether the eight bytes of @a v (see read_eight_bytes()) are ASCII digits
/// (after fast_float's is_made_of_eight_digits_fast)
inline bool is_eight_digits(std::uint64_t v) noexcept
{
    return ((v & 0xF0F0F0F0F0F0F0F0u) | (((v + 0x0606060606060606u) & 0xF0F0F0F0F0F0F0F0u) >> 4u)) == 0x3333333333333333u;
}

/// the value of the eight ASCII digits in @a v (see read_eight_bytes()), three
/// multiplications instead of eight (after simdjson and fast_float)
inline std::uint32_t parse_eight_digits(std::uint64_t v) noexcept
{
    v = ((v & 0x0F0F0F0F0F0F0F0Fu) * 2561u) >> 8u;
    v = ((v & 0x00FF00FF00FF00FFu) * 6553601u) >> 16u;
    return static_cast<std::uint32_t>(((v & 0x0000FFFF0000FFFFu) * 42949672960001u) >> 32u);
}

/*!
@brief the double nearest to w * 10^q (Eisel-Lemire)

The algorithm of Daniel Lemire, "Number Parsing at a Gigabyte per Second"
(Software: Practice and Experience, 2021), after fast_float's compute_float
(used under the MIT license). With a 128-bit approximation of 5^q, the product
is always sufficient to round correctly for w with at most 19 digits (Noble
Mushtak and Daniel Lemire, "Fast number parsing without fallback", Software:
Practice and Experience, 2023). Only integer arithmetic is used, so the result
does not depend on the floating-point environment.

@param[in] q  decimal exponent
@param[in] w  significand, w != 0
@return the IEEE-754 bits of the positive result (0 for underflow, infinity
        for overflow)
*/
inline std::uint64_t eisel_lemire(std::int64_t q, std::uint64_t w) noexcept
{
    constexpr int mantissa_bits = 52;
    constexpr std::uint64_t infinity = std::uint64_t{0x7FF} << mantissa_bits;
    if (q < pow5_128_smallest_power)
    {
        return 0;
    }
    if (q > pow5_128_largest_power)
    {
        return infinity;
    }

    const int lz = count_leading_zeros(w);
    w <<= static_cast<unsigned>(lz);
    const auto index = static_cast<std::size_t>(2 * (q - pow5_128_smallest_power));
    uint128_parts product = full_multiplication(w, pow5_128()[index]);
    constexpr std::uint64_t precision_mask = 0xFFFFFFFFFFFFFFFFu >> (mantissa_bits + 3);
    if ((product.high & precision_mask) == precision_mask)
    {
        // the lower bits may carry into the result: use the next 64 bits of 5^q
        const uint128_parts second = full_multiplication(w, pow5_128()[index + 1]);
        product.low += second.high;
        if (second.high > product.low)
        {
            ++product.high;
        }
    }

    const auto upperbit = static_cast<int>(product.high >> 63u);
    const int shift = upperbit + 64 - mantissa_bits - 3;
    std::uint64_t mantissa = product.high >> static_cast<unsigned>(shift);
    // floor(log2(10^q)) + 63 + 1023, with log2(10) ~ 217706 / 2^16
    std::int64_t power2 = (((152170 + 65536) * q) >> 16) + 63 + upperbit - lz + 1023;

    if (power2 <= 0) // subnormal
    {
        if (-power2 + 1 >= 64)
        {
            return 0;
        }
        mantissa >>= static_cast<unsigned>(-power2 + 1);
        mantissa += (mantissa & 1u);
        mantissa >>= 1u;
        // rounding up may produce the smallest normal number
        power2 = (mantissa < (std::uint64_t{1} << mantissa_bits)) ? 0 : 1;
        return mantissa | (static_cast<std::uint64_t>(power2) << mantissa_bits);
    }

    // a value exactly between two doubles rounds to even; this can only
    // happen for small |q|, where 5^q is exact
    if (product.low <= 1 && q >= -4 && q <= 23 && (mantissa & 3u) == 1
            && (mantissa << static_cast<unsigned>(shift)) == product.high)
    {
        mantissa &= ~std::uint64_t{1};
    }
    mantissa += (mantissa & 1u);
    mantissa >>= 1u;
    if (mantissa >= (std::uint64_t{2} << mantissa_bits))
    {
        mantissa = std::uint64_t{1} << mantissa_bits;
        ++power2;
    }
    mantissa &= ~(std::uint64_t{1} << mantissa_bits);
    if (power2 >= 0x7FF)
    {
        return infinity;
    }
    return mantissa | (static_cast<std::uint64_t>(power2) << mantissa_bits);
}

/*!
@brief parse a validated float token with the Eisel-Lemire algorithm

The significand is accumulated eight digits at a time where possible. A token
with more than 19 significant digits is truncated to w; the value then lies
in [w, w + 1) * 10^q, and it is only returned if both ends round to the same
double, which covers all but a few such tokens.

@param[in]  first  pointer to the first character of the token
@param[in]  last   pointer past the last character
@param[out] out    the correctly rounded value on success (±infinity if it
                   overflows, like strtod)
@return true on success; false if strtod must decide
*/
inline bool parse_float_eisel_lemire(const char* first, const char* last, double& out) noexcept
{
    const char* p = first;
    const bool negative = (p != last && *p == '-');
    if (negative)
    {
        ++p;
    }

    std::uint64_t w = 0;
    unsigned int digits = 0; // significant digits in w
    std::int64_t exponent = 0;
    bool truncated = false;
    bool in_fraction = false;
    for (;;)
    {
        // eight digits at a time, as long as they fit into w
        while (w != 0 && digits <= 19u - 8u && last - p >= 8)
        {
            const std::uint64_t v = read_eight_bytes(p);
            if (!is_eight_digits(v))
            {
                break;
            }
            w = (w * 100000000u) + parse_eight_digits(v);
            digits += 8u;
            exponent -= in_fraction ? 8 : 0;
            p += 8;
        }
        if (p == last)
        {
            break;
        }
        const char c = *p;
        if (c >= '0' && c <= '9')
        {
            if (w == 0 && c == '0')
            {
                // leading zeros are not significant, but scale a fraction
                exponent -= in_fraction ? 1 : 0;
            }
            else if (digits < 19u)
            {
                w = (w * 10u) + static_cast<std::uint64_t>(c - '0');
                ++digits;
                exponent -= in_fraction ? 1 : 0;
            }
            else
            {
                // dropped: the value lies between w and w + 1 (in units of
                // the last kept digit) unless all dropped digits are zero
                truncated = truncated || c != '0';
                exponent += in_fraction ? 0 : 1;
            }
            ++p;
        }
        else if (c == '.')
        {
            in_fraction = true;
            ++p;
        }
        else
        {
            break; // 'e' or 'E'
        }
    }

    if (p != last)
    {
        ++p; // 'e' or 'E'
        bool exp_negative = false;
        if (p != last && (*p == '-' || *p == '+'))
        {
            exp_negative = (*p == '-');
            ++p;
        }
        std::int64_t exp_value = 0;
        for (; p != last; ++p)
        {
            // saturate: any exponent beyond this under- or overflows anyway
            if (exp_value < 100000)
            {
                exp_value = (exp_value * 10) + (*p - '0');
            }
        }
        exponent += exp_negative ? -exp_value : exp_value;
    }

    std::uint64_t bits = 0;
    if (w != 0)
    {
        bits = eisel_lemire(exponent, w);
        if (truncated && (w + 1 == 0 || eisel_lemire(exponent, w + 1) != bits))
        {
            return false;
        }
    }
    bits |= negative ? (std::uint64_t{1} << 63u) : 0u;
    static_assert(sizeof(double) == sizeof(std::uint64_t), "double must have 64 bits");
    std::memcpy(&out, &bits, sizeof(out));
    return true;
}

/// Eisel-Lemire is only implemented for `double`
template<typename FloatType>
bool parse_float_eisel_lemire(const char* /*first*/, const char* /*last*/, FloatType& /*out*/) noexcept
{
    return false;
}

/*!
@brief check whether Clinger's fast path can still succeed for a float token

parse_float_fast() needs a significand below 2^53. A mantissa with 17 or
more significant digits is at least 10^16 and therefore always exceeds it,
so calling the fast path would walk the token one extra time only to
decline before strtod has to run anyway.

Significant digits are the mantissa's digits from the first nonzero one on;
the sign, the decimal point, leading zeros, and the exponent do not count.
The answer is derived from indices - the digits are not scanned again - so
this stays off the hot path of the number scanners.

@param[in] token                   the validated number token ('.' as decimal point)
@param[in] decimal_point_position  index of the '.' in @a token, or
                                   std::string::npos if there is none
@param[in] mantissa_end            offset just past the last mantissa byte
@return false if parse_float_fast() is guaranteed to decline
*/
inline bool mantissa_fits_clinger(const char* token, std::size_t decimal_point_position, std::size_t mantissa_end) noexcept
{
    // 10^16 already exceeds 2^53, so 17 digits can never fit
    constexpr std::size_t limit = 17;

    const std::size_t neg = (token[0] == '-') ? 1u : 0u;
    const std::size_t has_dot = (decimal_point_position != std::string::npos) ? 1u : 0u;
    // the JSON grammar restricts the integer part to "0" or [1-9][0-9]*, so
    // a leading zero can only be a lone "0", which is not significant
    const std::size_t lead_zero = (token[neg] == '0') ? 1u : 0u;
    JSON_ASSERT(mantissa_end >= neg + has_dot + lead_zero);
    std::size_t digits = mantissa_end - neg - has_dot - lead_zero;

    if (JSON_HEDLEY_LIKELY(digits < limit))
    {
        return true;
    }

    // Only a number below 1 can carry further insignificant zeros, and only
    // while the count stays at the limit does removing them change the
    // answer - so this loop is skipped for all but a few tokens. The
    // fraction is located through decimal_point_position rather than by
    // searching '.'.
    if (lead_zero != 0)
    {
        JSON_ASSERT(has_dot != 0); // an integer "0" cannot reach the limit
        for (std::size_t i = decimal_point_position + 1;
                digits >= limit && i < mantissa_end && token[i] == '0'; ++i)
        {
            --digits;
        }
    }

    return digits < limit;
}

/*!
@brief convert a validated float token without the C library, if possible

Tries std::from_chars (when available), Clinger's exact fast path (double
only, skipped when it cannot succeed), and the Eisel-Lemire algorithm (double
only).

@param[in]  first                   pointer to the first character of the token
@param[in]  last                    pointer past the last character
@param[in]  decimal_point_position  index of the '.' in the token, or
                                    std::string::npos if there is none
@param[in]  mantissa_end            offset just past the last mantissa byte (the
                                    index of 'e'/'E', or the token length)
@param[out] value                   the converted value on success
@return true if the value was converted; false if convert_float_locale_aware()
        must convert it
*/
template<typename FloatType>
bool convert_float_fast(const char* first, const char* last, std::size_t decimal_point_position,
                        std::size_t mantissa_end, FloatType& value) noexcept
{
    if (parse_float_from_chars(first, last, value))
    {
        return true;
    }
    // Skipping a fast path that cannot succeed is lossless and saves a full
    // extra pass over the token's bytes, which otherwise shows up on
    // high-precision inputs such as canada.json
    if (mantissa_fits_clinger(first, decimal_point_position, mantissa_end)
            && parse_float_fast(first, last, value))
    {
        return true;
    }
    return parse_float_eisel_lemire(first, last, value);
}

/// std::strtof, std::strtod, or std::strtold, chosen by the type of @a f
JSON_HEDLEY_NON_NULL(2)
inline void strtof_by_type(float& f, const char* str, char** endptr) noexcept
{
    f = std::strtof(str, endptr);
}

/// std::strtof, std::strtod, or std::strtold, chosen by the type of @a f
JSON_HEDLEY_NON_NULL(2)
inline void strtof_by_type(double& f, const char* str, char** endptr) noexcept
{
    f = std::strtod(str, endptr);
}

/// std::strtof, std::strtod, or std::strtold, chosen by the type of @a f
JSON_HEDLEY_NON_NULL(2)
inline void strtof_by_type(long double& f, const char* str, char** endptr) noexcept
{
    f = std::strtold(str, endptr);
}

/// return the decimal point of the current locale
inline char get_decimal_point() noexcept
{
    const auto* loc = localeconv();
    JSON_ASSERT(loc != nullptr);
    return (loc->decimal_point == nullptr) ? '.' : *(loc->decimal_point);
}

/*!
@brief convert a validated float token with strtof/strtod/strtold

These functions expect the decimal point of the *current* locale, so it is
looked up right before the conversion instead of once when the lexer is
constructed: a locale change in between (by a parser callback, a SAX
handler, or another thread) must not truncate the value (#5198). The
token has been validated before, so if the conversion stops early and the
decimal point changed in the meantime, the locale changed between the
lookup and the call, and the conversion is repeated with the new decimal
point. If the decimal point did not change, a retry cannot succeed: the
locale's decimal point is not a single character (e.g., the two-byte
U+066B of ar_EG.UTF-8 or fa_IR.UTF-8) and cannot be substituted in place.
The value strtod parsed up to that point is kept, as before this change.

Note that changing the locale in another thread *while* strtod runs is
undefined behavior of the C library, which this function cannot prevent.

@param[in,out] token                   the token with '.' as decimal point; its
                                       decimal point is replaced during the
                                       conversion and restored afterwards
                                       (data() must be NUL-terminated)
@param[in]     decimal_point_position  index of the '.' in @a token, or
                                       std::string::npos if there is none
@param[out]    value                   the converted value
*/
template<typename StringType, typename FloatType>
void convert_float_locale_aware(StringType& token, std::size_t decimal_point_position, FloatType& value)
{
    const bool has_dot = decimal_point_position != std::string::npos;
    char decimal_point = get_decimal_point();
    for (;;)
    {
        const bool substitute = has_dot && decimal_point != '.';
        if (substitute)
        {
            token[decimal_point_position] = static_cast<typename StringType::value_type>(decimal_point);
        }

        char* endptr = nullptr; // NOLINT(misc-const-correctness,cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        strtof_by_type(value, token.data(), &endptr);

        if (substitute)
        {
            // the caller hands the token on (e.g. to the SAX interface) with '.'
            token[decimal_point_position] = '.';
        }

        if (JSON_HEDLEY_LIKELY(endptr == token.data() + token.size()))
        {
            return;
        }

        // retry only if the locale changed; otherwise, this would loop forever
        const char current_decimal_point = get_decimal_point();
        if (current_decimal_point == decimal_point)
        {
            return;
        }
        decimal_point = current_decimal_point;
    }
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
