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
#include <cstdint> // int64_t, uint64_t
#include <limits> // numeric_limits

#include <nlohmann/detail/macro_scope.hpp>

// This file contains the value-conversion helpers used by the lexer to turn an
// already-validated number token into a value, without the locale/errno
// overhead of std::strtoull/std::strtod. They are free functions so the lexer
// stays focused on scanning; see lexer::convert_number().

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
        x = x * 10u + digit;
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
        magnitude = magnitude * 10u + digit;
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

@param[in]  first          pointer to the first character of the number
@param[in]  last           pointer past the last character
@param[in]  decimal_point  the (locale-dependent) decimal point character
@param[out] out            the parsed value on success
@return true if the value was parsed exactly; false to fall back to strtod
*/
template<typename DecimalPointType>
bool parse_float_fast(const char* first, const char* last, DecimalPointType decimal_point, double& out) noexcept
{
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
            significand = significand * 10u + static_cast<std::uint64_t>(c - '0');
            ++num_digits;
            fractional_digits += static_cast<int>(seen_dot);
        }
        else if (static_cast<DecimalPointType>(c) == decimal_point)
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
            exponent = exponent * 10 + (*p - '0');
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
}

/// fast float path is only exact for `double`; decline for float/long double
template<typename DecimalPointType, typename FloatType>
bool parse_float_fast(const char* /*first*/, const char* /*last*/, DecimalPointType /*decimal_point*/, FloatType& /*out*/) noexcept
{
    return false;
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
