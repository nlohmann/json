//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <cstdint> // int64_t, uint64_t
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // integral_constant

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/scan.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/*!
@brief the value of the float token of a node, as parse() converts it

Uses the lexer's conversion (detail::convert_float), so that the values are
bit-identical to parse(): float and double are converted without allocation
and independent of the locale. The digit layout recorded while parsing locates
the decimal point and the exponent without scanning the token.
*/
template<typename FloatType>
NLOHMANN_VIEW_NOINLINE FloatType float_value(const char* first, const node& n)
{
    const char* const last = first + n.len;
    const std::size_t neg = first[0] == '-' ? 1 : 0;
    const std::size_t int_digits = n.extra & 0xFFu;
    const std::size_t frac_digits = n.extra >> 8u;
    std::size_t dot = std::string::npos;
    std::size_t mantissa_end = n.len;
    if (int_digits != 255 && frac_digits != 255)
    {
        dot = frac_digits != 0 ? neg + int_digits : std::string::npos;
        mantissa_end = neg + int_digits + (frac_digits != 0 ? 1 + frac_digits : 0);
    }
    else
    {
        // more digits than the layout records: locate them
        for (std::size_t i = 0; i < n.len; ++i)
        {
            if (first[i] == '.')
            {
                dot = i;
            }
            else if (first[i] == 'e' || first[i] == 'E')
            {
                mantissa_end = i;
                break;
            }
        }
    }
    return convert_float<FloatType>(first, last, dot, mantissa_end);
}

/*!
@brief the digits of a float token with at most 19 digits, from its layout

The digit layout recorded while parsing says where the integer digits, the
fraction digits, and the exponent are, so the digits are read eight at a
time without scanning.

@param[in] p  first character of the token
@param[in] e  end of the token
@param[in] limit  end of the readable memory (the source text)
*/
NLOHMANN_VIEW_ALWAYS_INLINE float_significand layout_decimal(const unsigned char* p, const unsigned char* e, unsigned int_digits, unsigned frac_digits, const unsigned char* limit) noexcept
{
    const bool negative = *p == '-';
    p += negative ? 1 : 0;
    std::uint64_t w = parse_upto19(p, int_digits, limit);
    p += int_digits;
    std::int64_t q = 0;
    if (frac_digits != 0)
    {
        w = (w * int_pow10(frac_digits)) + parse_upto19(p + 1, frac_digits, limit);
        p += 1 + frac_digits;
        q = -static_cast<std::int64_t>(frac_digits);
    }
    if (p != e)
    {
        // [eE][+-]digits; huge exponents saturate (the parser rejected overflow)
        ++p;
        const bool exp_negative = *p == '-';
        p += (*p == '-' || *p == '+') ? 1 : 0;
        std::int64_t exp_value = 0;
        for (; p != e; ++p)
        {
            if (exp_value < 0x10000000)
            {
                exp_value = (exp_value * 10) + (*p - '0');
            }
        }
        q += exp_negative ? -exp_value : exp_value;
    }

    float_significand d;
    d.w = w;
    d.exponent = q;
    d.negative = negative;
    return d;
}

/*!
@brief the value of a float token with at most 19 digits, from its layout

The result is correctly rounded by the lexer's conversion
(detail::decimal_to_float(): Clinger's fast path where both operands are
exact, else the Eisel-Lemire algorithm, which needs no fallback for up to 19
digits), so it is the value parse() produces.
*/
template<typename FloatType>
NLOHMANN_VIEW_ALWAYS_INLINE FloatType layout_float(const unsigned char* p, const unsigned char* e, unsigned int_digits, unsigned frac_digits, const unsigned char* limit) noexcept
{
    return decimal_to_float<FloatType>(layout_decimal(p, e, int_digits, frac_digits, limit));
}

/// the value of a float set by an edit: its token (the shortest round-trip
/// text, or "nan", "inf", "-inf") in the edit arena
template<typename FloatType>
NLOHMANN_VIEW_NOINLINE FloatType edited_float(const char* token, const node& n)
{
    if (token[0] == 'n')
    {
        return std::numeric_limits<FloatType>::quiet_NaN();
    }
    if (token[0] == 'i' || (token[0] == '-' && token[1] == 'i'))
    {
        return token[0] == 'i' ? std::numeric_limits<FloatType>::infinity() : -std::numeric_limits<FloatType>::infinity();
    }
    return float_value<FloatType>(token, n);
}

/// the value of the float token of a node, as parse() converts it; floats and
/// doubles with at most 19 digits are converted from the digit layout
template<typename FloatType>
FloatType float_value(const document_data& d, const node& n)
{
    if (NLOHMANN_VIEW_UNLIKELY((n.flags & node_flags::storage) == node_flags::edited))
    {
        return edited_float<FloatType>(d.str(n), n);
    }
    return float_value<FloatType>(d, n, std::integral_constant<bool, has_native_float_format<FloatType>::value> {});
}

template<typename FloatType>
FloatType float_value(const document_data& d, const node& n, std::true_type /*binary32 or binary64*/)
{
    const unsigned int_digits = n.extra & 0xFFu;
    const unsigned frac_digits = n.extra >> 8u;
    if (NLOHMANN_VIEW_LIKELY(int_digits + frac_digits <= 19)) // (255 marks "many")
    {
        // (a float token not written by an edit is in the text)
        const auto* const first = reinterpret_cast<const unsigned char*>(d.src + n.off); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        return layout_float<FloatType>(first, first + n.len, int_digits, frac_digits, reinterpret_cast<const unsigned char*>(d.src + d.size)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }
    return float_value<FloatType>(d.str(n), n);
}

template<typename FloatType>
FloatType float_value(const document_data& d, const node& n, std::false_type /*other*/)
{
    return float_value<FloatType>(d.str(n), n);
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
