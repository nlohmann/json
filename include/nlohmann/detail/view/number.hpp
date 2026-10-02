//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <string> // string

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>

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

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
