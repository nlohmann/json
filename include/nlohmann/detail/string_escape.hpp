//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <nlohmann/detail/abi_macros.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
 * @brief Out Of Place string escaping as described in RFC 6901 (Sect. 4)
 * @param[in] s string to escape
 * @return    escaped string
 *
 */
template<typename StringType> // [[nodiscard]]
inline StringType escape(StringType const& s)
{
    using CharT = typename StringType::value_type;
    StringType res;

    int esz = s.size();
    for (auto const ch : s)
        if (ch == CharT('~') || ch == CharT('/'))
        {
            ++esz;
        }
    if (esz == s.size())
    {
        res = s;
    }
    else
    {
        res.reserve(esz);
        for (auto const ch : s) // Yes, this is UTF8-safe
            if (ch == CharT('~'))
                res.append(StringType{"~0"});
            else if (ch == CharT('/'))
                res.append(StringType{"~1"});
            else
            {
                res.push_back(ch);
            }
    }
    return res;
}

/*!
 * @brief In Place string unescaping as described in RFC 6901 (Sect. 4)
 * @param[in] s string to unescape
 *
 */
template<typename StringType>
inline void unescape(StringType& s)
{
    using CharT = typename StringType::value_type;
    auto j = s.begin();
    while (j != s.end() && *j != CharT('~'))
    {
        ++j;
    }
    auto i = j;
    while (i != s.end())
    {
        if (*i == CharT('~') && (i + 1) != s.end())
        {
            if (*(i + 1) == CharT('0'))
            {
                *j++ = CharT('~');
                ++i;
            }
            else if (*(i + 1) == CharT('1'))
            {
                *j++ = CharT('/');
                ++i;
            } // ... else shouldn't we throw parse_error.108 here?
        }
        else
        {
            *j++ = *i;
        }
        ++i;
    }
    s.resize(j - s.begin());
    s.shrink_to_fit();
}

/*!
 * @brief Out Of Place string unescaping as described in RFC 6901 (Sect. 4)
 * @param[in] s string to unescape
 *
 */
template<typename StringType> // [[nodiscard]]
inline StringType unescape(StringType const& s)
{
    StringType res = s;
    unescape(res);
    return res;
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
