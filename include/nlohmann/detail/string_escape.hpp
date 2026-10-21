//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <utility> // move

#include <nlohmann/detail/abi_macros.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// append @a s to @a out, escaped like @ref escape does
template<typename StringType>
inline void escape_into(StringType& out, const StringType& s)
{
    const std::size_t size = s.size();
    std::size_t run = 0;
    for (std::size_t i = 0; i < size; ++i)
    {
        const char c = s[i];
        if (c == '~' || c == '/')
        {
            out.append(s.data() + run, i - run);
            out.append(c == '~' ? "~0" : "~1", 2);
            run = i + 1;
        }
    }
    out.append(s.data() + run, size - run);
}

/*!
 * @brief string escaping as described in RFC 6901 (Sect. 4)
 * @param[in] s string to escape
 * @return    escaped string
 *
 * Note the order of escaping "~" to "~0" and "/" to "~1" is important.
 *
 * The string is rebuilt in a single pass, appending whole runs between the
 * characters that need escaping, while repeated replace() calls would move
 * the tail of the string once per escaped character. @ref escape_into appends
 * the escaped string to an existing one.
 */
template<typename StringType>
inline StringType escape(const StringType& s)
{
    // a single scan for both special characters; nothing to escape is the common case
    const std::size_t size = s.size();
    std::size_t i = 0;
    while (i < size && s[i] != '~' && s[i] != '/')
    {
        ++i;
    }
    if (i == size)
    {
        return s;
    }

    StringType result;
    result.reserve(size + 2);
    escape_into(result, s);
    return result;
}

/*!
 * @brief string unescaping as described in RFC 6901 (Sect. 4)
 * @param[in,out] s string to unescape in place
 *
 * Note the order of escaping "~1" to "/" and "~0" to "~" is important.
 *
 * Rebuilt in a single pass, see @ref escape. A "~" that is followed by
 * neither "0" nor "1" is passed through unchanged; @ref json_pointer rejects
 * such input before it gets here.
 */
template<typename StringType>
inline void unescape(StringType& s)
{
    auto pos = s.find_first_of('~', 0);
    if (pos == StringType::npos)
    {
        return;
    }

    StringType result;
    result.reserve(s.size());

    std::size_t run = 0;
    while (pos != StringType::npos)
    {
        result.append(s.data() + run, pos - run);

        const auto next = pos + 1;
        if (next < s.size() && (s[next] == '0' || s[next] == '1'))
        {
            result.append(s[next] == '0' ? "~" : "/", 1);
            run = pos + 2;
        }
        else
        {
            result.append("~", 1);
            run = pos + 1;
        }
        pos = s.find_first_of('~', run);
    }
    result.append(s.data() + run, s.size() - run);
    s = std::move(result);
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
