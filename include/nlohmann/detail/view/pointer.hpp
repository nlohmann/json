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
#include <limits> // numeric_limits
#include <string> // string, to_string

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/errors.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// what resolving a JSON pointer does where it cannot continue
enum class pointer_mode
{
    unchecked, ///< as const basic_json::operator[]: a discarded view where basic_json's behavior is undefined
    checked,   ///< as basic_json::at(): out_of_range.401/403
    value,     ///< as basic_json::value(): no out_of_range exceptions (the default value is used)
    contains,  ///< as basic_json::contains(): no exceptions at all
};

/// the outcome of reading an array index from a reference token
enum class index_status
{
    ok,
    leading_zero, ///< parse_error.106
    not_number,   ///< parse_error.109
    unresolved,   ///< out_of_range.404
    too_large,    ///< out_of_range.410
};

/// reads an array index like json_pointer::array_index (RFC 6901, Sect. 4),
/// but reports errors instead of throwing them
template<typename StringType>
index_status array_index(const StringType& s, std::size_t& idx) noexcept
{
    if (s.size() > 1 && s[0] == '0')
    {
        return index_status::leading_zero;
    }
    if (s.size() > 1 && !(s[0] >= '1' && s[0] <= '9'))
    {
        return index_status::not_number;
    }
    if (s.empty())
    {
        return index_status::unresolved;
    }
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < s.size(); ++i)
    {
        const auto d = static_cast<unsigned>(static_cast<unsigned char>(s[i])) - '0';
        if (d > 9 || v > ((std::numeric_limits<std::uint64_t>::max)() - d) / 10)
        {
            return index_status::unresolved; // not a number, or beyond unsigned long long
        }
        v = (v * 10) + d;
    }
    if (v >= (std::numeric_limits<std::size_t>::max)()) // (std::size_t converts to std::uint64_t implicitly)
    {
        return index_status::too_large;
    }
    idx = static_cast<std::size_t>(v);
    return index_status::ok;
}

/// throws the exception json_pointer::array_index throws for this status
template<typename StringType>
[[noreturn]] NLOHMANN_VIEW_NOINLINE void throw_array_index_error(index_status status, const StringType& s)
{
    switch (status)
    {
        case index_status::leading_zero:
            throw_parse_error(106, concat("array index '", s, "' must not begin with '0'"));
        case index_status::not_number:
            throw_parse_error(109, concat("array index '", s, "' is not a number"));
        case index_status::too_large:
            throw_out_of_range(410, concat("array index ", s, " exceeds size_type")); // LCOV_EXCL_LINE
        case index_status::unresolved:
        case index_status::ok:
        default:
            throw_out_of_range(404, concat("unresolved reference token '", s, "'"));
    }
}

/*!
@brief resolve the reference tokens of a JSON pointer, starting at a view

The exceptions are those basic_json throws for the same pointer; where
basic_json's behavior is undefined (a missing key or an index out of range
with const operator[]), the result is a discarded view.
*/
template<typename View, typename Tokens>
View resolve_pointer(View cur, const Tokens& tokens, pointer_mode mode)
{
    using string_view_t = typename View::string_view_t;
    const bool throwing = mode == pointer_mode::unchecked || mode == pointer_mode::checked;
    for (const auto& token : tokens)
    {
        if (cur.is_object())
        {
            const auto it = cur.find(string_view_t(token.data(), token.size()));
            if (it == cur.end())
            {
                if (mode == pointer_mode::checked)
                {
                    throw_out_of_range(403, concat("key '", token, "' not found"));
                }
                return View();
            }
            cur = *it;
        }
        else if (cur.is_array())
        {
            if (token.size() == 1 && token[0] == '-')
            {
                if (throwing)
                {
                    throw_out_of_range(402, concat("array index '-' (", std::to_string(cur.size()), ") is out of range"));
                }
                return View();
            }
            std::size_t idx = 0;
            const index_status status = array_index(token, idx);
            if (status != index_status::ok)
            {
                const bool parse_error = status == index_status::leading_zero || status == index_status::not_number;
                if (throwing || (mode == pointer_mode::value && parse_error))
                {
                    throw_array_index_error(status, token);
                }
                return View();
            }
            if (idx >= cur.size())
            {
                if (mode == pointer_mode::checked)
                {
                    throw_out_of_range(401, concat("array index ", std::to_string(idx), " is out of range"));
                }
                return View();
            }
            cur = cur[idx];
        }
        else
        {
            if (throwing)
            {
                throw_out_of_range(404, concat("unresolved reference token '", token, "'"));
            }
            return View();
        }
    }
    return cur;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
