//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // min
#include <cstddef> // size_t
#include <string> // string

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/builder.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

// Exceptions are thrown out of line, so that the accessors that may throw stay
// small enough to be inlined.

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_type_error(int id, const char* prefix, const char* type)
{
    NLOHMANN_VIEW_THROW(type_error::create(id, concat(prefix, type), nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_out_of_range(int id, const std::string& msg)
{
    NLOHMANN_VIEW_THROW(out_of_range::create(id, msg, nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_invalid_iterator(int id, const char* msg)
{
    NLOHMANN_VIEW_THROW(invalid_iterator::create(id, msg, nullptr));
}

/*!
@brief throw the exception BasicJsonType::parse would throw for this input

The view accepts exactly the inputs parse() accepts, so on a failure the
library parser is run on the same bytes: it throws the exception parse() would
throw, with the same message, position, and "last read" token. The error path
is cold, so this costs nothing on valid input. Should parse() accept the input
nevertheless (a bug), the view's own failure is reported.
*/
template<typename BasicJsonType>
[[noreturn]] NLOHMANN_VIEW_NOINLINE void throw_parse_failure(const parse_failure& f, const char* src, std::size_t size,
        bool ignore_comments, bool ignore_trailing_commas)
{
    if (f.code == error_code::input_too_large)
    {
        // LCOV_EXCL_START (4 GiB)
        NLOHMANN_VIEW_THROW(out_of_range::create(416, "input of 4 GiB or more is not supported by json_document", nullptr));
        // LCOV_EXCL_STOP
    }
    const BasicJsonType accepted = BasicJsonType::parse(src, src + size, nullptr, true, ignore_comments, ignore_trailing_commas);
    // LCOV_EXCL_START (only if parse() accepts what the view rejects: a bug)
    static_cast<void>(accepted);

    position_t pos;
    const std::size_t off = (std::min)(f.offset, size);
    pos.chars_read_total = off + 1;
    std::size_t line_start = 0;
    for (std::size_t i = 0; i < off; ++i)
    {
        if (src[i] == '\n')
        {
            ++pos.lines_read;
            line_start = i + 1;
        }
    }
    pos.chars_read_current_line = off + 1 - line_start;
    NLOHMANN_VIEW_THROW(parse_error::create(101, pos, "syntax error while parsing value", nullptr));
    // LCOV_EXCL_STOP
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
