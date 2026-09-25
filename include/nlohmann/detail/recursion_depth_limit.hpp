//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t

#include <nlohmann/detail/abi_macros.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief the number of nesting levels an operation recurses into

Operations that walk a value (serializing, hashing, merging, ...) recurse once
per nesting level, which is fastest, but a value nested deeply enough would
exhaust the call stack. So they recurse only this many levels deep and finish
whatever lies below with an explicit stack. All of them share this limit.

@sa https://github.com/nlohmann/json/issues/5387
*/
constexpr std::size_t recursion_depth_limit() noexcept
{
    return 128;
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
