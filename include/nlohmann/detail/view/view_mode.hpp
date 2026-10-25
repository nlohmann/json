//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // uint8_t

#include <nlohmann/json.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN

/// whether a basic_json_document and its views can be edited
enum class view_mode : std::uint8_t
{
    read_only, ///< parsed once, then only read (the default)
    editable,  ///< also has set(), push_back(), insert(), and erase()
};

template<typename BasicJsonType, view_mode Mode>
class basic_json_view;

NLOHMANN_JSON_NAMESPACE_END
