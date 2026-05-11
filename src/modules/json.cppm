//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

module;

#include <nlohmann/json.hpp>

export module nlohmann.json;

export
NLOHMANN_JSON_NAMESPACE_BEGIN

using NLOHMANN_JSON_NAMESPACE::adl_serializer;
using NLOHMANN_JSON_NAMESPACE::basic_json;
using NLOHMANN_JSON_NAMESPACE::json;
using NLOHMANN_JSON_NAMESPACE::json_pointer;
using NLOHMANN_JSON_NAMESPACE::ordered_json;
using NLOHMANN_JSON_NAMESPACE::ordered_map;
using NLOHMANN_JSON_NAMESPACE::to_string;

inline namespace literals
{
inline namespace json_literals
{
    using NLOHMANN_JSON_NAMESPACE::literals::json_literals::operator""_json;
    using NLOHMANN_JSON_NAMESPACE::literals::json_literals::operator""_json_pointer;
} // namespace json_literals
} // namespace literals

// Note: the following nlohmann::detail symbols must be exported due to
// an MSVC bug failing to compile without these symbols visible (ticket #3970)
namespace detail
{
    using NLOHMANN_JSON_NAMESPACE::detail::json_sax_dom_callback_parser;
    using NLOHMANN_JSON_NAMESPACE::detail::unknown_size;
} // namespace detail

NLOHMANN_JSON_NAMESPACE_END

export namespace std
{
    using std::hash;
    using std::less;
    using std::swap;
} // namespace std
