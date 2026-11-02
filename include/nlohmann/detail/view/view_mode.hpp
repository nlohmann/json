//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // uint8_t
#include <type_traits> // false_type, true_type

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

namespace detail
{
namespace view
{

/// whether two view modes differ
template<view_mode A, view_mode B>
struct is_other_mode : std::true_type {};

template<view_mode A>
struct is_other_mode<A, A> : std::false_type {};

/// whether a view of mode From converts implicitly to one of mode To: a
/// read-only document has no edits, so a view of it is read correctly as a
/// view of an editable document that has not been edited yet
template<view_mode From, view_mode To>
struct is_widening_mode : std::false_type {};

template<>
struct is_widening_mode<view_mode::read_only, view_mode::editable> : std::true_type {};

}  // namespace view
}  // namespace detail

NLOHMANN_JSON_NAMESPACE_END
