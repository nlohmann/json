//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // int64_t
#include <map> // map
#include <string> // basic_string
#include <type_traits> // enable_if, is_constructible
#include <unordered_map> // unordered_map
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/errors.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/number.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// selects a conversion by its target type
template<typename T>
struct value_tag {};

/*!
@brief the number or boolean of a node converted to an arithmetic type

As basic_json's get<T>() for arithmetic types: integers and floats are
converted with static_cast, booleans give 0 or 1, and other types throw
type_error.302.
*/
template<typename T, typename BasicJsonType>
NLOHMANN_VIEW_ALWAYS_INLINE T arithmetic_value(const document_data& d, const node& n)
{
    switch (static_cast<value_t>(n.kind))
    {
        case value_t::number_unsigned:
            return static_cast<T>(static_cast<typename BasicJsonType::number_unsigned_t>(integer_bits(n)));
        case value_t::number_integer:
            return static_cast<T>(static_cast<typename BasicJsonType::number_integer_t>(static_cast<std::int64_t>(integer_bits(n))));
        case value_t::number_float:
            return static_cast<T>(float_value<typename BasicJsonType::number_float_t>(d, n));
        case value_t::boolean:
            return static_cast<T>((n.flags & node_flags::is_true) != 0);
        case value_t::null:
        case value_t::object:
        case value_t::array:
        case value_t::string:
        case value_t::binary:
        case value_t::discarded:
        default:
            throw_type_error(302, "type must be number, but is ", value_type_name(static_cast<value_t>(n.kind)));
    }
}

/// std::vector from an array, element by element (type_error.302 otherwise)
template<typename View, typename U, typename A>
std::vector<U, A> vector_value(const View& v)
{
    if (NLOHMANN_VIEW_UNLIKELY(!v.is_array()))
    {
        throw_type_error(302, "type must be array, but is ", v.type_name());
    }
    std::vector<U, A> r;
    r.reserve(v.size());
    for (const View e : v)
    {
        r.push_back(e.template get<U>());
    }
    return r;
}

/// a map with string keys from an object; with duplicate keys, the last
/// value is kept, as parse() does (type_error.302 for other types)
template<typename Map, typename View>
Map map_value(const View& v)
{
    if (NLOHMANN_VIEW_UNLIKELY(!v.is_object()))
    {
        throw_type_error(302, "type must be object, but is ", v.type_name());
    }
    Map r;
    for (auto it = v.begin(); it != v.end(); ++it)
    {
        const auto key = it.key();
        r[typename Map::key_type(key.data(), key.size())] = it.value().template get<typename Map::mapped_type>();
    }
    return r;
}

/// whether a map type is read member by member (its keys are made from
/// characters and a length); other maps go through basic_json
template<typename Key>
struct is_string_key : std::is_constructible<Key, const char*, std::size_t> {};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
