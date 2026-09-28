//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // int64_t, uint8_t
#include <string> // string
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/number.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/*!
@brief the basic_json value of the subtree at n

The subtree is replayed into the SAX handler that parse() uses to build its
values, so the result is the value parse() would produce: duplicate keys keep
the last value, and with JSON_DIAGNOSTICS the parent pointers are set. It is
iterative, so the nesting depth is limited by memory only, as for parse().
Without a lexer the handler records no source positions
(JSON_DIAGNOSTIC_POSITIONS).
*/
template<typename BasicJsonType>
BasicJsonType materialize(const document_data& d, const node* n)
{
    using string_t = typename BasicJsonType::string_t;
    using sax_t = json_sax_dom_parser<BasicJsonType, iterator_input_adapter<const char*>>;

    BasicJsonType result;
    sax_t sax(result, true);
    const string_t no_token{};
    // the ends of the open containers, and whether they are objects
    std::vector<std::pair<const node*, bool>> open;
    for (;;)
    {
        switch (static_cast<value_t>(n->kind))
        {
            case value_t::object:
            case value_t::array:
            {
                const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
                if (object)
                {
                    sax.start_object(n->len);
                }
                else
                {
                    sax.start_array(n->len);
                }
                open.emplace_back(document_data::child_end(n), object);
                n = document_data::first_child(n);
                break;
            }
            case value_t::string:
            {
                string_t s(d.str(*n), n->len);
                sax.string(s);
                ++n;
                break;
            }
            case value_t::number_integer:
                sax.number_integer(static_cast<typename BasicJsonType::number_integer_t>(static_cast<std::int64_t>(integer_bits(*n))));
                ++n;
                break;
            case value_t::number_unsigned:
                sax.number_unsigned(static_cast<typename BasicJsonType::number_unsigned_t>(integer_bits(*n)));
                ++n;
                break;
            case value_t::number_float:
                sax.number_float(float_value<typename BasicJsonType::number_float_t>(d, *n), no_token);
                ++n;
                break;
            case value_t::boolean:
                sax.boolean((n->flags & node_flags::is_true) != 0);
                ++n;
                break;
            case value_t::null:
            case value_t::binary:
            case value_t::discarded:
            default:
                sax.null();
                ++n;
                break;
        }
        for (;;)
        {
            if (open.empty())
            {
                return result;
            }
            if (n != open.back().first)
            {
                break;
            }
            if (open.back().second)
            {
                sax.end_object();
            }
            else
            {
                sax.end_array();
            }
            open.pop_back();
        }
        if (open.back().second)
        {
            // the key of the next member
            string_t key(d.str(*n), n->len);
            sax.key(key);
            ++n;
        }
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
