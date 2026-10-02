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
template<typename BasicJsonType, bool Editable>
BasicJsonType materialize(const document_data& d, const node* n)
{
    using string_t = typename BasicJsonType::string_t;
    using sax_t = json_sax_dom_parser<BasicJsonType, iterator_input_adapter<const char*>>;
    using nav = navigation<Editable>;

    struct frame
    {
        const node* pos; ///< next element, or key of the next member
        const node* end;
        bool object;
    };

    BasicJsonType result;
    sax_t sax(result, true);
    const string_t no_token{};
    std::vector<frame> open;
    for (;;)
    {
        // false positive: n comes from nav::value(), which never returns null for a valid index
        // @infer-ignore NULLPTR_DEREFERENCE
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
                open.push_back(frame{nav::first(d, n), nav::end(d, n), object});
                break;
            }
            case value_t::string:
            {
                string_t s(d.str(*n), n->len);
                sax.string(s);
                break;
            }
            case value_t::number_integer:
                sax.number_integer(static_cast<typename BasicJsonType::number_integer_t>(static_cast<std::int64_t>(integer_bits(*n))));
                break;
            case value_t::number_unsigned:
                sax.number_unsigned(static_cast<typename BasicJsonType::number_unsigned_t>(integer_bits(*n)));
                break;
            case value_t::number_float:
                sax.number_float(float_value<typename BasicJsonType::number_float_t>(d, *n), no_token);
                break;
            case value_t::boolean:
                sax.boolean((n->flags & node_flags::is_true) != 0);
                break;
            case value_t::null:
            case value_t::binary:
            case value_t::discarded:
            default:
                sax.null();
                break;
        }

        // the next value: close finished containers, then read the key
        for (;;)
        {
            if (open.empty())
            {
                return result;
            }
            frame& f = open.back();
            if (f.pos == f.end)
            {
                if (f.object)
                {
                    sax.end_object();
                }
                else
                {
                    sax.end_array();
                }
                open.pop_back();
                continue;
            }
            const node* entry = f.pos;
            if (f.object)
            {
                string_t key(d.str(*entry), entry->len);
                sax.key(key);
                ++entry;
            }
            n = nav::value(entry);
            f.pos = document_data::after(entry);
            break;
        }
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
