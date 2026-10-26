//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cstddef> // size_t
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
    using sax_t = json_sax_dom_parser<BasicJsonType, iterator_input_adapter<const char*>, true>;
    using nav = navigation<Editable>;

    // the open containers: their next element (or key of the next member),
    // their end, and whether they are objects; for the first 16 levels on the
    // stack, else sized once from the document's deepest nesting (for a
    // subtree an upper bound)
    struct frame
    {
        const node* pos;
        const node* end;
        bool object;
    };

    // a scalar needs neither the handler nor the stack of open containers
    switch (static_cast<value_t>(n->kind))
    {
        case value_t::string:
            return BasicJsonType(string_t(d.str(*n), n->len));
        case value_t::number_integer:
            return BasicJsonType(static_cast<typename BasicJsonType::number_integer_t>(static_cast<std::int64_t>(integer_bits(*n))));
        case value_t::number_unsigned:
            return BasicJsonType(static_cast<typename BasicJsonType::number_unsigned_t>(integer_bits(*n)));
        case value_t::number_float:
            return BasicJsonType(float_value<typename BasicJsonType::number_float_t>(d, *n));
        case value_t::boolean:
            return BasicJsonType((n->flags & node_flags::is_true) != 0);
        case value_t::null:
            return BasicJsonType(nullptr);
        case value_t::object:
        case value_t::array:
        case value_t::binary:
        case value_t::discarded:
        default:
            break;
    }

    BasicJsonType result;
    sax_t sax(result, true);
    const string_t no_token{};
    // (shallow subtrees on the stack: a call for a small value then allocates only for the value)
    std::array<frame, 16> shallow; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): filled as containers open
    std::vector<frame> deep{};
    frame* open = shallow.data();
    std::size_t capacity = shallow.size();
    if (d.max_depth > capacity)
    {
        deep.resize(d.max_depth);
        open = deep.data();
        capacity = deep.size();
    }
    std::size_t depth = 0;
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
                if (NLOHMANN_VIEW_UNLIKELY(depth == capacity))
                {
                    // (deeper than the recorded nesting, e.g. after edits)
                    deep.assign(open, open + depth);
                    deep.resize(depth * 2);
                    open = deep.data();
                    capacity = deep.size();
                }
                open[depth++] = frame{nav::first(d, n), nav::end(d, n), object};
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
                // false positive: the parser's frame stack points into its own storage (never null)
                // @infer-ignore NULLPTR_DEREFERENCE
                sax.null();
                break;
        }

        // the next value: close finished containers, then read the key
        for (;;)
        {
            if (depth == 0)
            {
                return result;
            }
            frame& f = open[depth - 1];
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
                --depth;
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
