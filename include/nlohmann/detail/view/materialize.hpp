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

#if JSON_DIAGNOSTIC_POSITIONS
/*!
@brief the source positions of the values materialize() replays

Stands in for the lexer of json_sax_dom_parser, which reads the positions of
the values it stores from these three functions (diagnostic_positions). npos
is a value without a source position.
*/
struct position_source
{
    /// the token, of which diagnostic_positions only reads the length
    struct token
    {
        std::size_t length;
        std::size_t size() const noexcept
        {
            return length;
        }
    };

    std::size_t start = std::string::npos; ///< the first byte of the next value
    std::size_t end = std::string::npos;   ///< one past the next value (start_object/start_array: one past the bracket)

    std::size_t get_chars_read_total() const noexcept
    {
        return end;
    }
    std::size_t get_token_start_position() const noexcept
    {
        return start;
    }
    token get_string() const noexcept
    {
        return token{end - start};
    }

    /// the range [first, last), or none if either is npos
    void set(std::size_t first, std::size_t last) noexcept
    {
        const bool known = first != std::string::npos && last != std::string::npos;
        start = known ? first : std::string::npos;
        end = known ? last : std::string::npos;
    }

    /// one past the closing quote of the string whose opening quote is at
    /// src[quote], or npos (the scan is bounded by size, as images can be
    /// loaded without a check)
    static std::size_t string_end(const char* src, std::size_t size, std::size_t quote) noexcept
    {
        for (std::size_t i = quote + 1; i < size; ++i)
        {
            if (src[i] == '\\')
            {
                ++i;
            }
            else if (src[i] == '"')
            {
                return i + 1;
            }
        }
        return std::string::npos;
    }

    /// one past the closing bracket of the array or object whose last element
    /// ends at src[pos] (or whose opening bracket is at src[pos - 1]), or npos;
    /// in between, there can only be whitespace, comments, and a trailing comma
    /// (the source was validated when it was parsed)
    static std::size_t container_end(const char* src, std::size_t size, std::size_t pos) noexcept
    {
        while (pos < size)
        {
            switch (src[pos])
            {
                case ' ':
                case '\t':
                case '\n':
                case '\r':
                case ',':
                    ++pos;
                    break;
                case ']':
                case '}':
                    return pos + 1;
                case '/':
                    if (pos + 1 < size && src[pos + 1] == '/')
                    {
                        pos += 2;
                        while (pos < size && src[pos] != '\n' && src[pos] != '\r')
                        {
                            ++pos;
                        }
                        break;
                    }
                    if (pos + 1 < size && src[pos + 1] == '*')
                    {
                        pos += 2;
                        while (pos < size && !(src[pos] == '*' && pos + 1 < size && src[pos + 1] == '/'))
                        {
                            ++pos;
                        }
                        pos += 2;
                        break;
                    }
                    return std::string::npos;
                default:
                    return std::string::npos;
            }
        }
        return std::string::npos;
    }

    /// the range of the scalar n of document d
    void set_scalar(const document_data& d, const node& n) noexcept
    {
        const std::size_t size = d.size;
        const std::size_t off = n.off;
        std::size_t first = std::string::npos;
        std::size_t last = std::string::npos;
        if ((n.flags & node_flags::is_new) == 0)
        {
            switch (static_cast<value_t>(n.kind))
            {
                case value_t::string:
                    if ((n.flags & node_flags::storage) == 0)
                    {
                        // off is the first byte after the opening quote
                        if (off != 0)
                        {
                            first = off - 1;
                            last = off + std::size_t{n.len} + 1;
                        }
                    }
                    else if ((n.flags & node_flags::storage) == node_flags::escaped && n.next != 0)
                    {
                        // next is the offset of the opening quote plus one
                        first = n.next - 1;
                        last = string_end(d.base[0], size, first);
                    }
                    break;
                case value_t::number_integer:
                case value_t::number_unsigned:
                case value_t::number_float:
                    if ((n.flags & node_flags::storage) == 0)
                    {
                        first = off;
                        last = off + number_length(n);
                    }
                    break;
                case value_t::boolean:
                    first = off;
                    last = off + ((n.flags & node_flags::is_true) != 0 ? 4u : 5u);
                    break;
                case value_t::null:
                    first = off;
                    last = off + 4u;
                    break;
                case value_t::object:
                case value_t::array:
                case value_t::binary:
                case value_t::discarded:
                default:
                    break;
            }
        }
        // (a crafted image can point past the text)
        set(first, last != std::string::npos && last <= size ? last : std::string::npos);
    }
};
#endif

/*!
@brief the basic_json value of the subtree at n

The subtree is replayed into the SAX handler that parse() uses to build its
values, so the result is the value parse() would produce: duplicate keys keep
the last value, and with JSON_DIAGNOSTICS the parent pointers are set. It is
iterative, so the nesting depth is limited by memory only, as for parse().

With JSON_DIAGNOSTIC_POSITIONS, the values get their source positions as with
parse(): position_source stands in for the lexer. Values written by edits have
none (npos), and neither has an array or object whose elements changed, or
whose last element has none (the end of its closing bracket is found by
scanning from the end of the last element).
*/
template<typename BasicJsonType, bool Editable>
BasicJsonType materialize(const document_data& d, const node* n)
{
    using string_t = typename BasicJsonType::string_t;
#if JSON_DIAGNOSTIC_POSITIONS
    using sax_t = json_sax_dom_parser<BasicJsonType, iterator_input_adapter<const char*>, true, position_source>;
#else
    using sax_t = json_sax_dom_parser<BasicJsonType, iterator_input_adapter<const char*>, true>;
#endif
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
#if JSON_DIAGNOSTIC_POSITIONS
        std::size_t start;    ///< the opening bracket (npos: unknown)
        std::size_t last_end; ///< the end of the last element read (npos: unknown)
#endif
    };

#if !JSON_DIAGNOSTIC_POSITIONS
    // a scalar needs neither the handler nor the stack of open containers
    // (with positions, it goes through the handler, which sets them)
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
#endif

    BasicJsonType result;
#if JSON_DIAGNOSTIC_POSITIONS
    position_source positions;
    sax_t sax(result, true, &positions);
#else
    sax_t sax(result, true);
#endif
    const string_t no_token {};
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
#if JSON_DIAGNOSTIC_POSITIONS
        if (!is_container(*n))
        {
            positions.set_scalar(d, *n);
            if (depth != 0)
            {
                open[depth - 1].last_end = positions.end;
            }
        }
#endif
        // false positive: n comes from nav::value(), which never returns null for a valid index
        // @infer-ignore NULLPTR_DEREFERENCE
        switch (static_cast<value_t>(n->kind))
        {
            case value_t::object:
            case value_t::array:
            {
                const bool object = n->kind == node_kind::object;
#if JSON_DIAGNOSTIC_POSITIONS
                // (moved containers are also new)
                const std::size_t start = (n->flags & node_flags::is_new) == 0 && n->off < d.size ? std::size_t{n->off} :
                                          std::string::npos;
                positions.set(start, start + 1);
#endif
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
#if JSON_DIAGNOSTIC_POSITIONS
                // (until an element is read, the container's own bracket is the last thing read)
                open[depth++] = frame{nav::first(d, n), nav::end(d, n), object, start, positions.end};
                break;
#else
                open[depth++] = frame {nav::first(d, n), nav::end(d, n), object};
                break;
#endif
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
#if JSON_DIAGNOSTIC_POSITIONS
                const std::size_t end = f.start == std::string::npos || f.last_end == std::string::npos ? std::string::npos : position_source::container_end(d.base[0], d.size, f.last_end);
                // (an end of npos clears the start, see diagnostic_positions)
                positions.set(end == std::string::npos ? end : end - 1, end);
                if (depth > 1)
                {
                    open[depth - 2].last_end = end;
                }
#endif
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
