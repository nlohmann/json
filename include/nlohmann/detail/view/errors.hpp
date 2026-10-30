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
#include <string> // string, to_string
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/builder.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/materialize.hpp>
#include <nlohmann/detail/view/node.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/*!
@brief the value an exception is about

basic_json passes the value to the exception, which then names its path
(JSON_DIAGNOSTICS) and its bytes in the source (JSON_DIAGNOSTIC_POSITIONS). A
view's value has no parent pointer and no stored positions: both are found
from the document and the node, when the exception is thrown (so only the
error path pays for them). Without the two macros, a site is empty.
*/
class error_site
{
  public:
    error_site() noexcept = default;

    error_site(const document_data* d, const node* n) noexcept
#if JSON_DIAGNOSTICS || JSON_DIAGNOSTIC_POSITIONS
        : m_doc(d), m_node(n)
#endif
    {
        static_cast<void>(d);
        static_cast<void>(n);
    }

#if JSON_DIAGNOSTICS || JSON_DIAGNOSTIC_POSITIONS
    const document_data* doc() const noexcept
    {
        return m_doc;
    }
    const node* value() const noexcept
    {
        return m_node;
    }

  private:
    const document_data* m_doc = nullptr;
    const node* m_node = nullptr;
#endif
};

/// the site of a view's value (the views make this a friend)
struct view_access
{
    template<typename View>
    static error_site site(const View& v) noexcept
    {
        return error_site(v.m_doc, v.m_node);
    }
};

template<typename View>
error_site site_of(const View& v) noexcept
{
    return view_access::site(v);
}

#if JSON_DIAGNOSTICS
/*!
@brief the JSON pointer tokens from the root of document @a d to node @a target

Nodes have no parent index, so the path is found by descending from the root:
before the first edit, only into the subtree that contains the target (a
container spans the next `next` nodes); after edits, elements can live in
other sequences, so every container is searched. Iterative (the nesting depth
is limited by memory only). False if the target is not found (then tokens is
unspecified).
*/
template<bool Editable>
bool value_path(const document_data& d, const node* target, std::vector<std::string>& tokens)
{
    using nav = navigation<Editable>;
    struct frame
    {
        const node* pos;
        const node* end;
        std::size_t index;
        bool object;
    };
    const node* const root = d.nodes;
    if (target == root)
    {
        return true;
    }
    if (!is_container(*root))
    {
        return false;
    }
    std::vector<frame> stack;
    stack.push_back(frame{nav::first(d, root), nav::end(d, root), 0, root->kind == node_kind::object});
    // (tokens[i] leads from stack[i] to stack[i + 1], or to the target)
    while (!stack.empty())
    {
        frame& f = stack.back();
        if (f.pos == f.end)
        {
            stack.pop_back();
            if (!tokens.empty())
            {
                tokens.pop_back();
            }
            continue;
        }
        const node* entry = f.pos;
        std::string token;
        if (f.object)
        {
            // (as basic_json: the key up to a null byte)
            token.assign(d.str(*entry), entry->len);
            const std::size_t nul = token.find('\0');
            if (nul != std::string::npos)
            {
                token.resize(nul);
            }
            ++entry;
        }
        else
        {
            token = std::to_string(f.index);
        }
        const node* const child = nav::value(entry);
        f.pos = document_data::after(entry);
        ++f.index;
        if (child == target)
        {
            tokens.push_back(token);
            return true;
        }
        if (is_container(*child) && (nav::editable() || (target > child && target < child + child->next)))
        {
            tokens.push_back(token);
            stack.push_back(frame{nav::first(d, child), nav::end(d, child), 0, child->kind == node_kind::object});
        }
    }
    return false;
}
#endif

#if JSON_DIAGNOSTIC_POSITIONS
/*!
@brief the bytes [start, end) of node @a n in the source, as materialize() sets them

Scalars as position_source::set_scalar; an array or object from its opening
bracket to its closing bracket, which is found by following the chain of last
elements to a scalar (or an empty container) and scanning from there to the
closing brackets. None (npos) for values written by edits, and for containers
whose last element has none, as with materialize().
*/
template<bool Editable>
void value_range(const document_data& d, const node* n, std::size_t& start, std::size_t& end)
{
    using nav = navigation<Editable>;
    position_source p;
    start = std::string::npos;
    end = std::string::npos;
    if (!is_container(*n))
    {
        p.set_scalar(d, *n);
        start = p.start;
        end = p.end;
        return;
    }
    if ((n->flags & node_flags::is_new) != 0 || n->off >= d.size)
    {
        return;
    }
    // the open brackets: n, then the last element as long as it is a non-empty container
    std::size_t closing = 0;
    std::size_t pos = std::string::npos;
    for (const node* c = n;;)
    {
        if (is_container(*c))
        {
            if ((c->flags & node_flags::is_new) != 0 || c->off >= d.size)
            {
                return;
            }
            ++closing;
            const node* const first = nav::first(d, c);
            const node* const last_end = nav::end(d, c);
            if (first == last_end)
            {
                pos = std::size_t{c->off} + 1;
                break;
            }
            const std::size_t value_offset = c->kind == node_kind::object ? 1 : 0;
            const node* last = first;
            for (const node* e = document_data::after(first + value_offset); e != last_end; e = document_data::after(e + value_offset))
            {
                last = e;
            }
            c = nav::value(last + value_offset);
            continue;
        }
        p.set_scalar(d, *c);
        pos = p.end;
        break;
    }
    for (; closing != 0 && pos != std::string::npos; --closing)
    {
        pos = position_source::container_end(d.base[0], d.size, pos);
    }
    if (pos != std::string::npos)
    {
        start = n->off;
        end = pos;
    }
}
#endif

/// the context basic_json puts in front of the message of an exception about
/// a value: "(/path) " with JSON_DIAGNOSTICS (none for the root), then
/// "(bytes a-b) " with JSON_DIAGNOSTIC_POSITIONS (with JSON_DIAGNOSTICS, only
/// if there is a path)
inline std::string diagnostics(const error_site site)
{
#if JSON_DIAGNOSTICS || JSON_DIAGNOSTIC_POSITIONS
    if (site.doc() == nullptr || site.value() == nullptr)
    {
        return "";
    }
    const document_data& d = *site.doc();
    const bool edited = d.edits != nullptr;
    std::string bytes;
#if JSON_DIAGNOSTIC_POSITIONS
    std::size_t start = 0;
    std::size_t end = 0;
    if (edited)
    {
        value_range<true>(d, site.value(), start, end);
    }
    else
    {
        value_range<false>(d, site.value(), start, end);
    }
    if (start != std::string::npos && end != std::string::npos)
    {
        bytes = concat("(bytes ", std::to_string(start), "-", std::to_string(end), ") ");
    }
#endif
#if JSON_DIAGNOSTICS
    std::vector<std::string> tokens;
    const bool found = edited ? value_path<true>(d, site.value(), tokens) : value_path<false>(d, site.value(), tokens);
    if (!found || tokens.empty())
    {
        return "";
    }
    std::string path;
    for (const std::string& token : tokens)
    {
        path.push_back('/');
        path += detail::escape(token);
    }
    return concat('(', path, ") ", bytes);
#else
    return bytes;
#endif
#else
    static_cast<void>(site);
    return "";
#endif
}

/// the context of an exception about view @a v (see exception_prefix())
template<typename View>
std::string diagnostics_of(const View& v)
{
    return diagnostics(site_of(v));
}

// Exceptions are thrown out of line, so that the accessors that may throw stay
// small enough to be inlined. The overloads with an error_site put its context
// in front of the message.

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_type_error(exception_id id, const char* prefix, const char* type)
{
    NLOHMANN_VIEW_THROW(type_error::create(id, concat(prefix, type), nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_type_error(exception_id id, const std::string& msg)
{
    NLOHMANN_VIEW_THROW(type_error::create(id, msg, nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_out_of_range(exception_id id, const std::string& msg)
{
    NLOHMANN_VIEW_THROW(out_of_range::create(id, msg, nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_invalid_iterator(exception_id id, const char* msg)
{
    NLOHMANN_VIEW_THROW(invalid_iterator::create(id, msg, nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_type_error(const error_site site, exception_id id, const char* prefix, const char* type)
{
    NLOHMANN_VIEW_THROW(type_error::create(id, concat(diagnostics(site), prefix, type), nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_out_of_range(const error_site site, exception_id id, const std::string& msg)
{
    NLOHMANN_VIEW_THROW(out_of_range::create(id, concat(diagnostics(site), msg), nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_invalid_iterator(const error_site site, exception_id id, const char* msg)
{
    NLOHMANN_VIEW_THROW(invalid_iterator::create(id, concat(diagnostics(site), msg), nullptr));
}

/// a parse error without a position (as those of json_pointer)
[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_parse_error(exception_id id, const std::string& msg)
{
    NLOHMANN_VIEW_THROW(parse_error::create(id, 0, msg, nullptr));
}

/// out_of_range.401: the array index @a idx is not below the size
template<typename Index>
[[noreturn]] NLOHMANN_VIEW_NOINLINE void throw_array_index_out_of_range(const error_site site, const Index idx)
{
    throw_out_of_range(site, exception_id::array_index_out_of_range, concat("array index ", std::to_string(idx), " is out of range"));
}

/// out_of_range.402: the JSON Pointer token '-' of an array of @a size elements
[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_array_index_past_end(const error_site site, std::size_t size)
{
    throw_out_of_range(site, exception_id::pointer_past_the_end_index, concat("array index '-' (", std::to_string(size), ") is out of range"));
}

/// out_of_range.403: the object has no member @a key
template<typename Key>
[[noreturn]] NLOHMANN_VIEW_NOINLINE void throw_key_not_found(const error_site site, const Key& key)
{
    throw_out_of_range(site, exception_id::key_not_found, concat("key '", key, "' not found"));
}

/// SAX handler of the error replay: accepts every event without storing it,
/// and throws the exception the parser reports
template<typename BasicJsonType>
struct throwing_sax
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;

    bool null()
    {
        return true;
    }

    bool boolean(bool /*unused*/)
    {
        return true;
    }

    bool number_integer(number_integer_t /*unused*/)
    {
        return true;
    }

    bool number_unsigned(number_unsigned_t /*unused*/)
    {
        return true;
    }

    bool number_float(number_float_t /*unused*/, const string_t& /*unused*/)
    {
        return true;
    }

    bool string(string_t& /*unused*/)
    {
        return true;
    }

    bool binary(binary_t& /*unused*/)
    {
        return true;
    }

    bool start_object(std::size_t /*unused*/)
    {
        return true;
    }

    bool key(string_t& /*unused*/)
    {
        return true;
    }

    bool end_object()
    {
        return true;
    }

    bool start_array(std::size_t /*unused*/)
    {
        return true;
    }

    bool end_array()
    {
        return true;
    }

    /// (a template, as in json_sax_dom_parser: the parser passes the concrete
    /// exception type, which is thrown as is)
    template<class Exception>
    [[noreturn]] bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const Exception& ex)
    {
        NLOHMANN_VIEW_THROW(ex);
    }
};

/*!
@brief throw the exception BasicJsonType::parse would throw for this input

The view accepts exactly the inputs parse() accepts, so on a failure the
library parser is run on the same bytes: it throws the exception parse() would
throw, with the same message, position, and "last read" token. The replay
uses a SAX handler that stores nothing, so it only lexes and parses up to the
error, without building values. The error path is cold, so this costs nothing
on valid input. Should parse() accept the input nevertheless (a bug), the
view's own failure is reported.
*/
template<typename BasicJsonType>
[[noreturn]] NLOHMANN_VIEW_NOINLINE void throw_parse_failure(const parse_failure& f, const char* src, std::size_t size,
        bool ignore_comments, bool ignore_trailing_commas)
{
    if (f.code == error_code::input_too_large)
    {
        // (the limit is detail::view::max_input_size(): 4 GiB minus 16 bytes)
        NLOHMANN_VIEW_THROW(out_of_range::create(exception_id::document_too_large, "input of 4294967280 bytes or more is not supported by json_document", nullptr));
    }
    throwing_sax<BasicJsonType> sax;
    const bool accepted = BasicJsonType::sax_parse(src, src + size, &sax, input_format_t::json, true, ignore_comments, ignore_trailing_commas);
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
    NLOHMANN_VIEW_THROW(parse_error::create(exception_id::syntax_error, pos, "syntax error while parsing value", nullptr));
    // LCOV_EXCL_STOP
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
