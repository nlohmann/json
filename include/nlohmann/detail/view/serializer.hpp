//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // max
#include <array> // array
#include <cmath> // isfinite
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <cstring> // memcpy, memset
#include <limits> // numeric_limits
#include <type_traits> // integral_constant
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

/// append-only output buffer: writes through a raw pointer into a string that
/// is resized ahead, and trimmed by finish()
template<typename StringType>
class output_buffer
{
  public:
    output_buffer(StringType& out, std::size_t estimate)
        : m_out(sized(out, estimate))
        , m_pos(&m_out[0])
        , m_end(m_pos + m_out.size())
    {}

    void finish()
    {
        m_out.resize(static_cast<std::size_t>(m_pos - m_out.data()));
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void reserve(std::size_t n)
    {
        if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::size_t>(m_end - m_pos) < n))
        {
            grow(n);
        }
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void put(char c)
    {
        reserve(1);
        *m_pos++ = c;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void put(const char* s, std::size_t n)
    {
        reserve(n);
        std::memcpy(m_pos, s, n);
        m_pos += n;
    }

    void put_repeated(char c, std::size_t n)
    {
        reserve(n);
        std::memset(m_pos, c, n);
        m_pos += n;
    }

  private:
    static StringType& sized(StringType& out, std::size_t estimate)
    {
        out.resize((std::max)(estimate, static_cast<std::size_t>(64)));
        return out;
    }

    NLOHMANN_VIEW_NOINLINE void grow(std::size_t n)
    {
        const auto used = static_cast<std::size_t>(m_pos - m_out.data());
        m_out.resize((std::max)(m_out.size() * 2, used + n + 256));
        m_pos = &m_out[0] + used;
        m_end = &m_out[0] + m_out.size();
    }

    StringType& m_out;
    char* m_pos;
    char* m_end;
};

/// how the view's dump() writes a value
struct dump_style
{
    bool pretty = false;           ///< indent >= 0
    std::size_t indent = 0;        ///< characters per level
    char indent_char = ' ';
    bool ensure_ascii = false;
    bool source_numbers = false;   ///< copy number tokens from the source
};

/*!
@brief write a view's subtree as basic_json::dump() writes the value

The output of a subtree equals ordered_json::parse(text).dump() of it for
the same arguments (members in document order): strings are escaped by the
same rules, with the library's scanning kernels; floats are written with
the library's conversion; integers are copied from the source, where they
are canonical (except "-0", which parse() reads as 0). The walk is
iterative, so the nesting depth is limited by memory only.
*/
template<typename BasicJsonType>
class view_serializer
{
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;

  public:
    view_serializer(const document_data& d, string_t& out, std::size_t estimate, const dump_style& style)
        : m_doc(d), m_out(out, estimate), m_style(style)
    {}

    void dump(const node* root)
    {
        struct frame
        {
            const node* pos; ///< next element, or key of the next member
            const node* end;
            bool object;
            bool first;  ///< nothing written yet
        };
        std::vector<frame> stack;
        const node* n = root;
        for (;;)
        {
            // write the value at n
            if (is_container(*n))
            {
                const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
                if (n->len == 0)
                {
                    m_out.put(object ? "{}" : "[]", 2);
                }
                else
                {
                    m_out.put(object ? '{' : '[');
                    stack.push_back(frame{document_data::first_child(n), document_data::child_end(n), object, true});
                }
            }
            else
            {
                write_scalar(*n);
            }

            // go to the next value: close finished containers, then separate
            for (;;)
            {
                if (stack.empty())
                {
                    m_out.finish();
                    return;
                }
                frame& f = stack.back();
                if (f.pos == f.end)
                {
                    const bool object = f.object;
                    stack.pop_back();
                    newline(stack.size());
                    m_out.put(object ? '}' : ']');
                    continue;
                }
                if (!f.first)
                {
                    m_out.put(',');
                }
                f.first = false;
                newline(stack.size());
                if (f.object)
                {
                    write_string(*f.pos);
                    if (m_style.pretty)
                    {
                        m_out.put(": ", 2);
                    }
                    else
                    {
                        m_out.put(':');
                    }
                    n = f.pos + 1;
                }
                else
                {
                    n = f.pos;
                }
                f.pos = document_data::after(n);
                break;
            }
        }
    }

  private:
    void newline(std::size_t level)
    {
        if (m_style.pretty)
        {
            m_out.put('\n');
            m_out.put_repeated(m_style.indent_char, level * m_style.indent);
        }
    }

    void write_scalar(const node& n)
    {
        switch (static_cast<value_t>(n.kind))
        {
            case value_t::null:
                m_out.put("null", 4);
                break;
            case value_t::boolean:
                if ((n.flags & node_flags::is_true) != 0)
                {
                    m_out.put("true", 4);
                }
                else
                {
                    m_out.put("false", 5);
                }
                break;
            case value_t::string:
                write_string(n);
                break;
            case value_t::number_integer:
            case value_t::number_unsigned:
            {
                const char* const token = m_doc.str(n);
                const std::uint32_t len = number_length(n);
                if (!m_style.source_numbers && len == 2 && token[0] == '-' && token[1] == '0')
                {
                    m_out.put('0'); // parse() reads -0 as the integer 0
                }
                else
                {
                    m_out.put(token, len);
                }
                break;
            }
            case value_t::number_float:
                if (m_style.source_numbers)
                {
                    m_out.put(m_doc.str(n), n.len);
                }
                else
                {
                    write_float(float_value<number_float_t>(m_doc, n));
                }
                break;
            case value_t::object:    // LCOV_EXCL_LINE (containers are written by dump())
            case value_t::array:     // LCOV_EXCL_LINE
            case value_t::binary:    // LCOV_EXCL_LINE (not in a document)
            case value_t::discarded: // LCOV_EXCL_LINE
            default:                 // LCOV_EXCL_LINE
                break;               // LCOV_EXCL_LINE
        }
    }

    /// as serializer::dump_float()
    void write_float(number_float_t x)
    {
        if (!std::isfinite(x))
        {
            m_out.put("null", 4);
            return;
        }
        write_float(x, std::integral_constant < bool,
                    (std::numeric_limits<number_float_t>::is_iec559 && std::numeric_limits<number_float_t>::digits == 24 && std::numeric_limits<number_float_t>::max_exponent == 128)
                    || (std::numeric_limits<number_float_t>::is_iec559 && std::numeric_limits<number_float_t>::digits == 53 && std::numeric_limits<number_float_t>::max_exponent == 1024) > {});
    }

    void write_float(number_float_t x, std::true_type /*is_ieee_single_or_double*/)
    {
        std::array<char, 64> buf{};
        const char* const end = ::nlohmann::detail::to_chars(buf.data(), buf.data() + buf.size(), x);
        m_out.put(buf.data(), static_cast<std::size_t>(end - buf.data()));
    }

    void write_float(number_float_t x, std::false_type /*is_ieee_single_or_double*/)
    {
        // other types (e.g. long double) are rare: the library writes them
        const string_t s = BasicJsonType(x).dump();
        m_out.put(s.data(), s.size());
    }

    void write_string(const node& n)
    {
        const char* const s = m_doc.str(n);
        m_out.put('"');
        if ((n.flags & node_flags::escaped) == 0 && !m_style.ensure_ascii)
        {
            // a string without escape sequences has nothing to escape
            m_out.put(s, n.len);
        }
        else if (m_style.ensure_ascii)
        {
            write_escaped<true>(reinterpret_cast<const unsigned char*>(s), n.len); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        }
        else
        {
            write_escaped<false>(reinterpret_cast<const unsigned char*>(s), n.len); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        }
        m_out.put('"');
    }

    /// as serializer::dump_escaped() for valid UTF-8 (the view has no other)
    template<bool EnsureAscii>
    void write_escaped(const unsigned char* s, std::size_t n)
    {
        std::size_t i = 0;
        while (i < n)
        {
            std::size_t run = 0;
            if (!EnsureAscii)
            {
                run = string_bulk_run(s + i, n - i);
            }
            else if (is_ascii_copyable(s[i]))
            {
                run = find_ascii_copyable_run(s + i, n - i);
            }
            if (run != 0)
            {
                m_out.put(reinterpret_cast<const char*>(s + i), run); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                i += run;
                continue;
            }
            std::uint32_t codepoint = s[i];
            std::size_t len = 1;
            if (codepoint >= 0xC0)
            {
                len = 2;
                if (codepoint >= 0xE0)
                {
                    len = codepoint >= 0xF0 ? 4 : 3;
                }
                codepoint &= 0xFFu >> (len + 1);
                for (std::size_t k = 1; k < len; ++k)
                {
                    codepoint = (codepoint << 6u) | (s[i + k] & 0x3Fu);
                }
            }
            write_codepoint<EnsureAscii>(codepoint, s + i, len);
            i += len;
        }
    }

    template<bool EnsureAscii>
    void write_codepoint(std::uint32_t codepoint, const unsigned char* bytes, std::size_t len)
    {
        switch (codepoint)
        {
            case 0x08:
                m_out.put("\\b", 2);
                return;
            case 0x09:
                m_out.put("\\t", 2);
                return;
            case 0x0A:
                m_out.put("\\n", 2);
                return;
            case 0x0C:
                m_out.put("\\f", 2);
                return;
            case 0x0D:
                m_out.put("\\r", 2);
                return;
            case 0x22:
                m_out.put("\\\"", 2);
                return;
            case 0x5C:
                m_out.put("\\\\", 2);
                return;
            default:
                break;
        }
        if (codepoint <= 0x1F || (EnsureAscii && codepoint >= 0x7F))
        {
            if (codepoint <= 0xFFFF)
            {
                write_u_escape(codepoint);
            }
            else
            {
                write_u_escape(0xD7C0u + (codepoint >> 10u));
                write_u_escape(0xDC00u + (codepoint & 0x3FFu));
            }
            return;
        }
        m_out.put(reinterpret_cast<const char*>(bytes), len); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) LCOV_EXCL_LINE (printable characters are copied in runs)
    }

    void write_u_escape(std::uint32_t u)
    {
        static constexpr const char* hex = "0123456789abcdef";
        const std::array<char, 6> e = {{'\\', 'u', hex[(u >> 12u) & 0xFu], hex[(u >> 8u) & 0xFu], hex[(u >> 4u) & 0xFu], hex[u & 0xFu]}};
        m_out.put(e.data(), e.size());
    }

    const document_data& m_doc;
    output_buffer<string_t> m_out;
    const dump_style m_style;
};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
