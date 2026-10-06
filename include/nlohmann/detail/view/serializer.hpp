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
/// is resized ahead, and trimmed by finish(). The estimate is reserved, and the
/// string grows in steps of 64 KiB within it: resize() fills the new bytes
/// with zeros (before C++23, a string cannot grow without), and a small step
/// is filled while the writer is about to use it, in the cache, instead of
/// filling the whole estimate in memory first.
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

    /// the write position and the end of the writable space, for a writer
    /// that keeps the position in a local variable (set_cursor() hands it back)
    char* cursor() const noexcept
    {
        return m_pos;
    }

    char* limit() const noexcept
    {
        return m_end;
    }

    void set_cursor(char* p) noexcept
    {
        m_pos = p;
    }

  private:
    /// the size of a growth step (a function: std::min() takes a reference,
    /// which a static constexpr member does not have before C++17)
    static constexpr std::size_t step() noexcept
    {
        return 65536;
    }

    static StringType& sized(StringType& out, std::size_t estimate)
    {
        out.reserve(estimate);
        out.resize((std::min)((std::max)(estimate, static_cast<std::size_t>(64)), step()));
        return out;
    }

    NLOHMANN_VIEW_NOINLINE void grow(std::size_t n)
    {
        const auto used = static_cast<std::size_t>(m_pos - m_out.data());
        // (a step does not go beyond the reserved estimate, so that a good
        // estimate is never copied to a larger allocation)
        const std::size_t size = (std::max)((std::min)(m_out.size() + step(), m_out.capacity()), used + n + 256);
        if (size > m_out.capacity())
        {
            m_out.reserve((std::max)(m_out.capacity() * 2, size));
        }
        m_out.resize(size);
        m_pos = &m_out[0] + used;
        m_end = &m_out[0] + m_out.size();
    }

    StringType& m_out;
    char* m_pos;
    char* m_end;
};

/// The length of the run at s that dump() writes unchanged without
/// ensure_ascii: all bytes but quotes, backslashes, and control characters.
/// Unlike detail::string_bulk_run(), non-ASCII bytes are not validated: the
/// strings of a document are valid UTF-8 (a damaged image loaded with
/// image_check::bounds can have others, which are then written unchanged).
inline std::size_t plain_output_run(const unsigned char* s, std::size_t n) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        const std::uint64_t v = read_eight_bytes(s + i);
        const std::uint64_t q = v ^ 0x2222222222222222ull; // '"'
        const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull; // '\\'
        const std::uint64_t stop = (((q - ones) & ~q) | ((b - ones) & ~b) | ((v - 0x2020202020202020ull) & ~v)) & high;
        if (stop != 0)
        {
            // the lowest flagged byte is the first stop: borrows only flag bytes above a true one
            return i + (static_cast<std::size_t>(count_trailing_zeros(stop)) / 8);
        }
    }
    for (; i < n; ++i)
    {
        if (s[i] == '"' || s[i] == '\\' || s[i] < 0x20)
        {
            return i;
        }
    }
    return n;
}

/// A stack that starts in a buffer of the caller (a local array) and moves to
/// the heap (a vector of the caller) only when that is full, so that dumps of
/// shallow documents need no allocation. The top is a pointer, as in
/// std::vector. The address of the stack never escapes (the growth gets the
/// vector and returns the new storage), so its pointers stay in registers.
template<typename T>
class small_stack
{
  public:
    small_stack(T* buffer, std::size_t capacity, std::vector<T>& heap) noexcept
        : m_begin(buffer), m_top(buffer), m_end(buffer + capacity), m_heap(&heap)
    {}
    small_stack(const small_stack&) = delete;
    small_stack(small_stack&&) = delete;
    small_stack& operator=(const small_stack&) = delete;
    small_stack& operator=(small_stack&&) = delete;
    ~small_stack() = default;

    NLOHMANN_VIEW_ALWAYS_INLINE void push_back(const T& x)
    {
        if (NLOHMANN_VIEW_UNLIKELY(m_top == m_end))
        {
            const std::size_t used = size();
            const std::size_t capacity = 2 * static_cast<std::size_t>(m_end - m_begin);
            m_begin = grow(*m_heap, m_begin, used, capacity);
            m_top = m_begin + used;
            m_end = m_begin + capacity;
        }
        *m_top++ = x;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE T& back() noexcept
    {
        return m_top[-1];
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void pop_back() noexcept
    {
        --m_top;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE bool empty() const noexcept
    {
        return m_top == m_begin;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE std::size_t size() const noexcept
    {
        return static_cast<std::size_t>(m_top - m_begin);
    }

  private:
    /// the used entries moved to heap storage of the given capacity
    NLOHMANN_VIEW_NOINLINE static T* grow(std::vector<T>& heap, const T* begin, std::size_t used, std::size_t capacity)
    {
        std::vector<T> bigger(capacity);
        std::copy(begin, begin + used, bigger.begin());
        heap.swap(bigger);
        return heap.data();
    }

    T* m_begin;
    T* m_top;
    T* m_end;
    std::vector<T>* m_heap;
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
template<typename BasicJsonType, bool Editable>
class view_serializer
{
    using nav = navigation<Editable>;
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;

  public:
    view_serializer(const document_data& d, string_t& out, std::size_t estimate, const dump_style& style)
        : m_doc(d), m_out(out, estimate), m_style(style)
    {}

    void dump(const node* root)
    {
        if (!m_style.pretty && !m_style.ensure_ascii)
        {
            if (m_style.source_numbers)
            {
                dump_compact<true>(root);
            }
            else
            {
                dump_compact<false>(root);
            }
            return;
        }
        struct frame
        {
            const node* pos; ///< next element, or key of the next member
            const node* end;
            bool object;
            bool first;  ///< nothing written yet
        };
        std::array<frame, 32> buffer; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::vector<frame> heap;
        small_stack<frame> stack(buffer.data(), buffer.size(), heap);
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
                    stack.push_back(frame{nav::first(m_doc, n), nav::end(m_doc, n), object, true});
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
                    n = nav::value(f.pos + 1);
                    f.pos = document_data::after(f.pos + 1);
                }
                else
                {
                    n = nav::value(f.pos);
                    f.pos = document_data::after(f.pos);
                }
                break;
            }
        }
    }

  private:
    /*!
    @brief the compact output without ensure_ascii (the default dump())

    The same walk as dump(), with the write position in a local variable
    (stores through char pointers would otherwise force a reload of the
    buffer's members after each one), and with strings and number tokens of
    the source copied by fixed-size moves of 32 bytes where the source has
    that many bytes left, instead of a library call per token. The buffer
    keeps 64 bytes of slack for the overshoot.
    */
    /// a string that is not a plain string of the source (decoded, or written
    /// by an edit), without ensure_ascii: runs without characters to escape
    /// are copied
    NLOHMANN_VIEW_NOINLINE void write_decoded(const node& n)
    {
        const auto* const s = reinterpret_cast<const unsigned char*>(m_doc.str(n)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        m_out.put('"');
        for (std::size_t i = 0; i < n.len;)
        {
            const std::size_t run = plain_output_run(s + i, n.len - i);
            if (run != 0)
            {
                m_out.put(reinterpret_cast<const char*>(s + i), run); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                i += run;
                continue;
            }
            write_codepoint<false>(s[i], s + i, 1); // a quote, a backslash, or a control character
            ++i;
        }
        m_out.put('"');
    }

    /// the copies of dump_compact() that are not fixed-size moves (long
    /// strings, or near the end of the source); out of line, so that the
    /// compiler does not merge the fixed-size moves into this call
    NLOHMANN_VIEW_NOINLINE static void copy_long(char* to, const char* from, std::size_t n) noexcept
    {
        std::memcpy(to, from, n);
    }

    template<bool SourceNumbers>
    void dump_compact(const node* root)
    {
        struct frame
        {
            const node* pos; ///< (editable documents) next element, or key of the next member
            const node* end;
            bool object;
        };
        std::array<frame, 32> buffer; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::vector<frame> heap;
        small_stack<frame> stack(buffer.data(), buffer.size(), heap);
        const char* const src = m_doc.src;
        const char* const src_end = src + m_doc.size;
        char* w = m_out.cursor();
        char* lim = m_out.limit();
        // room for n bytes and the slack
        const auto room = [&](std::size_t n)
        {
            if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::size_t>(lim - w) < n + 64))
            {
                m_out.set_cursor(w);
                m_out.reserve(n + 64);
                w = m_out.cursor();
                lim = m_out.limit();
            }
        };
        // copy n bytes of the source (after room(n))
        const auto copy = [&](const char* from, std::size_t n)
        {
            if (n <= 32 && static_cast<std::size_t>(src_end - from) >= 32)
            {
                std::memcpy(w, from, 32);
            }
            else if (n <= 256 && static_cast<std::size_t>(src_end - from) >= n + 32)
            {
                for (std::size_t i = 0; i < n; i += 32)
                {
                    std::memcpy(w + i, from + i, 32);
                }
            }
            else
            {
                copy_long(w, from, n);
            }
            w += n;
        };
        // a literal of n bytes (after room(n))
        const auto literal = [&](const char* text, std::size_t n)
        {
            std::memcpy(w, text, n);
            w += n;
        };
        // a string that is not a plain string of the source (out of line, so
        // that the cursor stays in a register here)
        const auto escaped = [&](const node & n)
        {
            m_out.set_cursor(w);
            write_decoded(n);
            w = m_out.cursor();
            lim = m_out.limit();
        };

        // Read-only documents: the elements of a container follow it in the
        // node array, so the walk goes through the array in order, and a
        // frame only needs the end of its container. Editable documents: the
        // elements of a moved container live elsewhere, so a frame keeps the
        // position of the next element (see navigation).
        // The innermost open container is kept in registers (cur; end ==
        // nullptr: none), the stack holds the ones around it.
        frame cur{nullptr, nullptr, false};
        const node* n = root;
        for (;;)
        {
            // write the value at n (read-only documents: and advance n)
            bool opened = false;
            switch (static_cast<value_t>(n->kind))
            {
                case value_t::string:
                    if ((n->flags & node_flags::storage) == 0)
                    {
                        room(n->len + 2);
                        *w++ = '"';
                        copy(src + n->off, n->len);
                        *w++ = '"';
                    }
                    else
                    {
                        escaped(*n);
                    }
                    break;
                case value_t::number_integer:
                case value_t::number_unsigned:
                {
                    const std::uint32_t len = number_length(*n);
                    room(len);
                    if (Editable && (n->flags & node_flags::storage) != 0)
                    {
                        copy_long(w, m_doc.str(*n), len); // a canonical token written by an edit
                        w += len;
                        break;
                    }
                    const char* const token = src + n->off;
                    if (!SourceNumbers && NLOHMANN_VIEW_UNLIKELY(len == 2 && token[0] == '-' && token[1] == '0'))
                    {
                        *w++ = '0'; // parse() reads -0 as the integer 0
                    }
                    else
                    {
                        copy(token, len);
                    }
                    break;
                }
                case value_t::number_float:
                    if (SourceNumbers && (n->flags & node_flags::storage) != node_flags::edited)
                    {
                        room(n->len);
                        copy(src + n->off, n->len);
                    }
                    else if (std::is_same<number_float_t, double>::value)
                    {
                        room(64);
                        w = write_double_at(w, *n);
                    }
                    else
                    {
                        m_out.set_cursor(w);
                        write_float_node(*n);
                        w = m_out.cursor();
                        lim = m_out.limit();
                    }
                    break;
                case value_t::boolean:
                    room(8);
                    if ((n->flags & node_flags::is_true) != 0)
                    {
                        literal("true", 4);
                    }
                    else
                    {
                        literal("false", 5);
                    }
                    break;
                case value_t::object:
                case value_t::array:
                {
                    const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
                    room(8);
                    if (n->len == 0)
                    {
                        literal(object ? "{}" : "[]", 2);
                    }
                    else
                    {
                        *w++ = object ? '{' : '[';
                        stack.push_back(cur);
                        if (Editable)
                        {
                            cur = frame{nav::first(m_doc, n), nav::end(m_doc, n), object};
                        }
                        else
                        {
                            cur = frame{nullptr, n + n->next, object};
                        }
                        opened = true;
                    }
                    break;
                }
                case value_t::null:
                    room(8);
                    literal("null", 4);
                    break;
                case value_t::binary:    // LCOV_EXCL_LINE (not in a document)
                case value_t::discarded: // LCOV_EXCL_LINE
                default:                 // LCOV_EXCL_LINE
                    break;               // LCOV_EXCL_LINE
            }
            if (!Editable)
            {
                ++n; // the next node: the first element of an opened container, or the node after a scalar
            }

            // go to the next value: close finished containers, then separate
            // (a container just opened has an element)
            if (!opened)
            {
                for (;;)
                {
                    if (cur.end == nullptr)
                    {
                        m_out.set_cursor(w);
                        m_out.finish();
                        return;
                    }
                    if ((Editable ? cur.pos : n) != cur.end)
                    {
                        break;
                    }
                    room(1);
                    *w++ = cur.object ? '}' : ']';
                    cur = stack.back();
                    stack.pop_back();
                }
                room(1);
                *w++ = ',';
            }
            const node* const at = Editable ? cur.pos : n;
            if (cur.object)
            {
                const node& key = *at;
                if ((key.flags & node_flags::storage) == 0)
                {
                    room(key.len + 3);
                    *w++ = '"';
                    copy(src + key.off, key.len);
                    w[0] = '"';
                    w[1] = ':';
                    w += 2;
                }
                else
                {
                    escaped(key);
                    room(1);
                    *w++ = ':';
                }
                if (Editable)
                {
                    n = nav::value(at + 1);
                    cur.pos = document_data::after(at + 1);
                }
                else
                {
                    ++n;
                }
            }
            else if (Editable)
            {
                n = nav::value(at);
                cur.pos = document_data::after(at);
            }
        }
    }

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
                if (m_style.source_numbers && (n.flags & node_flags::storage) != node_flags::edited)
                {
                    m_out.put(m_doc.str(n), n.len); // (a float set by an edit is written as with shortest)
                }
                else
                {
                    write_float_node(n);
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

    /// a float node as dump() writes it
    void write_float_node(const node& n)
    {
        write_float_node(n, std::is_same<number_float_t, double> {});
    }

    void write_float_node(const node& n, std::false_type /*other*/)
    {
        write_float(float_value<number_float_t>(m_doc, n));
    }

    void write_float_node(const node& n, std::true_type /*double*/)
    {
        m_out.reserve(64);
        m_out.set_cursor(write_double_at(m_out.cursor(), n));
    }

    /*!
    @brief (doubles) the float at n as dump() writes it, at w (64 bytes of room)

    A token of at most 15 significant digits is written from its digits,
    without a conversion: two decimals of at most 15 digits are farther
    apart than the rounding interval of a (normal) double (the argument
    behind DBL_DIG), so the token's digits are the shortest ones of its
    double, which the library's conversion writes (Zmij). Other tokens are
    converted from the digits already read.
    */
    char* write_double_at(char* w, const node& n)
    {
        const unsigned int_digits = n.extra & 0xFFu;
        const unsigned frac_digits = n.extra >> 8u;
        if ((n.flags & node_flags::storage) != node_flags::edited && int_digits + frac_digits <= 19)
        {
            const auto* const first = reinterpret_cast<const unsigned char*>(m_doc.src + n.off); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            const float_significand d = layout_decimal(first, first + n.len, int_digits, frac_digits, reinterpret_cast<const unsigned char*>(m_doc.src + m_doc.size)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            // (the exponent keeps the value far from subnormals and overflow)
            if (d.w != 0 && d.w < 1000000000000000u && d.exponent >= -290 && d.exponent <= 290)
            {
                *w = '-';
                w += d.negative ? 1 : 0;
                // (without leading zeros, all digits of the token count)
                const unsigned char lead = first[d.negative ? 1 : 0];
                return lead != '0' ? ::nlohmann::detail::dtoa_impl::write_short_decimal(w, d.w, static_cast<int>(int_digits + frac_digits), static_cast<int>(d.exponent))
                       : ::nlohmann::detail::dtoa_impl::write_short_decimal(w, d.w, static_cast<int>(d.exponent));
            }
            return write_double_value_at(w, decimal_to_float<double>(d)); // (without reading the token again)
        }
        return write_double_value_at(w, static_cast<double>(float_value<number_float_t>(m_doc, n)));
    }

    /// n bytes of text at w
    static char* write_text_at(char* w, const char* text, std::size_t n) noexcept
    {
        std::memcpy(w, text, n);
        return w + n;
    }

    /// a double as dump() writes it, at w (64 bytes of room)
    static char* write_double_value_at(char* w, double x)
    {
        // (from the bits: without the checks of to_chars())
        std::uint64_t bits = 0;
        std::memcpy(&bits, &x, sizeof(bits));
        if (NLOHMANN_VIEW_UNLIKELY((bits & 0x7FF0000000000000u) == 0x7FF0000000000000u))
        {
            return write_text_at(w, "null", 4);
        }
        *w = '-';
        w += bits >> 63u;
        bits &= ~(std::uint64_t{1} << 63u);
        if (bits == 0)
        {
            return write_text_at(w, "0.0", 3);
        }
        return ::nlohmann::detail::dtoa_impl::write_shortest(w, ::nlohmann::detail::zmij::to_shortest(bits));
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
        if ((n.flags & node_flags::storage) == 0 && !m_style.ensure_ascii)
        {
            // a string of the source without escape sequences has nothing to escape
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

    /// as serializer::dump_escaped(); strings of a document are valid UTF-8,
    /// except in a damaged image loaded with image_check::bounds, for which
    /// this throws what basic_json::dump() throws for the string
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
            if (codepoint >= 0x80)
            {
                len = validate_one_utf8(s + i, n - i);
                if (NLOHMANN_VIEW_UNLIKELY(len == 0))
                {
                    invalid_utf8(s, n);
                    return;
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

    /// throw what basic_json::dump() throws for a string that is not valid UTF-8
    NLOHMANN_VIEW_NOINLINE static void invalid_utf8(const unsigned char* s, std::size_t n)
    {
        const string_t dumped = BasicJsonType(string_t(reinterpret_cast<const char*>(s), n)).dump(); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        static_cast<void>(dumped);
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
