//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2020 YaoYuan <https://github.com/ibireme/yyjson>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // find, find_if, max
#include <array> // array
#include <cstddef> // size_t, ptrdiff_t
#include <cstdint> // int64_t, uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcmp, memcpy
#include <limits> // numeric_limits
#include <string> // string
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/scan.hpp>

// The view's parser: one pass over the input that emits the node index (see
// node.hpp). The table-driven decoding of \u escapes and the fast paths for
// ": " and indentation follow yyjson (https://github.com/ibireme/yyjson, MIT
// license).

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

enum class error_code : std::uint8_t
{
    none,
    empty_input,
    unexpected_value,
    invalid_literal,
    expected_key,
    expected_colon,
    expected_array_end,
    expected_object_end,
    trailing_characters,
    number_after_minus,
    number_after_dot,
    number_after_exponent,
    number_overflow,
    string_missing_quote,
    string_control_character,
    string_utf8,
    string_escape,
    string_unicode_hex,
    string_surrogate_high,
    string_surrogate_low,
    comment_start,
    comment_unterminated,
    input_too_large,
};

struct parse_failure
{
    error_code code = error_code::none;
    std::size_t offset = 0; ///< byte offset of the offending character
};

/// FloatType: the number_float_t of the document, whose overflow parse() rejects
template<typename FloatType, bool Comments, bool TrailingCommas, bool NulIsEnd, bool Sentinel>
class builder
{
  public:
    builder(document_data& d, const char* src, std::size_t size) noexcept
        : doc(d)
        , b(reinterpret_cast<const unsigned char*>(src))
        , e(b + size)
    {}

    /// returns false and fills `failure` on error
    bool run()
    {
        cursor c(*this);
        return c.run();
    }

    builder(const builder&) = delete;
    builder& operator=(const builder&) = delete;
    builder(builder&&) = delete;
    builder& operator=(builder&&) = delete;
    ~builder() = default;

    /// where and why the parse failed (after run() returned false)
    const parse_failure& failure() const noexcept
    {
        return m_failure;
    }

  private:
    struct frame
    {
        std::uint32_t idx;
        std::uint32_t count;
        bool is_object;
    };

    document_data& doc;
    const unsigned char* const b;
    const unsigned char* const e;
    parse_failure m_failure{};

    // the open array/object is in the cursor; enclosing ones on a stack that is
    // inline for the first 64 levels
    frame shallow[64]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): not initialized on purpose; filled as containers open
    std::vector<frame> deep{};

    /// remember an object to index after parsing (out of line, so that the
    /// parse loop only has a call for it)
    NLOHMANN_VIEW_NOINLINE void note_large_object(std::uint32_t idx)
    {
        doc.large_objects.push_back(idx);
    }

    NLOHMANN_VIEW_NOINLINE bool fail(error_code c, const unsigned char* at) noexcept
    {
        m_failure.code = c;
        m_failure.offset = static_cast<std::size_t>(at - b);
        doc.tape_size = 0;
        return false;
    }

    /// a failure (recorded by fail) as a comment() result
    const unsigned char* fail_at(error_code c, const unsigned char* at) noexcept
    {
        fail(c, at);
        return nullptr;
    }

    /// a decoded string: p after its closing quote (nullptr: an error), and
    /// its bytes in the arena
    struct decoded
    {
        const unsigned char* p;
        std::size_t start;
        std::size_t len;
    };

    decoded failed(error_code c, const unsigned char* at) noexcept
    {
        fail(c, at);
        return decoded{nullptr, 0, 0};
    }

    /// the comment at p (*p == '/'): the position after it, or nullptr on error
    NLOHMANN_VIEW_NOINLINE const unsigned char* comment(const unsigned char* p)
    {
        if (e - p < 2)
        {
            ++p;
            return fail_at(error_code::comment_start, p);
        }
        if (p[1] == '/')
        {
            p += 2;
            // (as in parse(), a null byte is the end of the input, so it is
            // left for the caller to see)
            while (p != e && *p != '\n' && *p != '\r' && !(NulIsEnd && *p == 0))
            {
                ++p;
            }
            return p;
        }
        if (p[1] == '*')
        {
            p += 2;
            for (;;)
            {
                if (p == e || (NulIsEnd && *p == 0))
                {
                    return fail_at(error_code::comment_unterminated, p);
                }
                if (*p == '*' && p + 1 != e && p[1] == '/')
                {
                    p += 2;
                    return p;
                }
                ++p;
            }
        }
        ++p;
        return fail_at(error_code::comment_start, p);
    }

    /// the index is full (n nodes, parsed up to at): extrapolate the node
    /// count from the nodes per input byte so far (with headroom, and at least
    /// 1.5 times as many), so that dense inputs regrow once instead of
    /// doubling repeatedly; returns the new node array
    NLOHMANN_VIEW_NOINLINE node* grow(std::size_t n, const unsigned char* at)
    {
        const std::uint64_t done = static_cast<std::uint64_t>(at - b) + 1;
        const std::uint64_t guess = static_cast<std::uint64_t>(n) * static_cast<std::uint64_t>(e - b + 1) / done;
        const std::uint64_t grown = guess + (guess / 4) + 64; // a variable: GCC calls a cast of the sum useless where std::uint64_t is std::size_t
        doc.tape_size = n;
        doc.reserve((std::max)(static_cast<std::size_t>(grown), n + (n / 2) + 64));
        return doc.tape;
    }

    /// four hex digits at p as a code unit (p moves past them), or -1 (p at
    /// the first bad digit); one table lookup per digit and a single check,
    /// the four hex digits of a unicode escape (the library's table, after
    /// yyjson's read_hex_u16), or -1
    NLOHMANN_VIEW_ALWAYS_INLINE int hex4(const unsigned char*& p) noexcept
    {
        if (NLOHMANN_VIEW_LIKELY(e - p >= 4))
        {
            const int cp = hex_codepoint(p);
            if (NLOHMANN_VIEW_LIKELY(cp >= 0))
            {
                p += 4;
                return cp;
            }
        }
        p = hex4_error(p);
        return -1;
    }

    /// hex4() failed: the first bad digit (none: p)
    NLOHMANN_VIEW_NOINLINE const unsigned char* hex4_error(const unsigned char* p) noexcept
    {
        if (e - p >= 4)
        {
            while (is_hex(*p))
            {
                ++p;
            }
        }
        return p;
    }

    /// escapes present (or an error) in the string at s, scanned up to p:
    /// decode into the arena
    NLOHMANN_VIEW_NOINLINE decoded slow_string(const unsigned char* s, const unsigned char* p)
    {
        // single-character escapes; 0: invalid (and 'u', handled separately)
        static const std::array<char, 128> simple_escape =
        {
            {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, '"', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '/', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '\\', 0, 0, 0,
                0, 0, '\b', 0, 0, 0, '\f', 0, 0, 0, 0, 0, 0, 0, '\n', 0, 0, 0, '\r', 0, '\t', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }
        };
        const std::size_t start = arena_used();
        arena_run(s, static_cast<std::size_t>(p - s));
        for (;;)
        {
            if (p == e)
            {
                return failed(error_code::string_missing_quote, p);
            }
            const unsigned char c = *p;
            if (c == '"')
            {
                ++p;
                return decoded{p, start, arena_used() - start};
            }
            if (c != '\\')
            {
                // (a NUL before the end of the input is a control character, as
                // for json::parse, also where a NUL ends the input between values)
                return failed(c < 0x20 ? error_code::string_control_character : error_code::string_utf8, p);
            }
            ++p;
            if (p == e)
            {
                return failed(error_code::string_missing_quote, p);
            }
            const unsigned char d = *p++;
            arena_ensure(4);
            if (d == 'u')
            {
                int cp = hex4(p);
                if (NLOHMANN_VIEW_UNLIKELY(cp < 0))
                {
                    return failed(error_code::string_unicode_hex, p);
                }
                if (NLOHMANN_VIEW_UNLIKELY((cp & 0xF800) == 0xD800)) // a surrogate
                {
                    if (cp >= 0xDC00)
                    {
                        return failed(error_code::string_surrogate_low, p);
                    }
                    if (e - p < 2 || p[0] != '\\' || p[1] != 'u')
                    {
                        return failed(error_code::string_surrogate_high, p);
                    }
                    p += 2;
                    const int lo = hex4(p);
                    if (lo < 0)
                    {
                        return failed(error_code::string_unicode_hex, p);
                    }
                    if (lo < 0xDC00 || lo > 0xDFFF)
                    {
                        return failed(error_code::string_surrogate_high, p);
                    }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                aw = put_utf8(aw, cp);
            }
            else if (NLOHMANN_VIEW_LIKELY(d < 128 && simple_escape[d] != 0))
            {
                *aw++ = simple_escape[d];
            }
            else
            {
                --p;
                return failed(error_code::string_escape, p);
            }
            if (p != e && *p == '\\')
            {
                continue; // consecutive escapes ("\u00e4\u00f6"): no run in between
            }
            const unsigned char* const r = p;
            p = scan_string_run(p, e);
            arena_run(r, static_cast<std::size_t>(p - r));
        }
    }

    /// does the float token [s, p) overflow FloatType? (parse() rejects it)
    NLOHMANN_VIEW_NOINLINE static bool float_overflows(const unsigned char* s, const unsigned char* p)
    {
        const auto* const first = reinterpret_cast<const char*>(s); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto* const last = reinterpret_cast<const char*>(p); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const char* const dot = std::find(first, last, '.');
        const char* const exponent = std::find_if(first, last, [](char c)
        {
            return c == 'e' || c == 'E';
        });
        const auto v = convert_float<FloatType>(first, last, dot == last ? std::string::npos : static_cast<std::size_t>(dot - first),
                                                static_cast<std::size_t>(exponent - first));
        return v > (std::numeric_limits<FloatType>::max)() || v < -(std::numeric_limits<FloatType>::max)();
    }

    /// does the magnitude digits [d, d + n) exceed the given limit (same length)?
    static bool digits_exceed(const unsigned char* d, const char* limit, std::size_t n) noexcept
    {
        return std::memcmp(d, limit, n) > 0;
    }

    static bool is_hex(unsigned char c) noexcept
    {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    // decode arena: the std::string in the document, written through a raw
    // pointer (resized ahead in large steps; trimmed when parsing succeeds)
    char* aw = nullptr;
    char* aend = nullptr;

    NLOHMANN_VIEW_ALWAYS_INLINE std::size_t arena_used() const noexcept
    {
        return aw != nullptr ? static_cast<std::size_t>(aw - doc.arena.data()) : 0;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void arena_ensure(std::size_t n)
    {
        if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::size_t>(aend - aw) < n))
        {
            arena_grow(n);
        }
    }

    NLOHMANN_VIEW_NOINLINE void arena_grow(std::size_t n)
    {
        const std::size_t used = arena_used();
        doc.arena.resize((std::max)(doc.arena.size() * 2, used + n + 256));
        aw = &doc.arena[0] + used; // NOLINT(readability-container-data-pointer): data() is const before C++17
        aend = &doc.arena[0] + doc.arena.size(); // NOLINT(readability-container-data-pointer)
    }

    /// append the run [r, r + n) to the arena; short runs as one fixed-size
    /// 16-byte move when both sides have the room (no library call)
    NLOHMANN_VIEW_ALWAYS_INLINE void arena_run(const unsigned char* r, std::size_t n)
    {
        arena_ensure(n + 16);
        if (n <= 16 && e - r >= 16)
        {
            std::memcpy(aw, r, 16);
        }
        else
        {
            std::memcpy(aw, r, n);
        }
        aw += n;
    }

    /// UTF-8 encoding of cp at w (room for 4 bytes)
    static char* put_utf8(char* w, int cp) noexcept
    {
        if (cp < 0x80)
        {
            *w++ = static_cast<char>(cp);
        }
        else if (cp < 0x800)
        {
            *w++ = static_cast<char>(0xC0 | (cp >> 6));
            *w++ = static_cast<char>(0x80 | (cp & 0x3F));
        }
        else if (cp < 0x10000)
        {
            *w++ = static_cast<char>(0xE0 | (cp >> 12));
            *w++ = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            *w++ = static_cast<char>(0x80 | (cp & 0x3F));
        }
        else
        {
            *w++ = static_cast<char>(0xF0 | (cp >> 18));
            *w++ = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            *w++ = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            *w++ = static_cast<char>(0x80 | (cp & 0x3F));
        }
        return w;
    }

    /// a compile-time option as a runtime condition: testing the template
    /// argument directly makes a condition like `TrailingCommas && c == ']'`
    /// constant when the option is off, which MSVC reports as C4127
    static NLOHMANN_VIEW_ALWAYS_INLINE bool enabled(bool option) noexcept
    {
        return option;
    }

    /// The parse state and the parser proper. The cursor is a local object of
    /// run() whose address never escapes (everything it calls out of line is a
    /// member of the builder and gets the positions it needs), so that the
    /// compiler keeps the state in registers instead of reloading it from
    /// memory after every node store and call.
    struct cursor
    {
        explicit cursor(builder& owner) noexcept
            : cold(owner)
            , b(owner.b)
            , p(owner.b)
            , e(owner.e)
        {}

        builder& cold; ///< out-of-line helpers and state that needs no registers
        const unsigned char* const b;
        const unsigned char* p;
        const unsigned char* const e;
        node* base = nullptr;
        node* out = nullptr;
        node* cap = nullptr;

        // the open array/object
        std::uint32_t cur_idx = 0;
        std::uint32_t cur_count = 0;
        bool cur_is_object = false;
        std::size_t depth = 0;

        NLOHMANN_VIEW_ALWAYS_INLINE bool run()
        {
            cold.doc.reserve(estimate_nodes(reinterpret_cast<const char*>(b), static_cast<std::size_t>(e - b)));
            base = cold.doc.tape;
            out = base;
            cap = base + cold.doc.tape_cap;

            if (e - p >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
            {
                p += 3; // byte order mark
            }
            if (!ws())
            {
                return false;
            }
            if (p == e || (NulIsEnd && *p == 0))
            {
                return fail(error_code::empty_input);
            }

            // root value
            switch (cur())
            {
                case '{':
                    open(value_t::object);
                    ++p;
                    goto obj_first;
                case '[':
                    open(value_t::array);
                    ++p;
                    goto arr_first;
                default:
                    if (!scalar())
                    {
                        return false;
                    }
                    goto root_done;
            }

            // value dispatch, expanded once for array elements and once for member
            // values: each jump has its own history (arrays tend to hold one kind of
            // value), and the continuation needs no branch on the container kind
#define NLOHMANN_VIEW_VALUE(NEXT)                                                                   \
    switch (cur())                                                                              \
    {                                                                                           \
        case '"':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!string<true>())) { return false; }                \
            goto NEXT;                                                                          \
        case '{':                                                                               \
            open(value_t::object);                                                              \
            ++p;                                                                                \
            goto obj_first;                                                                     \
        case '[':                                                                               \
            open(value_t::array);                                                               \
            ++p;                                                                                \
            goto arr_first;                                                                     \
        case '-':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!number<true>())) { return false; }                      \
            goto NEXT;                                                                          \
        case '0': case '1': case '2': case '3':                                                 \
        case '4': case '5': case '6': case '7': case '8': case '9':                             \
            if (NLOHMANN_VIEW_UNLIKELY(!number<false>())) { return false; }                     \
            goto NEXT;                                                                          \
        case 't':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal("true", 4, value_t::boolean, node_flags::is_true))) { return false; } \
            goto NEXT;                                                                          \
        case 'f':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal_false())) { return false; }                     \
            goto NEXT;                                                                          \
        case 'n':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal("null", 4, value_t::null, 0))) { return false; } \
            goto NEXT;                                                                          \
        default:                                                                                \
            return fail(error_code::unexpected_value);                                          \
    }

arr_first:
            if (!ws())
            {
                return false;
            }
            if (cur() == ']')
            {
                ++p;
                goto close_container;
            }
value:
            NLOHMANN_VIEW_VALUE(arr_next)
arr_next:
            ++cur_count;
            if (!ws())
            {
                return false;
            }
            if (NLOHMANN_VIEW_LIKELY(cur() == ','))
            {
                ++p;
                if (!ws())
                {
                    return false;
                }
                if (enabled(TrailingCommas) && cur() == ']')
                {
                    ++p;
                    goto close_container;
                }
                goto value;
            }
            if (cur() == ']')
            {
                ++p;
                goto close_container;
            }
            return fail(error_code::expected_array_end);

obj_first:
            if (!ws())
            {
                return false;
            }
            if (cur() == '}')
            {
                ++p;
                goto close_container;
            }
obj_key:
            if (NLOHMANN_VIEW_UNLIKELY(cur() != '"'))
            {
                return fail(error_code::expected_key);
            }
            if (NLOHMANN_VIEW_UNLIKELY(!string<false>()))
            {
                return false;
            }
            if (NLOHMANN_VIEW_LIKELY(cur() == ':' && (Sentinel || e - p >= 2) && p[1] == ' '))
            {
                p += 2; // ": " (pretty-printed input; a fast path of yyjson)
            }
            else
            {
                if (!ws())
                {
                    return false;
                }
                if (NLOHMANN_VIEW_UNLIKELY(cur() != ':'))
                {
                    return fail(error_code::expected_colon);
                }
                ++p;
            }
            if (!ws())
            {
                return false;
            }
            NLOHMANN_VIEW_VALUE(obj_next)
obj_next:
            ++cur_count;
            if (!ws())
            {
                return false;
            }
            if (NLOHMANN_VIEW_LIKELY(cur() == ','))
            {
                ++p;
                if (!ws())
                {
                    return false;
                }
                if (enabled(TrailingCommas) && cur() == '}')
                {
                    ++p;
                    goto close_object;
                }
                goto obj_key;
            }
            if (cur() == '}')
            {
                ++p;
                goto close_object;
            }
            return fail(error_code::expected_object_end);

#undef NLOHMANN_VIEW_VALUE

close_object:
            // a large object gets a hash index (objects only, so that closing
            // an array pays nothing for this)
            if (NLOHMANN_VIEW_UNLIKELY(cur_count >= document_data::index_min_members))
            {
                cold.note_large_object(cur_idx);
            }

close_container:
            close();
            if (NLOHMANN_VIEW_UNLIKELY(depth == 0))
            {
                goto root_done;
            }
            if (cur_is_object)
            {
                goto obj_next;
            }
            goto arr_next;

root_done:
            if (!ws())
            {
                return false;
            }
            if (p != e && !(NulIsEnd && *p == 0))
            {
                return fail(error_code::trailing_characters);
            }
            cold.doc.tape_size = static_cast<std::size_t>(out - base);
            cold.doc.arena.resize(cold.arena_used());
            return true;
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool fail(error_code c) noexcept
        {
            return cold.fail(c, p);
        }

        /// the current byte, or 0 at the end. With a NUL-terminated input
        /// (Sentinel) the terminator is read instead of checking the bounds; a 0
        /// never matches a JSON token, so the error paths tell the end apart.
        NLOHMANN_VIEW_ALWAYS_INLINE unsigned char cur() const noexcept
        {
            if (Sentinel)
            {
                return *p;
            }
            return p != e ? *p : 0;
        }

        /// root scalar
        NLOHMANN_VIEW_ALWAYS_INLINE bool scalar()
        {
            switch (cur())
            {
                case '"':
                    return string<true>();
                case 't':
                    return literal("true", 4, value_t::boolean, node_flags::is_true);
                case 'f':
                    return literal_false();
                case 'n':
                    return literal("null", 4, value_t::null, 0);
                case '-':
                    return number<true>();
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    return number<false>();
                default:
                    return fail(error_code::unexpected_value);
            }
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool literal_false()
        {
            return literal("false", 5, value_t::boolean, 0);
        }

        /// skip whitespace (and comments); false on a malformed comment
        NLOHMANN_VIEW_ALWAYS_INLINE bool ws()
        {
            const unsigned char c = cur();
            if (NLOHMANN_VIEW_LIKELY(c > ' ' && (!Comments || c != '/')))
            {
                return true; // no whitespace: the common case in minified input
            }
            return ws_slow();
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool ws_slow()
        {
            for (;;)
            {
                if (cur() == ' ' && (Sentinel || e - p >= 2) && p[1] > ' ' && (!Comments || p[1] != '/'))
                {
                    ++p; // single space, e.g. after ':' or ','
                    return true;
                }
                if (cur() == '\n' || cur() == '\r')
                {
                    // (a branch, not an add of the comparison: p must not
                    // wait for the byte after the line break)
                    if (NLOHMANN_VIEW_UNLIKELY(cur() == '\r') && (Sentinel || e - p >= 2) && p[1] == '\n')
                    {
                        p += 2;
                    }
                    else
                    {
                        ++p;
                    }
                    // indentation: two spaces per step, fixed offsets (after yyjson)
                    while (e - p >= 32)
                    {
#define NLOHMANN_VIEW_STEP(i) if (NLOHMANN_VIEW_LIKELY(load16(p + (std::ptrdiff_t{2} * (i))) == 0x2020)) {} else { p += std::ptrdiff_t{2} * (i); goto indent_done; }
                        NLOHMANN_VIEW_REPEAT16(NLOHMANN_VIEW_STEP)
#undef NLOHMANN_VIEW_STEP
                        p += 32;
                    }
indent_done:
                    ;
                }
                for (unsigned char c = cur(); c == ' ' || c == '\n' || c == '\r' || c == '\t'; c = cur())
                {
                    ++p;
                }
                if (enabled(Comments) && cur() == '/')
                {
                    const unsigned char* const q = cold.comment(p);
                    if (q == nullptr)
                    {
                        return false;
                    }
                    p = q;
                    continue;
                }
                return true;
            }
        }

        /// append a node: (kind, flags, extra, off) and the second word (len, or
        /// an integer's value); two stores on little-endian targets
        NLOHMANN_VIEW_ALWAYS_INLINE node* emit(value_t k, std::uint8_t flags, std::uint16_t extra, std::size_t off, std::uint64_t second)
        {
            if (NLOHMANN_VIEW_UNLIKELY(out == cap))
            {
                const auto n = static_cast<std::size_t>(out - base);
                base = cold.grow(n, p);
                out = base + n;
                cap = base + cold.doc.tape_cap;
            }
            node* n = out++;
#if NLOHMANN_VIEW_LITTLE_ENDIAN
            const std::uint64_t first = static_cast<std::uint64_t>(k) | (static_cast<std::uint64_t>(flags) << 8)
                                        | (static_cast<std::uint64_t>(extra) << 16) | (static_cast<std::uint64_t>(off) << 32);
            std::memcpy(reinterpret_cast<unsigned char*>(n), &first, 8);
            std::memcpy(reinterpret_cast<unsigned char*>(n) + 8, &second, 8);
#else
            n->kind = static_cast<std::uint8_t>(k);
            n->flags = flags;
            n->extra = extra;
            n->off = static_cast<std::uint32_t>(off);
            set_integer_bits(*n, second);
#endif
            return n;
        }

        NLOHMANN_VIEW_ALWAYS_INLINE void open(value_t k)
        {
            const auto idx = static_cast<std::uint32_t>(emit(k, 0, 0, static_cast<std::size_t>(p - b), 0) - base);
            if (depth != 0)
            {
                if (NLOHMANN_VIEW_LIKELY(depth <= 64))
                {
                    // field by field: a frame put together on the stack and
                    // copied would be read back wider than it was written,
                    // and that load waits until the stores are done
                    frame& f = cold.shallow[depth - 1];
                    f.idx = cur_idx;
                    f.count = cur_count;
                    f.is_object = cur_is_object;
                }
                else
                {
                    cold.deep.push_back(frame{cur_idx, cur_count, cur_is_object});
                }
            }
            ++depth;
            cur_idx = idx;
            cur_count = 0;
            cur_is_object = k == value_t::object;
        }

        NLOHMANN_VIEW_ALWAYS_INLINE void close()
        {
            node& n = base[cur_idx];
            n.len = cur_count;
            n.next = static_cast<std::uint32_t>(out - base) - cur_idx;
            if (--depth != 0)
            {
                if (NLOHMANN_VIEW_LIKELY(depth <= 64))
                {
                    const frame& f = cold.shallow[depth - 1];
                    cur_idx = f.idx;
                    cur_count = f.count;
                    cur_is_object = f.is_object;
                }
                else
                {
                    const frame f = cold.deep.back();
                    cold.deep.pop_back();
                    cur_idx = f.idx;
                    cur_count = f.count;
                    cur_is_object = f.is_object;
                }
            }
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool literal(const char* text, std::size_t n, value_t k, std::uint8_t flags)
        {
            if (NLOHMANN_VIEW_UNLIKELY(e - p < static_cast<std::ptrdiff_t>(n) || std::memcmp(p, text, n) != 0))
            {
                return fail(error_code::invalid_literal);
            }
            emit(k, flags, 0, static_cast<std::size_t>(p - b), n);
            p += n;
            return true;
        }

        /// a number at p; the sign is known from the dispatch (so that p does
        /// not have to wait for the first byte)
        template<bool negative>
        NLOHMANN_VIEW_ALWAYS_INLINE bool number()
        {
            const unsigned char* const s = p;
            if (negative)
            {
                ++p;
            }
            const unsigned char* const int_start = p;
            if (p != e && *p == '0')
            {
                ++p;
            }
            else if (NLOHMANN_VIEW_LIKELY(p != e && *p >= '1' && *p <= '9'))
            {
                p = skip_digits(p + 1, e);
            }
            else
            {
                return fail(error_code::number_after_minus);
            }
            const auto int_digits = static_cast<std::size_t>(p - int_start);
            std::size_t frac_digits = 0;
            bool is_float = false;
            if (p != e && *p == '.')
            {
                ++p;
                const unsigned char* const f0 = p;
                p = skip_digits(p, e);
                if (NLOHMANN_VIEW_UNLIKELY(p == f0))
                {
                    return fail(error_code::number_after_dot);
                }
                frac_digits = static_cast<std::size_t>(p - f0);
                is_float = true;
            }
            std::int64_t exponent = 0;
            if (p != e && (*p | 0x20) == 'e')
            {
                ++p;
                bool exp_negative = false;
                if (p != e && (*p == '+' || *p == '-'))
                {
                    exp_negative = *p == '-';
                    ++p;
                }
                if (NLOHMANN_VIEW_UNLIKELY(p == e || !is_digit(*p)))
                {
                    return fail(error_code::number_after_exponent);
                }
                while (p != e && is_digit(*p))
                {
                    if (exponent < 100000)
                    {
                        exponent = (exponent * 10) + (*p - '0');
                    }
                    ++p;
                }
                if (exp_negative)
                {
                    exponent = -exponent;
                }
                is_float = true;
            }

            value_t kind = value_t::number_float;
            if (!is_float)
            {
                kind = negative ? value_t::number_integer : value_t::number_unsigned;
            }
            if (!is_float)
            {
                // integers that do not fit become floats, as in parse()
                if (NLOHMANN_VIEW_UNLIKELY(int_digits >= 19))
                {
                    if (negative)
                    {
                        if (int_digits > 19 || (int_digits == 19 && digits_exceed(int_start, "9223372036854775808", 19)))
                        {
                            kind = value_t::number_float;
                        }
                    }
                    else if (int_digits > 20 || (int_digits == 20 && digits_exceed(int_start, "18446744073709551615", 20)))
                    {
                        kind = value_t::number_float;
                    }
                }
            }
            // parse() rejects floats that overflow; only numbers whose magnitude
            // could reach the largest FloatType (1e308 for double, 1e38 for
            // float) need the conversion
            if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::int64_t>(int_digits) + exponent > std::numeric_limits<FloatType>::max_exponent10 - 8 && kind == value_t::number_float))
            {
                if (builder::float_overflows(s, p))
                {
                    p = s;
                    return fail(error_code::number_overflow);
                }
            }
            const auto layout = static_cast<std::uint16_t>((int_digits < 255 ? int_digits : 255) | ((frac_digits < 255 ? frac_digits : 255) << 8));
            auto second = static_cast<std::uint64_t>(p - s);
            if (kind != value_t::number_float)
            {
                // integers are converted now, while their digits are in cache
                const std::uint64_t m = int_digits <= 19 ? parse_upto19(int_start, static_cast<unsigned>(int_digits), e)
                                        : (parse_upto19(int_start, 19, e) * 10) + static_cast<std::uint64_t>(int_start[19] - '0');
                second = negative ? 0 - m : m;
            }
            emit(kind, 0, layout, static_cast<std::size_t>(s - b), second);
            return true;
        }

        /// a string at p: a value (Value) or a key
        template<bool Value>
        NLOHMANN_VIEW_ALWAYS_INLINE bool string()
        {
            ++p; // opening quote
            const unsigned char* const s = p;
            p = scan_string_run<Value>(p, e);
            if (NLOHMANN_VIEW_LIKELY(p != e && *p == '"'))
            {
                emit(value_t::string, 0, 0, static_cast<std::size_t>(s - b), static_cast<std::uint64_t>(p - s));
                ++p;
                return true;
            }
            const decoded r = cold.slow_string(s, p);
            if (r.p == nullptr)
            {
                return false;
            }
            p = r.p;
            emit(value_t::string, node_flags::escaped, 0, r.start, r.len);
            return true;
        }
    };
};

/// run the builder with compile-time options
template<typename FloatType, bool NulIsEnd, bool Comments, bool TrailingCommas>
inline bool build_with(document_data& d, const char* src, std::size_t size, bool sentinel, parse_failure& failure)
{
    if (sentinel)
    {
        builder<FloatType, Comments, TrailingCommas, NulIsEnd, true> bld(d, src, size);
        const bool ok = bld.run();
        failure = bld.failure();
        return ok;
    }
    builder<FloatType, Comments, TrailingCommas, NulIsEnd, false> bld(d, src, size);
    const bool ok = bld.run();
    failure = bld.failure();
    return ok;
}

/// sentinel: src[size] is readable and 0 (e.g. std::string); FloatType: the
/// number_float_t of the document
template<typename FloatType, bool NulIsEnd>
inline bool build(document_data& d, const char* src, std::size_t size, bool comments, bool trailing_commas, bool sentinel, parse_failure& failure)
{
    if (comments)
    {
        return trailing_commas ? build_with<FloatType, NulIsEnd, true, true>(d, src, size, sentinel, failure)
               : build_with<FloatType, NulIsEnd, true, false>(d, src, size, sentinel, failure);
    }
    return trailing_commas ? build_with<FloatType, NulIsEnd, false, true>(d, src, size, sentinel, failure)
           : build_with<FloatType, NulIsEnd, false, false>(d, src, size, sentinel, failure);
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
