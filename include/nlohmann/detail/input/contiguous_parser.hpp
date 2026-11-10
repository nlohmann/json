//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cmath> // isfinite
#include <cstddef> // size_t, ptrdiff_t
#include <cstdint> // uint64_t, int64_t
#include <cstring> // memcmp
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // integral_constant, true_type, false_type
#include <utility> // move
#include <vector> // vector

#include <nlohmann/detail/bit_ops.hpp>
#include <nlohmann/detail/input/input_adapters.hpp>
#include <nlohmann/detail/input/json_sax.hpp>
#include <nlohmann/detail/input/lexer.hpp>
#include <nlohmann/detail/input/number_parse.hpp>
#include <nlohmann/detail/input/parser.hpp>
#include <nlohmann/detail/input/string_scan.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/detected.hpp>
#include <nlohmann/detail/value_t.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief a parser for JSON text in one contiguous block, for parse(), accept(),
       and sax_parse()

The default parser and lexer exchange one token at a time, and the lexer keeps
its state (the current character, a pending unget, where the token starts) in
members, which every character pays for. This parser reads the block through a
local pointer instead, and the grammar, the whitespace and the tokens are one
loop, after yyjson's reader: the state stays in registers, and the expected
next token is tested where it is expected instead of being dispatched on.

It reports what it reads to a SAX handler: the one parse() uses to build the
value, the one accept() uses, or the user's handler of sax_parse(). On a byte
the default parser would reject, it stops before reporting the token, and
returns false: the events up to there are those the default parser reports.
The caller then runs the default parser on the same input to report the error
with its exact message and position (report_contiguous_error(),
json_sax_error_forwarder), and parse() builds no value from what was read.

What is accepted, and the values reported, are those of the default parser
with default options: the same number grammar and conversions, the same UTF-8
and escape rules, a UTF-8 byte order mark at the start, and, without
JSON_STRICT_NUL_HANDLING, a NUL byte as the end of the input.

@tparam KeepValues  whether the handler needs the values of strings and
                    numbers (false for accept(), whose handler ignores them)
*/
template<typename BasicJsonType, typename SAX, bool KeepValues>
class contiguous_parser
{
    using string_t = typename BasicJsonType::string_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using char_t = typename string_t::value_type;
    using uchar = unsigned char;

  public:
    contiguous_parser(const uchar* first, const uchar* last, SAX* sax_) noexcept
        : begin(first), end(last), sax(sax_)
    {}

    contiguous_parser(const contiguous_parser&) = delete;
    contiguous_parser(contiguous_parser&&) = delete;
    contiguous_parser& operator=(const contiguous_parser&) = delete;
    contiguous_parser& operator=(contiguous_parser&&) = delete;
    ~contiguous_parser() = default;

    /// whether the whole block is one valid JSON text; the handler has seen all of it
    JSON_HEDLEY_NEVER_INLINE bool parse()
    {
        const uchar* p = begin;
        const uchar* const e = end;

        if (p != e && *p == 0xEF)
        {
            // a byte order mark, or the lexer reports a bad one
            if (e - p < 3 || p[1] != 0xBB || p[2] != 0xBF)
            {
                return false;
            }
            p += 3;
        }

        // The open arrays and objects: bit 0 of `kinds` is the innermost (1:
        // object), so that the kind of the enclosing container is a shift away
        // and stays in a register; every 64 levels, the word is pushed to
        // `outer` and a new one is begun.
        std::uint64_t kinds = 0;
        std::size_t depth = 0;
        std::vector<std::uint64_t> outer;

        // the current byte, or 0 at the end (no JSON token starts with 0)
#define JSON_CONTIGUOUS_CUR() current(p, e)
        // skip whitespace; most tokens have none before them
#define JSON_CONTIGUOUS_WS()                                    \
    do                                                          \
    {                                                           \
        if (JSON_HEDLEY_UNLIKELY(JSON_CONTIGUOUS_CUR() <= ' ')) \
        {                                                       \
            p = skip_whitespace(p, e);                          \
        }                                                       \
    }                                                           \
    while (false)
#define JSON_CONTIGUOUS_OPEN(is_object)                                                             \
    do                                                                                              \
    {                                                                                               \
        if (JSON_HEDLEY_UNLIKELY(depth != 0 && (depth % 64) == 0)) /* NOLINT(readability/braces) */ \
        {                                                                                           \
            outer.push_back(kinds);                                                                 \
            kinds = 0;                                                                              \
        }                                                                                           \
        kinds = (kinds << 1u) | static_cast<std::uint64_t>(is_object);                              \
        ++depth;                                                                                    \
    }                                                                                               \
    while (false)

        JSON_CONTIGUOUS_WS();
        switch (JSON_CONTIGUOUS_CUR())
        {
            case '{':
                ++p;
                if (JSON_HEDLEY_UNLIKELY(!report(sax->start_object(detail::unknown_size()))))
                {
                    return false;
                }
                JSON_CONTIGUOUS_OPEN(1u);
                goto object_first;
            case '[':
                ++p;
                if (JSON_HEDLEY_UNLIKELY(!report(sax->start_array(detail::unknown_size()))))
                {
                    return false;
                }
                JSON_CONTIGUOUS_OPEN(0u);
                goto array_first;
            default:
                if (JSON_HEDLEY_UNLIKELY(!scalar(p)))
                {
                    return false;
                }
                goto done;
        }

        // a value in an array or an object: expanded once for each, so that
        // each dispatch has its own branch history (arrays tend to hold values
        // of one kind) and the code after a scalar knows where it is
#define JSON_CONTIGUOUS_VALUE                                                               \
    switch (JSON_CONTIGUOUS_CUR())                                                          \
    {                                                                                       \
        case '"':                                                                           \
            if (JSON_HEDLEY_UNLIKELY(!string(p, false)))                                    \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
            break;                                                                          \
        case '{':                                                                           \
            ++p;                                                                            \
            if (JSON_HEDLEY_UNLIKELY(!report(sax->start_object(detail::unknown_size()))))   \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
            JSON_CONTIGUOUS_OPEN(1u);                                                       \
            goto object_first;                                                              \
        case '[':                                                                           \
            ++p;                                                                            \
            if (JSON_HEDLEY_UNLIKELY(!report(sax->start_array(detail::unknown_size()))))    \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
            JSON_CONTIGUOUS_OPEN(0u);                                                       \
            goto array_first;                                                               \
        case '-':                                                                           \
        case '0':                                                                           \
        case '1':                                                                           \
        case '2':                                                                           \
        case '3':                                                                           \
        case '4':                                                                           \
        case '5':                                                                           \
        case '6':                                                                           \
        case '7':                                                                           \
        case '8':                                                                           \
        case '9':                                                                           \
            if (JSON_HEDLEY_UNLIKELY(!number(p)))                                           \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
            break;                                                                          \
        case 't':                                                                           \
            if (JSON_HEDLEY_UNLIKELY(!literal(p, "true") || !report(sax->boolean(true))))   \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
            break;                                                                          \
        case 'f':                                                                           \
            if (JSON_HEDLEY_UNLIKELY(!literal(p, "false") || !report(sax->boolean(false)))) \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
            break;                                                                          \
        case 'n':                                                                           \
            if (JSON_HEDLEY_UNLIKELY(!literal(p, "null") || !report(sax->null())))          \
            {                                                                               \
                return false;                                                               \
            }                                                                               \
            break;                                                                          \
        default:                                                                            \
            return false;                                                                   \
    }

        // what may follow a value in an array: a comma and the next value, or the end
#define JSON_CONTIGUOUS_AFTER_ELEMENT                                                      \
    JSON_CONTIGUOUS_WS();                                                                  \
    if (JSON_HEDLEY_LIKELY(JSON_CONTIGUOUS_CUR() == ',')) /* NOLINT(readability/braces) */ \
    {                                                                                      \
        ++p;                                                                               \
        JSON_CONTIGUOUS_WS();                                                              \
        goto array_value;                                                                  \
    }                                                                                      \
    if (JSON_HEDLEY_LIKELY(JSON_CONTIGUOUS_CUR() == ']')) /* NOLINT(readability/braces) */ \
    {                                                                                      \
        ++p;                                                                               \
        if (JSON_HEDLEY_UNLIKELY(!report(sax->end_array())))                               \
        {                                                                                  \
            return false;                                                                  \
        }                                                                                  \
        goto close;                                                                        \
    }                                                                                      \
    return false;

        // what may follow a value in an object: a comma and the next member, or the end
#define JSON_CONTIGUOUS_AFTER_MEMBER                                                       \
    JSON_CONTIGUOUS_WS();                                                                  \
    if (JSON_HEDLEY_LIKELY(JSON_CONTIGUOUS_CUR() == ',')) /* NOLINT(readability/braces) */ \
    {                                                                                      \
        ++p;                                                                               \
        JSON_CONTIGUOUS_WS();                                                              \
        goto object_key;                                                                   \
    }                                                                                      \
    if (JSON_HEDLEY_LIKELY(JSON_CONTIGUOUS_CUR() == '}')) /* NOLINT(readability/braces) */ \
    {                                                                                      \
        ++p;                                                                               \
        if (JSON_HEDLEY_UNLIKELY(!report(sax->end_object())))                              \
        {                                                                                  \
            return false;                                                                  \
        }                                                                                  \
        goto close;                                                                        \
    }                                                                                      \
    return false;

array_first:
        JSON_CONTIGUOUS_WS();
        if (JSON_CONTIGUOUS_CUR() == ']')
        {
            ++p;
            if (JSON_HEDLEY_UNLIKELY(!report(sax->end_array())))
            {
                return false;
            }
            goto close;
        }
array_value:
        JSON_CONTIGUOUS_VALUE
        JSON_CONTIGUOUS_AFTER_ELEMENT

object_first:
        JSON_CONTIGUOUS_WS();
        if (JSON_CONTIGUOUS_CUR() == '}')
        {
            ++p;
            if (JSON_HEDLEY_UNLIKELY(!report(sax->end_object())))
            {
                return false;
            }
            goto close;
        }
object_key:
        if (JSON_HEDLEY_UNLIKELY(JSON_CONTIGUOUS_CUR() != '"' || !string(p, true)))
        {
            return false;
        }
        if (JSON_HEDLEY_LIKELY(e - p >= 2 && p[0] == ':' && p[1] == ' '))
        {
            p += 2; // ": " (pretty-printed input; a fast path of yyjson)
        }
        else
        {
            JSON_CONTIGUOUS_WS();
            if (JSON_HEDLEY_UNLIKELY(JSON_CONTIGUOUS_CUR() != ':'))
            {
                return false;
            }
            ++p;
        }
        JSON_CONTIGUOUS_WS();
        JSON_CONTIGUOUS_VALUE
        JSON_CONTIGUOUS_AFTER_MEMBER

close:
        // an array or object was closed: continue in the enclosing one
        --depth;
        kinds >>= 1u;
        if (JSON_HEDLEY_UNLIKELY(depth == 0))
        {
            goto done;
        }
        if (JSON_HEDLEY_UNLIKELY((depth % 64) == 0))
        {
            kinds = outer.back();
            outer.pop_back();
        }
        if ((kinds & 1u) != 0)
        {
            JSON_CONTIGUOUS_AFTER_MEMBER
        }
        JSON_CONTIGUOUS_AFTER_ELEMENT

done:
        JSON_CONTIGUOUS_WS();
#if JSON_STRICT_NUL_HANDLING
        return p == e;
#else
        // a NUL byte ends the input, as in the lexer
        return p == e || *p == 0;
#endif

#undef JSON_CONTIGUOUS_AFTER_MEMBER
#undef JSON_CONTIGUOUS_AFTER_ELEMENT
#undef JSON_CONTIGUOUS_VALUE
#undef JSON_CONTIGUOUS_OPEN
#undef JSON_CONTIGUOUS_WS
#undef JSON_CONTIGUOUS_CUR
    }

    /// whether the handler stopped the parse (by returning false), as opposed
    /// to a syntax error
    bool aborted() const noexcept
    {
        return handler_stopped;
    }

  private:
    /// the result @a r of an event of the handler: false stops the parse
    bool report(const bool r) noexcept
    {
        handler_stopped = handler_stopped || !r;
        return r;
    }

    /// the text of the float token [@a first, @a last), for a handler that reads it
    const string_t& number_text(const char* first, const char* last)
    {
        return number_text(first, last, std::integral_constant<bool, sax_ignores_number_text<SAX>::value> {});
    }

    const string_t& number_text(const char* /*first*/, const char* /*last*/, std::true_type /*ignored*/) const noexcept
    {
        return no_text;
    }

    const string_t& number_text(const char* first, const char* last, std::false_type /*ignored*/)
    {
        float_text.clear();
        float_text.append(reinterpret_cast<const char_t*>(first), static_cast<std::size_t>(last - first));
        return float_text;
    }

    /// KeepValues as a runtime condition: testing the template argument
    /// directly makes `if` conditions constant, which MSVC reports as C4127
    static bool keep_values() noexcept
    {
        return KeepValues;
    }

    /// the byte at @a p, or 0 at the end @a e (no JSON token starts with 0)
    static JSON_HEDLEY_ALWAYS_INLINE uchar current(const uchar* p, const uchar* e) noexcept
    {
        return p != e ? *p : 0;
    }

    /// the first byte at or after p that is not whitespace, or e
    static JSON_HEDLEY_NEVER_INLINE const uchar* skip_whitespace(const uchar* p, const uchar* e) noexcept
    {
        while (p != e)
        {
            const uchar c = *p;
            if (c == ' ' || c == '\t' || c == '\r')
            {
                ++p;
            }
            else if (c == '\n')
            {
                // the indentation of the next line, 8 spaces at a time
                ++p;
                while (e - p >= 8)
                {
                    const std::uint64_t non_space = read_eight_bytes(p) ^ 0x2020202020202020ull;
                    if (non_space != 0)
                    {
                        p += static_cast<std::size_t>(count_trailing_zeros(non_space)) / 8;
                        break;
                    }
                    p += 8;
                }
            }
            else
            {
                break;
            }
        }
        return p;
    }

    /// the literal @a text at p, whose first byte the dispatch has seen
    template<std::size_t N>
    JSON_HEDLEY_ALWAYS_INLINE bool literal(const uchar*& p, const char (&text)[N]) const noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): a string literal
    {
        constexpr std::size_t length = N - 1;
        if (JSON_HEDLEY_UNLIKELY(static_cast<std::size_t>(end - p) < length || std::memcmp(p, text, length) != 0))
        {
            return false;
        }
        p += length;
        return true;
    }

    /// a JSON text that is a single scalar
    bool scalar(const uchar*& p)
    {
        switch (current(p, end))
        {
            case '"':
                return string(p, false);
            case '-':
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
                return number(p);
            case 't':
                return literal(p, "true") && report(sax->boolean(true));
            case 'f':
                return literal(p, "false") && report(sax->boolean(false));
            case 'n':
                return literal(p, "null") && report(sax->null());
            default:
                return false;
        }
    }

    /// the string whose opening quote is at p, reported as a key or a value;
    /// p is moved past the closing quote
    JSON_HEDLEY_ALWAYS_INLINE bool string(const uchar*& p, const bool is_key)
    {
        const uchar* const s = ++p;
        // the text up to the first quote, backslash, control character or
        // ill-formed UTF-8 (well-formed UTF-8 is part of the run)
        p = s + lexer_string_bulk_run(s, static_cast<std::size_t>(end - s));
        if (JSON_HEDLEY_LIKELY(p != end && *p == '"'))
        {
            if (keep_values())
            {
                buffer.clear();
                buffer.append(reinterpret_cast<const char_t*>(s), static_cast<std::size_t>(p - s));
            }
            ++p;
        }
        else if (JSON_HEDLEY_UNLIKELY(!escaped_string(s, p)))
        {
            return false;
        }
        return is_key ? report(sax->key(buffer)) : report(sax->string(buffer));
    }

    /// the rest of a string from p, a backslash, a control character,
    /// ill-formed UTF-8 or the end; s is where the string starts. With
    /// KeepValues, the string is decoded into buffer.
    JSON_HEDLEY_NEVER_INLINE bool escaped_string(const uchar* s, const uchar*& pos)
    {
        const uchar* p = pos;
        if (keep_values())
        {
            buffer.clear();
            buffer.append(reinterpret_cast<const char_t*>(s), static_cast<std::size_t>(p - s));
        }
        for (;;)
        {
            if (JSON_HEDLEY_UNLIKELY(p == end))
            {
                return false;
            }
            if (*p == '"')
            {
                pos = p + 1;
                return true;
            }
            if (JSON_HEDLEY_UNLIKELY(*p != '\\' || end - p < 2))
            {
                return false; // a control character or ill-formed UTF-8
            }
            const uchar escape = p[1];
            p += 2;
            switch (escape)
            {
                case '"':
                case '\\':
                case '/':
                    add(static_cast<char_t>(escape));
                    break;
                case 'b':
                    add('\b');
                    break;
                case 'f':
                    add('\f');
                    break;
                case 'n':
                    add('\n');
                    break;
                case 'r':
                    add('\r');
                    break;
                case 't':
                    add('\t');
                    break;
                case 'u':
                {
                    if (JSON_HEDLEY_UNLIKELY(end - p < 4))
                    {
                        return false;
                    }
                    int codepoint = hex_codepoint(p);
                    if (JSON_HEDLEY_UNLIKELY(codepoint < 0))
                    {
                        return false;
                    }
                    p += 4;
                    if (JSON_HEDLEY_UNLIKELY((codepoint & 0xF800) == 0xD800))
                    {
                        // a high surrogate must be followed by \u and a low surrogate
                        if (codepoint >= 0xDC00 || end - p < 6 || p[0] != '\\' || p[1] != 'u')
                        {
                            return false;
                        }
                        const int low = hex_codepoint(p + 2);
                        if (low < 0xDC00 || low > 0xDFFF)
                        {
                            return false;
                        }
                        p += 6;
                        codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00);
                    }
                    add_utf8(codepoint);
                    break;
                }
                default:
                    return false;
            }
            const uchar* const run = p;
            p = run + lexer_string_bulk_run(run, static_cast<std::size_t>(end - run));
            if (keep_values() && p != run)
            {
                buffer.append(reinterpret_cast<const char_t*>(run), static_cast<std::size_t>(p - run));
            }
        }
    }

    void add(const char_t c)
    {
        if (keep_values())
        {
            buffer.push_back(c);
        }
    }

    /// add the UTF-8 encoding of @a codepoint (at most U+10FFFF) to buffer
    void add_utf8(const int codepoint)
    {
        if (!keep_values())
        {
            return;
        }
        const auto cp = static_cast<unsigned>(codepoint);
        if (cp < 0x80)
        {
            buffer.push_back(static_cast<char_t>(cp));
        }
        else if (cp < 0x800)
        {
            buffer.push_back(static_cast<char_t>(0xC0u | (cp >> 6u)));
            buffer.push_back(static_cast<char_t>(0x80u | (cp & 0x3Fu)));
        }
        else if (cp < 0x10000)
        {
            buffer.push_back(static_cast<char_t>(0xE0u | (cp >> 12u)));
            buffer.push_back(static_cast<char_t>(0x80u | ((cp >> 6u) & 0x3Fu)));
            buffer.push_back(static_cast<char_t>(0x80u | (cp & 0x3Fu)));
        }
        else
        {
            buffer.push_back(static_cast<char_t>(0xF0u | (cp >> 18u)));
            buffer.push_back(static_cast<char_t>(0x80u | ((cp >> 12u) & 0x3Fu)));
            buffer.push_back(static_cast<char_t>(0x80u | ((cp >> 6u) & 0x3Fu)));
            buffer.push_back(static_cast<char_t>(0x80u | (cp & 0x3Fu)));
        }
    }

    /*!
    @brief the number at p, with the grammar and the conversions of the lexer's
           contiguous path (lexer::scan_number_bulk_contiguous())

    Integers that do not fit their type become floats; floats that overflow
    are an error, which the default parser reports.
    */
    JSON_HEDLEY_ALWAYS_INLINE bool number(const uchar*& pos)
    {
        const auto* const data = reinterpret_cast<const char*>(pos);
        const auto avail = static_cast<std::size_t>(end - pos);
        std::size_t i = 0;
        std::size_t dot_index = std::string::npos;
        bool is_float = false;
        std::uint64_t w = 0;
        const bool negative = data[0] == '-';
        if (negative)
        {
            i = 1;
        }
        const std::size_t integer_begin = i;
        if (i < avail && data[i] == '0')
        {
            ++i;
        }
        else if (i < avail && data[i] >= '1' && data[i] <= '9')
        {
            // accept() needs the value only for a float with a large exponent,
            // which computes it below; its handler ignores the values
            i = keep_values() ? accumulate_digits(data, i, avail, w) : skip_digits(data, i, avail);
        }
        else
        {
            return false;
        }
        std::size_t digit_count = i - integer_begin;
        std::size_t fraction_digits = 0;
        if (i < avail && data[i] == '.')
        {
            is_float = true;
            dot_index = i;
            ++i;
            if (i >= avail || !(data[i] >= '0' && data[i] <= '9'))
            {
                return false;
            }
            const std::size_t fraction_begin = i;
            i = keep_values() ? accumulate_digits(data, i, avail, w) : skip_digits(data, i, avail);
            fraction_digits = i - fraction_begin;
            digit_count += fraction_digits;
        }
        const std::size_t mantissa_end = i;
        std::int64_t exponent = 0;
        if (i < avail && (data[i] == 'e' || data[i] == 'E'))
        {
            is_float = true;
            ++i;
            bool negative_exponent = false;
            if (i < avail && (data[i] == '+' || data[i] == '-'))
            {
                negative_exponent = data[i] == '-';
                ++i;
            }
            if (i >= avail || !(data[i] >= '0' && data[i] <= '9'))
            {
                return false;
            }
            // saturated far beyond every range, see parse_float_exponent()
            constexpr std::int64_t saturation = 100000000000000000; // 10^17
            while (i < avail && data[i] >= '0' && data[i] <= '9')
            {
                if (exponent < saturation)
                {
                    exponent = (exponent * 10) + (data[i] - '0');
                }
                ++i;
            }
            exponent = negative_exponent ? -exponent : exponent;
        }
        pos += i;

        if (!is_float)
        {
            if (digit_count <= 18)
            {
                // up to 18 digits always fit into std::uint64_t and std::int64_t;
                // a narrower type takes the value only if it round-trips
                if (negative)
                {
                    const std::int64_t x = -static_cast<std::int64_t>(w);
                    const auto value = static_cast<number_integer_t>(x);
                    if (static_cast<std::int64_t>(value) == x)
                    {
                        return report(sax->number_integer(value));
                    }
                }
                else
                {
                    const auto value = static_cast<number_unsigned_t>(w);
                    if (static_cast<std::uint64_t>(value) == w)
                    {
                        return report(sax->number_unsigned(value));
                    }
                }
            }
            else if (negative)
            {
                number_integer_t value{};
                if (parse_integer_signed(data, data + i, value))
                {
                    return report(sax->number_integer(value));
                }
            }
            else
            {
                number_unsigned_t value{};
                if (parse_integer_unsigned(data, data + i, value))
                {
                    return report(sax->number_unsigned(value));
                }
            }
        }

        number_float_t value{};
        if (digit_count <= 19)
        {
            float_significand s;
            s.w = w;
            s.exponent = exponent - static_cast<std::int64_t>(fraction_digits);
            s.negative = negative;
            // accept() only needs to know that the value is finite: w < 10^19,
            // so only a token that may reach the largest float is converted
            if (!keep_values() && s.exponent + 19 <= std::numeric_limits<number_float_t>::max_exponent10)
            {
                return report(sax->number_float(value, number_text(data, data + i)));
            }
            if (!keep_values())
            {
                // the digits were skipped: their value now
                s.w = 0;
                const std::size_t integer_end = accumulate_digits(data, integer_begin, avail, s.w);
                if (dot_index != std::string::npos)
                {
                    static_cast<void>(accumulate_digits(data, integer_end + 1, avail, s.w));
                }
            }
            value = decimal_to_float<number_float_t>(s);
        }
        else
        {
            static_cast<void>(convert_float_fast(data, data + i, dot_index, mantissa_end, value));
        }
        if (JSON_HEDLEY_UNLIKELY(!std::isfinite(value)))
        {
            return false; // the default parser reports the overflow
        }
        return report(sax->number_float(value, number_text(data, data + i)));
    }

    const uchar* const begin;
    const uchar* const end;
    SAX* const sax;
    /// the current string (with KeepValues); the handler may move from it
    string_t buffer {};
    /// the text of float tokens, for the library's handlers, which ignore it
    const string_t no_text {};
    /// the text of the current float token, for other handlers
    string_t float_text {};
    /// whether the handler returned false
    bool handler_stopped = false;
};

/// whether parse() and accept() can read the input behind @a InputAdapterType
/// with contiguous_parser: one contiguous block of bytes (not a window into a
/// stream), and floats in a format the library converts itself
template<typename BasicJsonType, typename InputAdapterType>
struct can_parse_contiguous
{
    static constexpr bool value =
#if JSON_DIAGNOSTIC_POSITIONS
        // the values record the positions the lexer reports
        false &&
#endif
        input_adapter_supports_bulk_scan<InputAdapterType>(is_detected<detect_supports_bulk_scan, InputAdapterType> {})
        && !input_adapter_bulk_window<InputAdapterType>(is_detected<detect_bulk_window, InputAdapterType> {})
        && has_native_float_format<typename BasicJsonType::number_float_t>::value;
};

/*!
@brief report the input behind @a adapter, one block of memory, to @a sax

@return whether the input is valid and was reported completely; if not,
        nothing was consumed from @a adapter, and the caller has the default
        parser report the error
*/
template<typename BasicJsonType, bool KeepValues, typename SAX, typename InputAdapterType>
bool parse_contiguous(InputAdapterType& adapter, SAX& sax, std::true_type /*contiguous*/)
{
    const std::size_t size = adapter.bulk_remaining();
    if (size == 0)
    {
        return false; // the default parser reports the empty input
    }
    const auto* const first = reinterpret_cast<const unsigned char*>(adapter.bulk_data());
    contiguous_parser<BasicJsonType, SAX, KeepValues> p(first, first + size, &sax);
    return p.parse();
}

/*!
@brief a SAX handler that only reports a parse error, as the handler of parse()
       does: it throws the exception, unless exceptions are not allowed

After contiguous_parser has rejected an input, the default parser is run again
with this handler to report the error: the error, its message and its position
are those of parse(), without building the values read up to it.
*/
template<typename BasicJsonType>
class json_sax_error_reporter : public json_sax_acceptor<BasicJsonType>
{
  public:
    explicit json_sax_error_reporter(const bool allow_exceptions_) noexcept
        : allow_exceptions(allow_exceptions_)
    {}

    /// (a template, as in json_sax_dom_parser: the parser passes the concrete
    /// exception type, which is thrown as is)
    template<class Exception>
    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const Exception& ex)
    {
        static_cast<void>(ex); // (unused without exceptions)
        if (allow_exceptions)
        {
            JSON_THROW(ex);
        }
        return false;
    }

  private:
    const bool allow_exceptions;
};

template<typename BasicJsonType>
struct sax_ignores_number_text<json_sax_error_reporter<BasicJsonType>> : std::true_type {};

/*!
@brief report the error in the input behind @a adapter, which contiguous_parser
       rejected, as parse() reports it: throw its exception, or, without
       exceptions, return true

@return false if the default parser accepts the input after all (which would
        be a disagreement of the two parsers): the caller then parses it
*/
template<typename BasicJsonType, typename InputAdapterType>
bool report_contiguous_error(const InputAdapterType& adapter, const bool allow_exceptions)
{
    json_sax_error_reporter<BasicJsonType> reporter(allow_exceptions);
    // (a copy of the adapter, which the caller may need again)
    // (the lexer of parse(), which the fallback in basic_json::parse_impl()
    // instantiates anyway: only the grammar loop is instantiated again)
    return !parser<BasicJsonType, InputAdapterType>(InputAdapterType(adapter), nullptr, allow_exceptions, false, false).sax_parse(&reporter, true);
}

/*!
@brief parse(): parse the input behind @a adapter into @a result, if it is one
       block of memory

@return whether @a result is the result of parse(): the value, or, after an
        error and without exceptions, a discarded value (with exceptions, the
        error is thrown); false if the input is not one block of memory, in
        which case the caller parses it
*/
template<typename BasicJsonType, typename InputAdapterType>
bool parse_contiguous(InputAdapterType& adapter, BasicJsonType& result, const bool allow_exceptions, std::true_type /*contiguous*/)
{
    {
        // the handler of parser::parse(), so that the values are built by the same code
        json_sax_dom_parser<BasicJsonType, InputAdapterType, true> sax(result, true);
        if (parse_contiguous<BasicJsonType, true>(adapter, sax, std::true_type {}))
        {
            return true;
        }
    }
    // (what was read up to the error)
    result = BasicJsonType();
    if (report_contiguous_error<BasicJsonType>(adapter, allow_exceptions))
    {
        result = BasicJsonType(value_t::discarded);
        return true;
    }
    return false; // LCOV_EXCL_LINE (only if the two parsers disagree: a bug)
}

template<typename BasicJsonType, typename InputAdapterType>
bool parse_contiguous(InputAdapterType& /*adapter*/, BasicJsonType& /*result*/, const bool /*allow_exceptions*/, std::false_type /*contiguous*/) noexcept
{
    return false;
}

/*!
@brief accept(): check the input behind @a adapter, if it is one block of memory

@return whether @a accepted is the result of accept(); false if the input is
        not one block of memory, in which case the caller checks it.
        contiguous_parser accepts exactly what the default parser accepts.
*/
template<typename BasicJsonType, typename InputAdapterType>
bool accept_contiguous(InputAdapterType& adapter, bool& accepted, std::true_type /*contiguous*/)
{
    json_sax_acceptor<BasicJsonType> sax;
    accepted = parse_contiguous<BasicJsonType, false>(adapter, sax, std::true_type {});
    return true;
}

template<typename BasicJsonType, typename InputAdapterType>
bool accept_contiguous(InputAdapterType& /*adapter*/, bool& /*accepted*/, std::false_type /*contiguous*/) noexcept
{
    return false;
}

/*!
@brief a SAX handler that ignores the values and passes a parse error on to the
       handler of the user

After contiguous_parser has delivered the events of the input to the user's
handler and rejected it, the default parser is run again with this handler:
the user's handler gets the error, its message and its position from the
default parser, as before, but no event twice.
*/
template<typename BasicJsonType, typename SAX>
class json_sax_error_forwarder : public json_sax_acceptor<BasicJsonType>
{
  public:
    explicit json_sax_error_forwarder(SAX* user_) noexcept
        : user(user_)
    {}

    template<class Exception>
    bool parse_error(std::size_t position, const std::string& last_token, const Exception& ex)
    {
        forwarded = true;
        return user->parse_error(position, last_token, ex);
    }

    /// whether the default parser reported an error
    bool reported() const noexcept
    {
        return forwarded;
    }

  private:
    SAX* const user;
    bool forwarded = false;
};

template<typename BasicJsonType, typename SAX>
struct sax_ignores_number_text<json_sax_error_forwarder<BasicJsonType, SAX>> : std::true_type {};

/*!
@brief sax_parse() of JSON in one block of memory with the strict option and
       a user's handler @a sax

contiguous_parser reports to @a sax what it reads, and stops at the token that
the default parser would reject, before reporting it: the events up to an error
are the same. The error itself is then reported by the default parser (see
json_sax_error_forwarder).

@return whether @a result is the result of sax_parse(); false if the input is
        not one block of memory, in which case the caller parses it
*/
template<typename BasicJsonType, typename SAX, typename InputAdapterType>
bool sax_parse_contiguous(InputAdapterType& adapter, SAX* sax, bool& result, std::true_type /*contiguous*/)
{
    const std::size_t size = adapter.bulk_remaining();
    if (size != 0)
    {
        const auto* const first = reinterpret_cast<const unsigned char*>(adapter.bulk_data());
        contiguous_parser<BasicJsonType, SAX, true> p(first, first + size, sax);
        if (p.parse())
        {
            result = true;
            return true;
        }
        if (p.aborted())
        {
            // the handler returned false, as with the default parser
            result = false;
            return true;
        }
    }
    json_sax_error_forwarder<BasicJsonType, SAX> forwarder(sax);
    result = parser<BasicJsonType, InputAdapterType>(InputAdapterType(adapter), nullptr, true, false, false).sax_parse(&forwarder, true);
    // the default parser must reject the input as well (the events after the
    // byte contiguous_parser stopped at cannot be delivered any more)
    JSON_ASSERT(forwarder.reported());
    return true;
}

template<typename BasicJsonType, typename SAX, typename InputAdapterType>
bool sax_parse_contiguous(InputAdapterType& /*adapter*/, SAX* /*sax*/, bool& /*result*/, std::false_type /*contiguous*/) noexcept
{
    return false;
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
