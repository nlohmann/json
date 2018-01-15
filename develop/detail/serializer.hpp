#pragma once

#include <algorithm> // reverse, remove, fill, find, none_of
#include <array> // array
#include <cassert> // assert
#include <ciso646> // and, or
#include <clocale> // localeconv, lconv
#include <cmath> // labs, isfinite, isnan, signbit
#include <cstddef> // size_t, ptrdiff_t
#include <cstdint> // uint8_t
#include <cstdio> // snprintf
#include <iterator> // next
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // is_same

#include "detail/conversions/to_chars.hpp"
#include "detail/macro_scope.hpp"
#include "detail/meta.hpp"
#include "detail/parsing/output_adapters.hpp"
#include "detail/value_t.hpp"

namespace nlohmann
{
namespace detail
{
///////////////////
// serialization //
///////////////////

template<typename BasicJsonType>
class serializer
{
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
  public:
    /*!
    @param[in] s  output stream to serialize to
    @param[in] ichar  indentation character to use
    */
    serializer(output_adapter_t<char> s, const char ichar)
        : o(std::move(s)), loc(std::localeconv()),
          thousands_sep(loc->thousands_sep == nullptr ? '\0' : * (loc->thousands_sep)),
          decimal_point(loc->decimal_point == nullptr ? '\0' : * (loc->decimal_point)),
          indent_char(ichar), indent_string(512, indent_char) {}

    // delete because of pointer members
    serializer(const serializer&) = delete;
    serializer& operator=(const serializer&) = delete;

    /*!
    @brief internal implementation of the serialization function

    This function is called by the public member function dump and organizes
    the serialization internally. The indentation level is propagated as
    additional parameter. In case of arrays and objects, the function is
    called recursively.

    - strings and object keys are escaped using `escape_string()`
    - integer numbers are converted implicitly via `operator<<`
    - floating-point numbers are converted to a string using `"%g"` format

    @param[in] val             value to serialize
    @param[in] pretty_print    whether the output shall be pretty-printed
    @param[in] indent_step     the indent level
    @param[in] current_indent  the current indent level (only used internally)
    */
    void dump(const BasicJsonType& val, const bool pretty_print,
              const bool ensure_ascii,
              const unsigned int indent_step,
              const unsigned int current_indent = 0)
    {
        switch (val.m_type)
        {
            case value_t::object:
            {
                if (val.m_value.object->empty())
                {
                    o->write_characters("{}", 2);
                    return;
                }

                if (pretty_print)
                {
                    o->write_characters("{\n", 2);

                    // variable to hold indentation for recursive calls
                    const auto new_indent = current_indent + indent_step;
                    if (JSON_UNLIKELY(indent_string.size() < new_indent))
                    {
                        indent_string.resize(indent_string.size() * 2, ' ');
                    }

                    // first n-1 elements
                    auto i = val.m_value.object->cbegin();
                    for (std::size_t cnt = 0; cnt < val.m_value.object->size() - 1; ++cnt, ++i)
                    {
                        o->write_characters(indent_string.c_str(), new_indent);
                        o->write_character('\"');
                        dump_escaped(i->first, ensure_ascii);
                        o->write_characters("\": ", 3);
                        dump(i->second, true, ensure_ascii, indent_step, new_indent);
                        o->write_characters(",\n", 2);
                    }

                    // last element
                    assert(i != val.m_value.object->cend());
                    assert(std::next(i) == val.m_value.object->cend());
                    o->write_characters(indent_string.c_str(), new_indent);
                    o->write_character('\"');
                    dump_escaped(i->first, ensure_ascii);
                    o->write_characters("\": ", 3);
                    dump(i->second, true, ensure_ascii, indent_step, new_indent);

                    o->write_character('\n');
                    o->write_characters(indent_string.c_str(), current_indent);
                    o->write_character('}');
                }
                else
                {
                    o->write_character('{');

                    // first n-1 elements
                    auto i = val.m_value.object->cbegin();
                    for (std::size_t cnt = 0; cnt < val.m_value.object->size() - 1; ++cnt, ++i)
                    {
                        o->write_character('\"');
                        dump_escaped(i->first, ensure_ascii);
                        o->write_characters("\":", 2);
                        dump(i->second, false, ensure_ascii, indent_step, current_indent);
                        o->write_character(',');
                    }

                    // last element
                    assert(i != val.m_value.object->cend());
                    assert(std::next(i) == val.m_value.object->cend());
                    o->write_character('\"');
                    dump_escaped(i->first, ensure_ascii);
                    o->write_characters("\":", 2);
                    dump(i->second, false, ensure_ascii, indent_step, current_indent);

                    o->write_character('}');
                }

                return;
            }

            case value_t::array:
            {
                if (val.m_value.array->empty())
                {
                    o->write_characters("[]", 2);
                    return;
                }

                if (pretty_print)
                {
                    o->write_characters("[\n", 2);

                    // variable to hold indentation for recursive calls
                    const auto new_indent = current_indent + indent_step;
                    if (JSON_UNLIKELY(indent_string.size() < new_indent))
                    {
                        indent_string.resize(indent_string.size() * 2, ' ');
                    }

                    // first n-1 elements
                    for (auto i = val.m_value.array->cbegin();
                            i != val.m_value.array->cend() - 1; ++i)
                    {
                        o->write_characters(indent_string.c_str(), new_indent);
                        dump(*i, true, ensure_ascii, indent_step, new_indent);
                        o->write_characters(",\n", 2);
                    }

                    // last element
                    assert(not val.m_value.array->empty());
                    o->write_characters(indent_string.c_str(), new_indent);
                    dump(val.m_value.array->back(), true, ensure_ascii, indent_step, new_indent);

                    o->write_character('\n');
                    o->write_characters(indent_string.c_str(), current_indent);
                    o->write_character(']');
                }
                else
                {
                    o->write_character('[');

                    // first n-1 elements
                    for (auto i = val.m_value.array->cbegin();
                            i != val.m_value.array->cend() - 1; ++i)
                    {
                        dump(*i, false, ensure_ascii, indent_step, current_indent);
                        o->write_character(',');
                    }

                    // last element
                    assert(not val.m_value.array->empty());
                    dump(val.m_value.array->back(), false, ensure_ascii, indent_step, current_indent);

                    o->write_character(']');
                }

                return;
            }

            case value_t::string:
            {
                o->write_character('\"');
                dump_escaped(*val.m_value.string, ensure_ascii);
                o->write_character('\"');
                return;
            }

            case value_t::boolean:
            {
                if (val.m_value.boolean)
                {
                    o->write_characters("true", 4);
                }
                else
                {
                    o->write_characters("false", 5);
                }
                return;
            }

            case value_t::number_integer:
            {
                dump_integer(val.m_value.number_integer);
                return;
            }

            case value_t::number_unsigned:
            {
                dump_integer(val.m_value.number_unsigned);
                return;
            }

            case value_t::number_float:
            {
                dump_float(val.m_value.number_float);
                return;
            }

            case value_t::discarded:
            {
                o->write_characters("<discarded>", 11);
                return;
            }

            case value_t::null:
            {
                o->write_characters("null", 4);
                return;
            }
        }
    }

  private:
    /*!
    @brief returns the number of expected bytes following in UTF-8 string

    @param[in]  u  the first byte of a UTF-8 string
    @return  the number of expected bytes following
    */
    static constexpr std::size_t bytes_following(const uint8_t u)
    {
        return ((u <= 127) ? 0
                : ((192 <= u and u <= 223) ? 1
                   : ((224 <= u and u <= 239) ? 2
                      : ((240 <= u and u <= 247) ? 3 : std::string::npos))));
    }

    /*!
    @brief calculates the extra space to escape a JSON string

    @param[in] s  the string to escape
    @param[in] ensure_ascii  whether to escape non-ASCII characters with
                             \uXXXX sequences
    @return the number of characters required to escape string @a s

    @complexity Linear in the length of string @a s.
    */
    static std::size_t extra_space(const string_t& s,
                                   const bool ensure_ascii) noexcept
    {
        std::size_t res = 0;

        for (std::size_t i = 0; i < s.size(); ++i)
        {
            switch (s[i])
            {
                // control characters that can be escaped with a backslash
                case '"':
                case '\\':
                case '\b':
                case '\f':
                case '\n':
                case '\r':
                case '\t':
                {
                    // from c (1 byte) to \x (2 bytes)
                    res += 1;
                    break;
                }

                // control characters that need \uxxxx escaping
                case 0x00:
                case 0x01:
                case 0x02:
                case 0x03:
                case 0x04:
                case 0x05:
                case 0x06:
                case 0x07:
                case 0x0B:
                case 0x0E:
                case 0x0F:
                case 0x10:
                case 0x11:
                case 0x12:
                case 0x13:
                case 0x14:
                case 0x15:
                case 0x16:
                case 0x17:
                case 0x18:
                case 0x19:
                case 0x1A:
                case 0x1B:
                case 0x1C:
                case 0x1D:
                case 0x1E:
                case 0x1F:
                {
                    // from c (1 byte) to \uxxxx (6 bytes)
                    res += 5;
                    break;
                }

                default:
                {
                    if (ensure_ascii and (s[i] & 0x80 or s[i] == 0x7F))
                    {
                        const auto bytes = bytes_following(static_cast<uint8_t>(s[i]));
                        // invalid characters will be detected by throw_if_invalid_utf8
                        assert (bytes != std::string::npos);

                        if (bytes == 3)
                        {
                            // codepoints that need 4 bytes (i.e., 3 additional
                            // bytes) in UTF-8 need a surrogate pair when \u
                            // escaping is used: from 4 bytes to \uxxxx\uxxxx
                            // (12 bytes)
                            res += (12 - bytes - 1);
                        }
                        else
                        {
                            // from x bytes to \uxxxx (6 bytes)
                            res += (6 - bytes - 1);
                        }

                        // skip the additional bytes
                        i += bytes;
                    }
                    break;
                }
            }
        }

        return res;
    }

    static void escape_codepoint(int codepoint, string_t& result, std::size_t& pos)
    {
        // expecting a proper codepoint
        assert(0x00 <= codepoint and codepoint <= 0x10FFFF);

        // the last written character was the backslash before the 'u'
        assert(result[pos] == '\\');

        // write the 'u'
        result[++pos] = 'u';

        // convert a number 0..15 to its hex representation (0..f)
        static const std::array<char, 16> hexify =
        {
            {
                '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
            }
        };

        if (codepoint < 0x10000)
        {
            // codepoints U+0000..U+FFFF can be represented as \uxxxx.
            result[++pos] = hexify[(codepoint >> 12) & 0x0F];
            result[++pos] = hexify[(codepoint >> 8) & 0x0F];
            result[++pos] = hexify[(codepoint >> 4) & 0x0F];
            result[++pos] = hexify[codepoint & 0x0F];
        }
        else
        {
            // codepoints U+10000..U+10FFFF need a surrogate pair to be
            // represented as \uxxxx\uxxxx.
            // http://www.unicode.org/faq/utf_bom.html#utf16-4
            codepoint -= 0x10000;
            const int high_surrogate = 0xD800 | ((codepoint >> 10) & 0x3FF);
            const int low_surrogate = 0xDC00 | (codepoint & 0x3FF);
            result[++pos] = hexify[(high_surrogate >> 12) & 0x0F];
            result[++pos] = hexify[(high_surrogate >> 8) & 0x0F];
            result[++pos] = hexify[(high_surrogate >> 4) & 0x0F];
            result[++pos] = hexify[high_surrogate & 0x0F];
            ++pos;  // backslash is already in output
            result[++pos] = 'u';
            result[++pos] = hexify[(low_surrogate >> 12) & 0x0F];
            result[++pos] = hexify[(low_surrogate >> 8) & 0x0F];
            result[++pos] = hexify[(low_surrogate >> 4) & 0x0F];
            result[++pos] = hexify[low_surrogate & 0x0F];
        }

        ++pos;
    }

    /*!
    @brief dump escaped string

    Escape a string by replacing certain special characters by a sequence of an
    escape character (backslash) and another character and other control
    characters by a sequence of "\u" followed by a four-digit hex
    representation. The escaped string is written to output stream @a o.

    @param[in] s  the string to escape
    @param[in] ensure_ascii  whether to escape non-ASCII characters with
                             \uXXXX sequences

    @complexity Linear in the length of string @a s.
    */
    void dump_escaped(const string_t& s, const bool ensure_ascii) const
    {
        throw_if_invalid_utf8(s);

        const auto space = extra_space(s, ensure_ascii);
        if (space == 0)
        {
            o->write_characters(s.c_str(), s.size());
            return;
        }

        // create a result string of necessary size
        string_t result(s.size() + space, '\\');
        std::size_t pos = 0;

        for (std::size_t i = 0; i < s.size(); ++i)
        {
            switch (s[i])
            {
                case '"': // quotation mark (0x22)
                {
                    result[pos + 1] = '"';
                    pos += 2;
                    break;
                }

                case '\\': // reverse solidus (0x5C)
                {
                    // nothing to change
                    pos += 2;
                    break;
                }

                case '\b': // backspace (0x08)
                {
                    result[pos + 1] = 'b';
                    pos += 2;
                    break;
                }

                case '\f': // formfeed (0x0C)
                {
                    result[pos + 1] = 'f';
                    pos += 2;
                    break;
                }

                case '\n': // newline (0x0A)
                {
                    result[pos + 1] = 'n';
                    pos += 2;
                    break;
                }

                case '\r': // carriage return (0x0D)
                {
                    result[pos + 1] = 'r';
                    pos += 2;
                    break;
                }

                case '\t': // horizontal tab (0x09)
                {
                    result[pos + 1] = 't';
                    pos += 2;
                    break;
                }

                default:
                {
                    // escape control characters (0x00..0x1F) or, if
                    // ensure_ascii parameter is used, non-ASCII characters
                    if ((0x00 <= s[i] and s[i] <= 0x1F) or
                            (ensure_ascii and (s[i] & 0x80 or s[i] == 0x7F)))
                    {
                        const auto bytes = bytes_following(static_cast<uint8_t>(s[i]));
                        // invalid characters will be detected by throw_if_invalid_utf8
                        assert (bytes != std::string::npos);

                        // check that the additional bytes are present
                        assert(i + bytes < s.size());

                        // to use \uxxxx escaping, we first need to calculate
                        // the codepoint from the UTF-8 bytes
                        int codepoint = 0;

                        // bytes is unsigned type:
                        assert(bytes <= 3);
                        switch (bytes)
                        {
                            case 0:
                            {
                                codepoint = s[i] & 0xFF;
                                break;
                            }

                            case 1:
                            {
                                codepoint = ((s[i] & 0x3F) << 6)
                                            + (s[i + 1] & 0x7F);
                                break;
                            }

                            case 2:
                            {
                                codepoint = ((s[i] & 0x1F) << 12)
                                            + ((s[i + 1] & 0x7F) << 6)
                                            + (s[i + 2] & 0x7F);
                                break;
                            }

                            case 3:
                            {
                                codepoint = ((s[i] & 0xF) << 18)
                                            + ((s[i + 1] & 0x7F) << 12)
                                            + ((s[i + 2] & 0x7F) << 6)
                                            + (s[i + 3] & 0x7F);
                                break;
                            }

                            default:
                                break;  // LCOV_EXCL_LINE
                        }

                        escape_codepoint(codepoint, result, pos);
                        i += bytes;
                    }
                    else
                    {
                        // all other characters are added as-is
                        result[pos++] = s[i];
                    }
                    break;
                }
            }
        }

        assert(pos == result.size());
        o->write_characters(result.c_str(), result.size());
    }

    /*!
    @brief dump an integer

    Dump a given integer to output stream @a o. Works internally with
    @a number_buffer.

    @param[in] x  integer number (signed or unsigned) to dump
    @tparam NumberType either @a number_integer_t or @a number_unsigned_t
    */
    template<typename NumberType, detail::enable_if_t<
                 std::is_same<NumberType, number_unsigned_t>::value or
                 std::is_same<NumberType, number_integer_t>::value,
                 int> = 0>
    void dump_integer(NumberType x)
    {
        // special case for "0"
        if (x == 0)
        {
            o->write_character('0');
            return;
        }

        const bool is_negative = (x <= 0) and (x != 0);  // see issue #755
        std::size_t i = 0;

        while (x != 0)
        {
            // spare 1 byte for '\0'
            assert(i < number_buffer.size() - 1);

            const auto digit = std::labs(static_cast<long>(x % 10));
            number_buffer[i++] = static_cast<char>('0' + digit);
            x /= 10;
        }

        if (is_negative)
        {
            // make sure there is capacity for the '-'
            assert(i < number_buffer.size() - 2);
            number_buffer[i++] = '-';
        }

        std::reverse(number_buffer.begin(), number_buffer.begin() + i);
        o->write_characters(number_buffer.data(), i);
    }

    /*!
    @brief dump a floating-point number

    Dump a given floating-point number to output stream @a o. Works internally
    with @a number_buffer.

    @param[in] x  floating-point number to dump
    */
    void dump_float(number_float_t x)
    {
        // NaN / inf
        if (not std::isfinite(x))
        {
            o->write_characters("null", 4);
            return;
        }

        // If number_float_t is an IEEE-754 single or double precision number,
        // use the Grisu2 algorithm to produce short numbers which are guaranteed
        // to round-trip, using strtof and strtod, resp.
        //
        // NB: The test below works if <long double> == <double>.
        static constexpr bool is_ieee_single_or_double
            = (std::numeric_limits<number_float_t>::is_iec559 and std::numeric_limits<number_float_t>::digits == 24 and std::numeric_limits<number_float_t>::max_exponent == 128) or
              (std::numeric_limits<number_float_t>::is_iec559 and std::numeric_limits<number_float_t>::digits == 53 and std::numeric_limits<number_float_t>::max_exponent == 1024);

        dump_float(x, std::integral_constant<bool, is_ieee_single_or_double>());
    }

    void dump_float(number_float_t x, std::true_type /*is_ieee_single_or_double*/)
    {
        char* begin = number_buffer.data();
        char* end = ::nlohmann::detail::to_chars(begin, begin + number_buffer.size(), x);

        o->write_characters(begin, static_cast<size_t>(end - begin));
    }

    void dump_float(number_float_t x, std::false_type /*is_ieee_single_or_double*/)
    {
        // get number of digits for a float -> text -> float round-trip
        static constexpr auto d = std::numeric_limits<number_float_t>::max_digits10;

        // the actual conversion
        std::ptrdiff_t len = snprintf(number_buffer.data(), number_buffer.size(), "%.*g", d, x);

        // negative value indicates an error
        assert(len > 0);
        // check if buffer was large enough
        assert(static_cast<std::size_t>(len) < number_buffer.size());

        // erase thousands separator
        if (thousands_sep != '\0')
        {
            const auto end = std::remove(number_buffer.begin(),
                                         number_buffer.begin() + len, thousands_sep);
            std::fill(end, number_buffer.end(), '\0');
            assert((end - number_buffer.begin()) <= len);
            len = (end - number_buffer.begin());
        }

        // convert decimal point to '.'
        if (decimal_point != '\0' and decimal_point != '.')
        {
            const auto dec_pos = std::find(number_buffer.begin(), number_buffer.end(), decimal_point);
            if (dec_pos != number_buffer.end())
            {
                *dec_pos = '.';
            }
        }

        o->write_characters(number_buffer.data(), static_cast<std::size_t>(len));

        // determine if need to append ".0"
        const bool value_is_int_like =
            std::none_of(number_buffer.begin(), number_buffer.begin() + len + 1,
                         [](char c)
        {
            return (c == '.' or c == 'e');
        });

        if (value_is_int_like)
        {
            o->write_characters(".0", 2);
        }
    }

    /*!
    @brief check whether a string is UTF-8 encoded

    The function checks each byte of a string whether it is UTF-8 encoded. The
    result of the check is stored in the @a state parameter. The function must
    be called initially with state 0 (accept). State 1 means the string must
    be rejected, because the current byte is not allowed. If the string is
    completely processed, but the state is non-zero, the string ended
    prematurely; that is, the last byte indicated more bytes should have
    followed.

    @param[in,out] state  the state of the decoding
    @param[in] byte       next byte to decode

    @note The function has been edited: a std::array is used and the code
          point is not calculated.

    @copyright Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>
    @sa http://bjoern.hoehrmann.de/utf-8/decoder/dfa/
    */
    static void decode(uint8_t& state, const uint8_t byte)
    {
        static const std::array<uint8_t, 400> utf8d =
        {
            {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 00..1F
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20..3F
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 40..5F
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 60..7F
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, // 80..9F
                7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // A0..BF
                8, 8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // C0..DF
                0xA, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x4, 0x3, 0x3, // E0..EF
                0xB, 0x6, 0x6, 0x6, 0x5, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, // F0..FF
                0x0, 0x1, 0x2, 0x3, 0x5, 0x8, 0x7, 0x1, 0x1, 0x1, 0x4, 0x6, 0x1, 0x1, 0x1, 0x1, // s0..s0
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, // s1..s2
                1, 2, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, // s3..s4
                1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1, // s5..s6
                1, 3, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 // s7..s8
            }
        };

        const uint8_t type = utf8d[byte];
        state = utf8d[256u + state * 16u + type];
    }

    /*!
    @brief throw an exception if a string is not UTF-8 encoded

    @param[in] str  UTF-8 string to check
    @throw type_error.316 if passed string is not UTF-8 encoded

    @since version 3.0.0
    */
    static void throw_if_invalid_utf8(const std::string& str)
    {
        // start with state 0 (= accept)
        uint8_t state = 0;

        for (size_t i = 0; i < str.size(); ++i)
        {
            const auto byte = static_cast<uint8_t>(str[i]);
            decode(state, byte);
            if (state == 1)
            {
                // state 1 means reject
                std::stringstream ss;
                ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << static_cast<int>(byte);
                JSON_THROW(type_error::create(316, "invalid UTF-8 byte at index " + std::to_string(i) + ": 0x" + ss.str()));
            }
        }

        if (state != 0)
        {
            // we finish reading, but do not accept: string was incomplete
            std::stringstream ss;
            ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << static_cast<int>(static_cast<uint8_t>(str.back()));
            JSON_THROW(type_error::create(316, "incomplete UTF-8 string; last byte: 0x" + ss.str()));
        }
    }

  private:
    /// the output of the serializer
    output_adapter_t<char> o = nullptr;

    /// a (hopefully) large enough character buffer
    std::array<char, 64> number_buffer{{}};

    /// the locale
    const std::lconv* loc = nullptr;
    /// the locale's thousand separator character
    const char thousands_sep = '\0';
    /// the locale's decimal point character
    const char decimal_point = '\0';

    /// the indentation character
    const char indent_char;

    /// the indentation string
    string_t indent_string;
};
}
}
