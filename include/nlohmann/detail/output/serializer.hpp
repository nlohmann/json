#pragma once

#include <algorithm> // reverse, remove, fill, find, none_of
#include <array> // array
#include <clocale> // localeconv, lconv
#include <cmath> // labs, isfinite, isnan, signbit
#include <cstddef> // size_t, ptrdiff_t
#include <cstdint> // uint8_t
#include <cstdio> // snprintf
#include <limits> // numeric_limits
#include <string> // string, char_traits
#include <iomanip> // setfill, setw
#include <sstream> // stringstream
#include <type_traits> // is_same
#include <utility> // move

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/output/binary_writer.hpp>
#include <nlohmann/detail/output/output_adapters.hpp>
#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/detail/output/denumerizer.hpp>

namespace nlohmann
{
namespace detail
{
///////////////////
// serialization //
///////////////////

/// how to treat decoding errors
enum class error_handler_t
{
    strict,  ///< throw a type_error exception in case of invalid UTF-8
    replace, ///< replace invalid UTF-8 sequences with U+FFFD
    ignore   ///< ignore invalid UTF-8 sequences
};

template<typename BasicJsonType, typename DenumerizerType = denumerizer>
class serializer
{
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using binary_char_t = typename BasicJsonType::binary_t::value_type;
    static constexpr std::uint8_t UTF8_ACCEPT = 0;
    static constexpr std::uint8_t UTF8_REJECT = 1;

  public:
    /*!
    @param[in] s  output stream to serialize to
    @param[in] ichar  indentation character to use
    @param[in] error_handler_  how to react on decoding errors
    */
    serializer(output_adapter_t<char> s, const char ichar,
               error_handler_t error_handler_ = error_handler_t::strict)
        : o(std::move(s))
        , indent_char(ichar)
        , indent_string(512, indent_char)
        , error_handler(error_handler_)
    {}

    // delete because of pointer members
    serializer(const serializer&) = delete;
    serializer& operator=(const serializer&) = delete;
    serializer(serializer&&) = delete;
    serializer& operator=(serializer&&) = delete;
    ~serializer() = default;

    /*!
    @brief internal implementation of the serialization function

    This function is called by the public member function dump and organizes
    the serialization internally. The indentation level is propagated as
    additional parameter. In case of arrays and objects, the function is
    called recursively.

    - strings and object keys are escaped using `escape_string()`
    - integer numbers are converted implicitly via `operator<<`
    - floating-point numbers are converted to a string using `"%g"` format
    - binary values are serialized as objects containing the subtype and the
      byte array

    @param[in] val               value to serialize
    @param[in] pretty_print      whether the output shall be pretty-printed
    @param[in] ensure_ascii If @a ensure_ascii is true, all non-ASCII characters
    in the output are escaped with `\uXXXX` sequences, and the result consists
    of ASCII characters only.
    @param[in] indent_step       the indent level
    @param[in] current_indent    the current indent level (only used internally)
    */
    void dump(const BasicJsonType& val,
              const bool pretty_print,
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
                    if (JSON_HEDLEY_UNLIKELY(indent_string.size() < new_indent))
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
                    JSON_ASSERT(i != val.m_value.object->cend());
                    JSON_ASSERT(std::next(i) == val.m_value.object->cend());
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
                    JSON_ASSERT(i != val.m_value.object->cend());
                    JSON_ASSERT(std::next(i) == val.m_value.object->cend());
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
                    if (JSON_HEDLEY_UNLIKELY(indent_string.size() < new_indent))
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
                    JSON_ASSERT(!val.m_value.array->empty());
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
                    JSON_ASSERT(!val.m_value.array->empty());
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

            case value_t::binary:
            {
                if (pretty_print)
                {
                    o->write_characters("{\n", 2);

                    // variable to hold indentation for recursive calls
                    const auto new_indent = current_indent + indent_step;
                    if (JSON_HEDLEY_UNLIKELY(indent_string.size() < new_indent))
                    {
                        indent_string.resize(indent_string.size() * 2, ' ');
                    }

                    o->write_characters(indent_string.c_str(), new_indent);

                    o->write_characters("\"bytes\": [", 10);

                    if (!val.m_value.binary->empty())
                    {
                        for (auto i = val.m_value.binary->cbegin();
                                i != val.m_value.binary->cend() - 1; ++i)
                        {
                            DenumerizerType::dump_integer(o, *i);
                            o->write_characters(", ", 2);
                        }
                        DenumerizerType::dump_integer(o, val.m_value.binary->back());
                    }

                    o->write_characters("],\n", 3);
                    o->write_characters(indent_string.c_str(), new_indent);

                    o->write_characters("\"subtype\": ", 11);
                    if (val.m_value.binary->has_subtype())
                    {
                        DenumerizerType::dump_integer(o, val.m_value.binary->subtype());
                    }
                    else
                    {
                        o->write_characters("null", 4);
                    }
                    o->write_character('\n');
                    o->write_characters(indent_string.c_str(), current_indent);
                    o->write_character('}');
                }
                else
                {
                    o->write_characters("{\"bytes\":[", 10);

                    if (!val.m_value.binary->empty())
                    {
                        for (auto i = val.m_value.binary->cbegin();
                                i != val.m_value.binary->cend() - 1; ++i)
                        {
                            DenumerizerType::dump_integer(o, *i);
                            o->write_character(',');
                        }
                        DenumerizerType::dump_integer(o, val.m_value.binary->back());
                    }

                    o->write_characters("],\"subtype\":", 12);
                    if (val.m_value.binary->has_subtype())
                    {
                        DenumerizerType::dump_integer(o, val.m_value.binary->subtype());
                        o->write_character('}');
                    }
                    else
                    {
                        o->write_characters("null}", 5);
                    }
                }
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
                DenumerizerType::dump_integer(o, val.m_value.number_integer);
                return;
            }

            case value_t::number_unsigned:
            {
                DenumerizerType::dump_integer(o, val.m_value.number_unsigned);
                return;
            }

            case value_t::number_float:
            {
                DenumerizerType::dump_float(o, val.m_value.number_float);
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

            default:            // LCOV_EXCL_LINE
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
        }
    }

  JSON_PRIVATE_UNLESS_TESTED:
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
    void dump_escaped(const string_t& s, const bool ensure_ascii)
    {
        std::uint32_t codepoint{};
        std::uint8_t state = UTF8_ACCEPT;
        std::size_t bytes = 0;  // number of bytes written to string_buffer

        // number of bytes written at the point of the last valid byte
        std::size_t bytes_after_last_accept = 0;
        std::size_t undumped_chars = 0;

        for (std::size_t i = 0; i < s.size(); ++i)
        {
            const auto byte = static_cast<std::uint8_t>(s[i]);

            switch (decode(state, codepoint, byte))
            {
                case UTF8_ACCEPT:  // decode found a new code point
                {
                    switch (codepoint)
                    {
                        case 0x08: // backspace
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 'b';
                            break;
                        }

                        case 0x09: // horizontal tab
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 't';
                            break;
                        }

                        case 0x0A: // newline
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 'n';
                            break;
                        }

                        case 0x0C: // formfeed
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 'f';
                            break;
                        }

                        case 0x0D: // carriage return
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 'r';
                            break;
                        }

                        case 0x22: // quotation mark
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = '\"';
                            break;
                        }

                        case 0x5C: // reverse solidus
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = '\\';
                            break;
                        }

                        default:
                        {
                            // escape control characters (0x00..0x1F) or, if
                            // ensure_ascii parameter is used, non-ASCII characters
                            if ((codepoint <= 0x1F) || (ensure_ascii && (codepoint >= 0x7F)))
                            {
                                if (codepoint <= 0xFFFF)
                                {
                                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
                                    (std::snprintf)(string_buffer.data() + bytes, 7, "\\u%04x",
                                                    static_cast<std::uint16_t>(codepoint));
                                    bytes += 6;
                                }
                                else
                                {
                                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
                                    (std::snprintf)(string_buffer.data() + bytes, 13, "\\u%04x\\u%04x",
                                                    static_cast<std::uint16_t>(0xD7C0u + (codepoint >> 10u)),
                                                    static_cast<std::uint16_t>(0xDC00u + (codepoint & 0x3FFu)));
                                    bytes += 12;
                                }
                            }
                            else
                            {
                                // copy byte to buffer (all previous bytes
                                // been copied have in default case above)
                                string_buffer[bytes++] = s[i];
                            }
                            break;
                        }
                    }

                    // write buffer and reset index; there must be 13 bytes
                    // left, as this is the maximal number of bytes to be
                    // written ("\uxxxx\uxxxx\0") for one code point
                    if (string_buffer.size() - bytes < 13)
                    {
                        o->write_characters(string_buffer.data(), bytes);
                        bytes = 0;
                    }

                    // remember the byte position of this accept
                    bytes_after_last_accept = bytes;
                    undumped_chars = 0;
                    break;
                }

                case UTF8_REJECT:  // decode found invalid UTF-8 byte
                {
                    switch (error_handler)
                    {
                        case error_handler_t::strict:
                        {
                            std::stringstream ss;
                            ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (byte | 0);
                            JSON_THROW(type_error::create(316, "invalid UTF-8 byte at index " + std::to_string(i) + ": 0x" + ss.str(), BasicJsonType()));
                        }

                        case error_handler_t::ignore:
                        case error_handler_t::replace:
                        {
                            // in case we saw this character the first time, we
                            // would like to read it again, because the byte
                            // may be OK for itself, but just not OK for the
                            // previous sequence
                            if (undumped_chars > 0)
                            {
                                --i;
                            }

                            // reset length buffer to the last accepted index;
                            // thus removing/ignoring the invalid characters
                            bytes = bytes_after_last_accept;

                            if (error_handler == error_handler_t::replace)
                            {
                                // add a replacement character
                                if (ensure_ascii)
                                {
                                    string_buffer[bytes++] = '\\';
                                    string_buffer[bytes++] = 'u';
                                    string_buffer[bytes++] = 'f';
                                    string_buffer[bytes++] = 'f';
                                    string_buffer[bytes++] = 'f';
                                    string_buffer[bytes++] = 'd';
                                }
                                else
                                {
                                    string_buffer[bytes++] = detail::binary_writer<BasicJsonType, char>::to_char_type('\xEF');
                                    string_buffer[bytes++] = detail::binary_writer<BasicJsonType, char>::to_char_type('\xBF');
                                    string_buffer[bytes++] = detail::binary_writer<BasicJsonType, char>::to_char_type('\xBD');
                                }

                                // write buffer and reset index; there must be 13 bytes
                                // left, as this is the maximal number of bytes to be
                                // written ("\uxxxx\uxxxx\0") for one code point
                                if (string_buffer.size() - bytes < 13)
                                {
                                    o->write_characters(string_buffer.data(), bytes);
                                    bytes = 0;
                                }

                                bytes_after_last_accept = bytes;
                            }

                            undumped_chars = 0;

                            // continue processing the string
                            state = UTF8_ACCEPT;
                            break;
                        }

                        default:            // LCOV_EXCL_LINE
                            JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
                    }
                    break;
                }

                default:  // decode found yet incomplete multi-byte code point
                {
                    if (!ensure_ascii)
                    {
                        // code point will not be escaped - copy byte to buffer
                        string_buffer[bytes++] = s[i];
                    }
                    ++undumped_chars;
                    break;
                }
            }
        }

        // we finished processing the string
        if (JSON_HEDLEY_LIKELY(state == UTF8_ACCEPT))
        {
            // write buffer
            if (bytes > 0)
            {
                o->write_characters(string_buffer.data(), bytes);
            }
        }
        else
        {
            // we finish reading, but do not accept: string was incomplete
            switch (error_handler)
            {
                case error_handler_t::strict:
                {
                    std::stringstream ss;
                    ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << (static_cast<std::uint8_t>(s.back()) | 0);
                    JSON_THROW(type_error::create(316, "incomplete UTF-8 string; last byte: 0x" + ss.str(), BasicJsonType()));
                }

                case error_handler_t::ignore:
                {
                    // write all accepted bytes
                    o->write_characters(string_buffer.data(), bytes_after_last_accept);
                    break;
                }

                case error_handler_t::replace:
                {
                    // write all accepted bytes
                    o->write_characters(string_buffer.data(), bytes_after_last_accept);
                    // add a replacement character
                    if (ensure_ascii)
                    {
                        o->write_characters("\\ufffd", 6);
                    }
                    else
                    {
                        o->write_characters("\xEF\xBF\xBD", 3);
                    }
                    break;
                }

                default:            // LCOV_EXCL_LINE
                    JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
            }
        }
    }

  private:

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
    @param[in,out] codep  codepoint (valid only if resulting state is UTF8_ACCEPT)
    @param[in] byte       next byte to decode
    @return               new state

    @note The function has been edited: a std::array is used.

    @copyright Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>
    @sa http://bjoern.hoehrmann.de/utf-8/decoder/dfa/
    */
    static std::uint8_t decode(std::uint8_t& state, std::uint32_t& codep, const std::uint8_t byte) noexcept
    {
        static const std::array<std::uint8_t, 400> utf8d =
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

        JSON_ASSERT(byte < utf8d.size());
        const std::uint8_t type = utf8d[byte];

        codep = (state != UTF8_ACCEPT)
                ? (byte & 0x3fu) | (codep << 6u)
                : (0xFFu >> type) & (byte);

        std::size_t index = 256u + static_cast<size_t>(state) * 16u + static_cast<size_t>(type);
        JSON_ASSERT(index < 400);
        state = utf8d[index];
        return state;
    }

  private:
    /// the output of the serializer
    output_adapter_t<char> o = nullptr;

    /// string buffer
    std::array<char, 512> string_buffer{{}};

    /// the indentation character
    const char indent_char;
    /// the indentation string
    string_t indent_string;

    /// error_handler how to react on decoding errors
    const error_handler_t error_handler;
};
}  // namespace detail
}  // namespace nlohmann
