#pragma once

#include <algorithm> // generate_n
#include <array> // array
#include <cassert> // assert
#include <cmath> // ldexp
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t
#include <cstdio> // snprintf
#include <cstring> // memcpy
#include <iterator> // back_inserter
#include <limits> // numeric_limits
#include <string> // char_traits, string
#include <utility> // make_pair, move

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/input/input_adapters.hpp>
#include <nlohmann/detail/input/json_sax.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/is_sax.hpp>
#include <nlohmann/detail/value_t.hpp>

namespace nlohmann
{
namespace detail
{
///////////////////
// binary reader //
///////////////////

/*!
@brief deserialization of CBOR, MessagePack, and UBJSON values
*/
template<typename BasicJsonType, typename SAX = json_sax_dom_parser<BasicJsonType>>
class binary_reader
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using json_sax_t = SAX;

  public:
    /*!
    @brief create a binary reader

    @param[in] adapter  input adapter to read from
    */
    explicit binary_reader(input_adapter_t adapter) : ia(std::move(adapter))
    {
        (void)detail::is_sax_static_asserts<SAX, BasicJsonType> {};
        assert(ia);
    }

    // make class move-only
    binary_reader(const binary_reader&) = delete;
    binary_reader(binary_reader&&) = default;
    binary_reader& operator=(const binary_reader&) = delete;
    binary_reader& operator=(binary_reader&&) = default;
    ~binary_reader() = default;

    /*!
    @param[in] format  the binary format to parse
    @param[in] sax_    a SAX event processor
    @param[in] strict  whether to expect the input to be consumed completed

    @return
    */
    bool sax_parse(const input_format_t format,
                   json_sax_t* sax_,
                   const bool strict = true)
    {
        sax = sax_;
        bool result = false;

        switch (format)
        {
            case input_format_t::bson:
                result = parse_bson_internal();
                break;

            case input_format_t::cbor:
                result = parse_cbor_internal();
                break;

            case input_format_t::msgpack:
                result = parse_msgpack_internal();
                break;

            case input_format_t::ubjson:
                result = parse_ubjson_internal();
                break;

            default:            // LCOV_EXCL_LINE
                assert(false);  // LCOV_EXCL_LINE
        }

        // strict mode: next byte must be EOF
        if (result and strict)
        {
            if (format == input_format_t::ubjson)
            {
                get_ignore_noop();
            }
            else
            {
                get();
            }

            if (JSON_UNLIKELY(current != std::char_traits<char>::eof()))
            {
                return sax->parse_error(chars_read, get_token_string(),
                                        parse_error::create(110, chars_read, exception_message(format, "expected end of input; last byte: 0x" + get_token_string(), "value")));
            }
        }

        return result;
    }

    /*!
    @brief determine system byte order

    @return true if and only if system's byte order is little endian

    @note from http://stackoverflow.com/a/1001328/266378
    */
    static constexpr bool little_endianess(int num = 1) noexcept
    {
        return *reinterpret_cast<char*>(&num) == 1;
    }

  private:
    //////////
    // BSON //
    //////////

    /*!
    @brief Reads in a BSON-object and passes it to the SAX-parser.
    @return whether a valid BSON-value was passed to the SAX parser
    */
    bool parse_bson_internal()
    {
        std::int32_t document_size;
        get_number<std::int32_t, true>(input_format_t::bson, document_size);

        if (JSON_UNLIKELY(not sax->start_object(std::size_t(-1))))
        {
            return false;
        }

        if (JSON_UNLIKELY(not parse_bson_element_list(/*is_array*/false)))
        {
            return false;
        }

        return sax->end_object();
    }

    /*!
    @brief Parses a C-style string from the BSON input.
    @param[in, out] result  A reference to the string variable where the read
                            string is to be stored.
    @return `true` if the \x00-byte indicating the end of the string was
             encountered before the EOF; false` indicates an unexpected EOF.
    */
    bool get_bson_cstr(string_t& result)
    {
        auto out = std::back_inserter(result);
        while (true)
        {
            get();
            if (JSON_UNLIKELY(not unexpect_eof(input_format_t::bson, "cstring")))
            {
                return false;
            }
            if (current == 0x00)
            {
                return true;
            }
            *out++ = static_cast<char>(current);
        }

        return true;
    }

    /*!
    @brief Parses a zero-terminated string of length @a len from the BSON
           input.
    @param[in] len  The length (including the zero-byte at the end) of the
                    string to be read.
    @param[in, out] result  A reference to the string variable where the read
                            string is to be stored.
    @tparam NumberType The type of the length @a len
    @pre len >= 1
    @return `true` if the string was successfully parsed
    */
    template<typename NumberType>
    bool get_bson_string(const NumberType len, string_t& result)
    {
        if (JSON_UNLIKELY(len < 1))
        {
            auto last_token = get_token_string();
            return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, exception_message(input_format_t::bson, "string length must be at least 1, is " + std::to_string(len), "string")));
        }

        return get_string(input_format_t::bson, len - static_cast<NumberType>(1), result) and get() != std::char_traits<char>::eof();
    }

    /*!
    @brief Read a BSON document element of the given @a element_type.
    @param[in] element_type The BSON element type, c.f. http://bsonspec.org/spec.html
    @param[in] element_type_parse_position The position in the input stream,
               where the `element_type` was read.
    @warning Not all BSON element types are supported yet. An unsupported
             @a element_type will give rise to a parse_error.114:
             Unsupported BSON record type 0x...
    @return whether a valid BSON-object/array was passed to the SAX parser
    */
    bool parse_bson_element_internal(const int element_type,
                                     const std::size_t element_type_parse_position)
    {
        switch (element_type)
        {
            case 0x01: // double
            {
                double number;
                return get_number<double, true>(input_format_t::bson, number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0x02: // string
            {
                std::int32_t len;
                string_t value;
                return get_number<std::int32_t, true>(input_format_t::bson, len) and get_bson_string(len, value) and sax->string(value);
            }

            case 0x03: // object
            {
                return parse_bson_internal();
            }

            case 0x04: // array
            {
                return parse_bson_array();
            }

            case 0x08: // boolean
            {
                return sax->boolean(get() != 0);
            }

            case 0x0A: // null
            {
                return sax->null();
            }

            case 0x10: // int32
            {
                std::int32_t value;
                return get_number<std::int32_t, true>(input_format_t::bson, value) and sax->number_integer(value);
            }

            case 0x12: // int64
            {
                std::int64_t value;
                return get_number<std::int64_t, true>(input_format_t::bson, value) and sax->number_integer(value);
            }

            default: // anything else not supported (yet)
            {
                std::array<char, 3> cr{{}};
                (std::snprintf)(cr.data(), cr.size(), "%.2hhX", static_cast<unsigned char>(element_type));
                return sax->parse_error(element_type_parse_position, std::string(cr.data()), parse_error::create(114, element_type_parse_position, "Unsupported BSON record type 0x" + std::string(cr.data())));
            }
        }
    }

    /*!
    @brief Read a BSON element list (as specified in the BSON-spec)

    The same binary layout is used for objects and arrays, hence it must be
    indicated with the argument @a is_array which one is expected
    (true --> array, false --> object).

    @param[in] is_array Determines if the element list being read is to be
                        treated as an object (@a is_array == false), or as an
                        array (@a is_array == true).
    @return whether a valid BSON-object/array was passed to the SAX parser
    */
    bool parse_bson_element_list(const bool is_array)
    {
        string_t key;
        while (int element_type = get())
        {
            if (JSON_UNLIKELY(not unexpect_eof(input_format_t::bson, "element list")))
            {
                return false;
            }

            const std::size_t element_type_parse_position = chars_read;
            if (JSON_UNLIKELY(not get_bson_cstr(key)))
            {
                return false;
            }

            if (not is_array and not sax->key(key))
            {
                return false;
            }

            if (JSON_UNLIKELY(not parse_bson_element_internal(element_type, element_type_parse_position)))
            {
                return false;
            }

            // get_bson_cstr only appends
            key.clear();
        }

        return true;
    }

    /*!
    @brief Reads an array from the BSON input and passes it to the SAX-parser.
    @return whether a valid BSON-array was passed to the SAX parser
    */
    bool parse_bson_array()
    {
        std::int32_t document_size;
        get_number<std::int32_t, true>(input_format_t::bson, document_size);

        if (JSON_UNLIKELY(not sax->start_array(std::size_t(-1))))
        {
            return false;
        }

        if (JSON_UNLIKELY(not parse_bson_element_list(/*is_array*/true)))
        {
            return false;
        }

        return sax->end_array();
    }

    //////////
    // CBOR //
    //////////

    /*!
    @param[in] get_char  whether a new character should be retrieved from the
                         input (true, default) or whether the last read
                         character should be considered instead

    @return whether a valid CBOR value was passed to the SAX parser
    */
    bool parse_cbor_internal(const bool get_char = true)
    {
        switch (get_char ? get() : current)
        {
            // EOF
            case std::char_traits<char>::eof():
                return unexpect_eof(input_format_t::cbor, "value");

            // Integer 0x00..0x17 (0..23)
            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
            case 0x04:
            case 0x05:
            case 0x06:
            case 0x07:
            case 0x08:
            case 0x09:
            case 0x0A:
            case 0x0B:
            case 0x0C:
            case 0x0D:
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
                return sax->number_unsigned(static_cast<number_unsigned_t>(current));

            case 0x18: // Unsigned integer (one-byte uint8_t follows)
            {
                std::uint8_t number;
                return get_number(input_format_t::cbor, number) and sax->number_unsigned(number);
            }

            case 0x19: // Unsigned integer (two-byte uint16_t follows)
            {
                std::uint16_t number;
                return get_number(input_format_t::cbor, number) and sax->number_unsigned(number);
            }

            case 0x1A: // Unsigned integer (four-byte uint32_t follows)
            {
                std::uint32_t number;
                return get_number(input_format_t::cbor, number) and sax->number_unsigned(number);
            }

            case 0x1B: // Unsigned integer (eight-byte uint64_t follows)
            {
                std::uint64_t number;
                return get_number(input_format_t::cbor, number) and sax->number_unsigned(number);
            }

            // Negative integer -1-0x00..-1-0x17 (-1..-24)
            case 0x20:
            case 0x21:
            case 0x22:
            case 0x23:
            case 0x24:
            case 0x25:
            case 0x26:
            case 0x27:
            case 0x28:
            case 0x29:
            case 0x2A:
            case 0x2B:
            case 0x2C:
            case 0x2D:
            case 0x2E:
            case 0x2F:
            case 0x30:
            case 0x31:
            case 0x32:
            case 0x33:
            case 0x34:
            case 0x35:
            case 0x36:
            case 0x37:
                return sax->number_integer(static_cast<std::int8_t>(0x20 - 1 - current));

            case 0x38: // Negative integer (one-byte uint8_t follows)
            {
                std::uint8_t number;
                return get_number(input_format_t::cbor, number) and sax->number_integer(static_cast<number_integer_t>(-1) - number);
            }

            case 0x39: // Negative integer -1-n (two-byte uint16_t follows)
            {
                std::uint16_t number;
                return get_number(input_format_t::cbor, number) and sax->number_integer(static_cast<number_integer_t>(-1) - number);
            }

            case 0x3A: // Negative integer -1-n (four-byte uint32_t follows)
            {
                std::uint32_t number;
                return get_number(input_format_t::cbor, number) and sax->number_integer(static_cast<number_integer_t>(-1) - number);
            }

            case 0x3B: // Negative integer -1-n (eight-byte uint64_t follows)
            {
                std::uint64_t number;
                return get_number(input_format_t::cbor, number) and sax->number_integer(static_cast<number_integer_t>(-1)
                        - static_cast<number_integer_t>(number));
            }

            // UTF-8 string (0x00..0x17 bytes follow)
            case 0x60:
            case 0x61:
            case 0x62:
            case 0x63:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
            case 0x68:
            case 0x69:
            case 0x6A:
            case 0x6B:
            case 0x6C:
            case 0x6D:
            case 0x6E:
            case 0x6F:
            case 0x70:
            case 0x71:
            case 0x72:
            case 0x73:
            case 0x74:
            case 0x75:
            case 0x76:
            case 0x77:
            case 0x78: // UTF-8 string (one-byte uint8_t for n follows)
            case 0x79: // UTF-8 string (two-byte uint16_t for n follow)
            case 0x7A: // UTF-8 string (four-byte uint32_t for n follow)
            case 0x7B: // UTF-8 string (eight-byte uint64_t for n follow)
            case 0x7F: // UTF-8 string (indefinite length)
            {
                string_t s;
                return get_cbor_string(s) and sax->string(s);
            }

            // array (0x00..0x17 data items follow)
            case 0x80:
            case 0x81:
            case 0x82:
            case 0x83:
            case 0x84:
            case 0x85:
            case 0x86:
            case 0x87:
            case 0x88:
            case 0x89:
            case 0x8A:
            case 0x8B:
            case 0x8C:
            case 0x8D:
            case 0x8E:
            case 0x8F:
            case 0x90:
            case 0x91:
            case 0x92:
            case 0x93:
            case 0x94:
            case 0x95:
            case 0x96:
            case 0x97:
                return get_cbor_array(static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x1Fu));

            case 0x98: // array (one-byte uint8_t for n follows)
            {
                std::uint8_t len;
                return get_number(input_format_t::cbor, len) and get_cbor_array(static_cast<std::size_t>(len));
            }

            case 0x99: // array (two-byte uint16_t for n follow)
            {
                std::uint16_t len;
                return get_number(input_format_t::cbor, len) and get_cbor_array(static_cast<std::size_t>(len));
            }

            case 0x9A: // array (four-byte uint32_t for n follow)
            {
                std::uint32_t len;
                return get_number(input_format_t::cbor, len) and get_cbor_array(static_cast<std::size_t>(len));
            }

            case 0x9B: // array (eight-byte uint64_t for n follow)
            {
                std::uint64_t len;
                return get_number(input_format_t::cbor, len) and get_cbor_array(static_cast<std::size_t>(len));
            }

            case 0x9F: // array (indefinite length)
                return get_cbor_array(std::size_t(-1));

            // map (0x00..0x17 pairs of data items follow)
            case 0xA0:
            case 0xA1:
            case 0xA2:
            case 0xA3:
            case 0xA4:
            case 0xA5:
            case 0xA6:
            case 0xA7:
            case 0xA8:
            case 0xA9:
            case 0xAA:
            case 0xAB:
            case 0xAC:
            case 0xAD:
            case 0xAE:
            case 0xAF:
            case 0xB0:
            case 0xB1:
            case 0xB2:
            case 0xB3:
            case 0xB4:
            case 0xB5:
            case 0xB6:
            case 0xB7:
                return get_cbor_object(static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x1Fu));

            case 0xB8: // map (one-byte uint8_t for n follows)
            {
                std::uint8_t len;
                return get_number(input_format_t::cbor, len) and get_cbor_object(static_cast<std::size_t>(len));
            }

            case 0xB9: // map (two-byte uint16_t for n follow)
            {
                std::uint16_t len;
                return get_number(input_format_t::cbor, len) and get_cbor_object(static_cast<std::size_t>(len));
            }

            case 0xBA: // map (four-byte uint32_t for n follow)
            {
                std::uint32_t len;
                return get_number(input_format_t::cbor, len) and get_cbor_object(static_cast<std::size_t>(len));
            }

            case 0xBB: // map (eight-byte uint64_t for n follow)
            {
                std::uint64_t len;
                return get_number(input_format_t::cbor, len) and get_cbor_object(static_cast<std::size_t>(len));
            }

            case 0xBF: // map (indefinite length)
                return get_cbor_object(std::size_t(-1));

            case 0xF4: // false
                return sax->boolean(false);

            case 0xF5: // true
                return sax->boolean(true);

            case 0xF6: // null
                return sax->null();

            case 0xF9: // Half-Precision Float (two-byte IEEE 754)
            {
                const int byte1_raw = get();
                if (JSON_UNLIKELY(not unexpect_eof(input_format_t::cbor, "number")))
                {
                    return false;
                }
                const int byte2_raw = get();
                if (JSON_UNLIKELY(not unexpect_eof(input_format_t::cbor, "number")))
                {
                    return false;
                }

                const auto byte1 = static_cast<unsigned char>(byte1_raw);
                const auto byte2 = static_cast<unsigned char>(byte2_raw);

                // code from RFC 7049, Appendix D, Figure 3:
                // As half-precision floating-point numbers were only added
                // to IEEE 754 in 2008, today's programming platforms often
                // still only have limited support for them. It is very
                // easy to include at least decoding support for them even
                // without such support. An example of a small decoder for
                // half-precision floating-point numbers in the C language
                // is shown in Fig. 3.
                const auto half = static_cast<unsigned int>((byte1 << 8u) + byte2);
                const double val = [&half]
                {
                    const int exp = (half >> 10u) & 0x1Fu;
                    const unsigned int mant = half & 0x3FFu;
                    assert(0 <= exp and exp <= 32);
                    assert(0 <= mant and mant <= 1024);
                    switch (exp)
                    {
                        case 0:
                            return std::ldexp(mant, -24);
                        case 31:
                            return (mant == 0)
                            ? std::numeric_limits<double>::infinity()
                            : std::numeric_limits<double>::quiet_NaN();
                        default:
                            return std::ldexp(mant + 1024, exp - 25);
                    }
                }();
                return sax->number_float((half & 0x8000u) != 0
                                         ? static_cast<number_float_t>(-val)
                                         : static_cast<number_float_t>(val), "");
            }

            case 0xFA: // Single-Precision Float (four-byte IEEE 754)
            {
                float number;
                return get_number(input_format_t::cbor, number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xFB: // Double-Precision Float (eight-byte IEEE 754)
            {
                double number;
                return get_number(input_format_t::cbor, number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            default: // anything else (0xFF is handled inside the other types)
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, exception_message(input_format_t::cbor, "invalid byte: 0x" + last_token, "value")));
            }
        }
    }

    /*!
    @brief reads a CBOR string

    This function first reads starting bytes to determine the expected
    string length and then copies this number of bytes into a string.
    Additionally, CBOR's strings with indefinite lengths are supported.

    @param[out] result  created string

    @return whether string creation completed
    */
    bool get_cbor_string(string_t& result)
    {
        if (JSON_UNLIKELY(not unexpect_eof(input_format_t::cbor, "string")))
        {
            return false;
        }

        switch (current)
        {
            // UTF-8 string (0x00..0x17 bytes follow)
            case 0x60:
            case 0x61:
            case 0x62:
            case 0x63:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
            case 0x68:
            case 0x69:
            case 0x6A:
            case 0x6B:
            case 0x6C:
            case 0x6D:
            case 0x6E:
            case 0x6F:
            case 0x70:
            case 0x71:
            case 0x72:
            case 0x73:
            case 0x74:
            case 0x75:
            case 0x76:
            case 0x77:
            {
                return get_string(input_format_t::cbor, static_cast<unsigned int>(current) & 0x1Fu, result);
            }

            case 0x78: // UTF-8 string (one-byte uint8_t for n follows)
            {
                std::uint8_t len;
                return get_number(input_format_t::cbor, len) and get_string(input_format_t::cbor, len, result);
            }

            case 0x79: // UTF-8 string (two-byte uint16_t for n follow)
            {
                std::uint16_t len;
                return get_number(input_format_t::cbor, len) and get_string(input_format_t::cbor, len, result);
            }

            case 0x7A: // UTF-8 string (four-byte uint32_t for n follow)
            {
                std::uint32_t len;
                return get_number(input_format_t::cbor, len) and get_string(input_format_t::cbor, len, result);
            }

            case 0x7B: // UTF-8 string (eight-byte uint64_t for n follow)
            {
                std::uint64_t len;
                return get_number(input_format_t::cbor, len) and get_string(input_format_t::cbor, len, result);
            }

            case 0x7F: // UTF-8 string (indefinite length)
            {
                while (get() != 0xFF)
                {
                    string_t chunk;
                    if (not get_cbor_string(chunk))
                    {
                        return false;
                    }
                    result.append(chunk);
                }
                return true;
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format_t::cbor, "expected length specification (0x60-0x7B) or indefinite string type (0x7F); last byte: 0x" + last_token, "string")));
            }
        }
    }

    /*!
    @param[in] len  the length of the array or std::size_t(-1) for an
                    array of indefinite size
    @return whether array creation completed
    */
    bool get_cbor_array(const std::size_t len)
    {
        if (JSON_UNLIKELY(not sax->start_array(len)))
        {
            return false;
        }

        if (len != std::size_t(-1))
        {
            for (std::size_t i = 0; i < len; ++i)
            {
                if (JSON_UNLIKELY(not parse_cbor_internal()))
                {
                    return false;
                }
            }
        }
        else
        {
            while (get() != 0xFF)
            {
                if (JSON_UNLIKELY(not parse_cbor_internal(false)))
                {
                    return false;
                }
            }
        }

        return sax->end_array();
    }

    /*!
    @param[in] len  the length of the object or std::size_t(-1) for an
                    object of indefinite size
    @return whether object creation completed
    */
    bool get_cbor_object(const std::size_t len)
    {
        if (JSON_UNLIKELY(not sax->start_object(len)))
        {
            return false;
        }

        string_t key;
        if (len != std::size_t(-1))
        {
            for (std::size_t i = 0; i < len; ++i)
            {
                get();
                if (JSON_UNLIKELY(not get_cbor_string(key) or not sax->key(key)))
                {
                    return false;
                }

                if (JSON_UNLIKELY(not parse_cbor_internal()))
                {
                    return false;
                }
                key.clear();
            }
        }
        else
        {
            while (get() != 0xFF)
            {
                if (JSON_UNLIKELY(not get_cbor_string(key) or not sax->key(key)))
                {
                    return false;
                }

                if (JSON_UNLIKELY(not parse_cbor_internal()))
                {
                    return false;
                }
                key.clear();
            }
        }

        return sax->end_object();
    }

    /////////////
    // MsgPack //
    /////////////

    /*!
    @return whether a valid MessagePack value was passed to the SAX parser
    */
    bool parse_msgpack_internal()
    {
        switch (get())
        {
            // EOF
            case std::char_traits<char>::eof():
                return unexpect_eof(input_format_t::msgpack, "value");

            // positive fixint
            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
            case 0x04:
            case 0x05:
            case 0x06:
            case 0x07:
            case 0x08:
            case 0x09:
            case 0x0A:
            case 0x0B:
            case 0x0C:
            case 0x0D:
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
            case 0x20:
            case 0x21:
            case 0x22:
            case 0x23:
            case 0x24:
            case 0x25:
            case 0x26:
            case 0x27:
            case 0x28:
            case 0x29:
            case 0x2A:
            case 0x2B:
            case 0x2C:
            case 0x2D:
            case 0x2E:
            case 0x2F:
            case 0x30:
            case 0x31:
            case 0x32:
            case 0x33:
            case 0x34:
            case 0x35:
            case 0x36:
            case 0x37:
            case 0x38:
            case 0x39:
            case 0x3A:
            case 0x3B:
            case 0x3C:
            case 0x3D:
            case 0x3E:
            case 0x3F:
            case 0x40:
            case 0x41:
            case 0x42:
            case 0x43:
            case 0x44:
            case 0x45:
            case 0x46:
            case 0x47:
            case 0x48:
            case 0x49:
            case 0x4A:
            case 0x4B:
            case 0x4C:
            case 0x4D:
            case 0x4E:
            case 0x4F:
            case 0x50:
            case 0x51:
            case 0x52:
            case 0x53:
            case 0x54:
            case 0x55:
            case 0x56:
            case 0x57:
            case 0x58:
            case 0x59:
            case 0x5A:
            case 0x5B:
            case 0x5C:
            case 0x5D:
            case 0x5E:
            case 0x5F:
            case 0x60:
            case 0x61:
            case 0x62:
            case 0x63:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
            case 0x68:
            case 0x69:
            case 0x6A:
            case 0x6B:
            case 0x6C:
            case 0x6D:
            case 0x6E:
            case 0x6F:
            case 0x70:
            case 0x71:
            case 0x72:
            case 0x73:
            case 0x74:
            case 0x75:
            case 0x76:
            case 0x77:
            case 0x78:
            case 0x79:
            case 0x7A:
            case 0x7B:
            case 0x7C:
            case 0x7D:
            case 0x7E:
            case 0x7F:
                return sax->number_unsigned(static_cast<number_unsigned_t>(current));

            // fixmap
            case 0x80:
            case 0x81:
            case 0x82:
            case 0x83:
            case 0x84:
            case 0x85:
            case 0x86:
            case 0x87:
            case 0x88:
            case 0x89:
            case 0x8A:
            case 0x8B:
            case 0x8C:
            case 0x8D:
            case 0x8E:
            case 0x8F:
                return get_msgpack_object(static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x0Fu));

            // fixarray
            case 0x90:
            case 0x91:
            case 0x92:
            case 0x93:
            case 0x94:
            case 0x95:
            case 0x96:
            case 0x97:
            case 0x98:
            case 0x99:
            case 0x9A:
            case 0x9B:
            case 0x9C:
            case 0x9D:
            case 0x9E:
            case 0x9F:
                return get_msgpack_array(static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x0Fu));

            // fixstr
            case 0xA0:
            case 0xA1:
            case 0xA2:
            case 0xA3:
            case 0xA4:
            case 0xA5:
            case 0xA6:
            case 0xA7:
            case 0xA8:
            case 0xA9:
            case 0xAA:
            case 0xAB:
            case 0xAC:
            case 0xAD:
            case 0xAE:
            case 0xAF:
            case 0xB0:
            case 0xB1:
            case 0xB2:
            case 0xB3:
            case 0xB4:
            case 0xB5:
            case 0xB6:
            case 0xB7:
            case 0xB8:
            case 0xB9:
            case 0xBA:
            case 0xBB:
            case 0xBC:
            case 0xBD:
            case 0xBE:
            case 0xBF:
            {
                string_t s;
                return get_msgpack_string(s) and sax->string(s);
            }

            case 0xC0: // nil
                return sax->null();

            case 0xC2: // false
                return sax->boolean(false);

            case 0xC3: // true
                return sax->boolean(true);

            case 0xCA: // float 32
            {
                float number;
                return get_number(input_format_t::msgpack, number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xCB: // float 64
            {
                double number;
                return get_number(input_format_t::msgpack, number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xCC: // uint 8
            {
                std::uint8_t number;
                return get_number(input_format_t::msgpack, number) and sax->number_unsigned(number);
            }

            case 0xCD: // uint 16
            {
                std::uint16_t number;
                return get_number(input_format_t::msgpack, number) and sax->number_unsigned(number);
            }

            case 0xCE: // uint 32
            {
                std::uint32_t number;
                return get_number(input_format_t::msgpack, number) and sax->number_unsigned(number);
            }

            case 0xCF: // uint 64
            {
                std::uint64_t number;
                return get_number(input_format_t::msgpack, number) and sax->number_unsigned(number);
            }

            case 0xD0: // int 8
            {
                std::int8_t number;
                return get_number(input_format_t::msgpack, number) and sax->number_integer(number);
            }

            case 0xD1: // int 16
            {
                std::int16_t number;
                return get_number(input_format_t::msgpack, number) and sax->number_integer(number);
            }

            case 0xD2: // int 32
            {
                std::int32_t number;
                return get_number(input_format_t::msgpack, number) and sax->number_integer(number);
            }

            case 0xD3: // int 64
            {
                std::int64_t number;
                return get_number(input_format_t::msgpack, number) and sax->number_integer(number);
            }

            case 0xD9: // str 8
            case 0xDA: // str 16
            case 0xDB: // str 32
            {
                string_t s;
                return get_msgpack_string(s) and sax->string(s);
            }

            case 0xDC: // array 16
            {
                std::uint16_t len;
                return get_number(input_format_t::msgpack, len) and get_msgpack_array(static_cast<std::size_t>(len));
            }

            case 0xDD: // array 32
            {
                std::uint32_t len;
                return get_number(input_format_t::msgpack, len) and get_msgpack_array(static_cast<std::size_t>(len));
            }

            case 0xDE: // map 16
            {
                std::uint16_t len;
                return get_number(input_format_t::msgpack, len) and get_msgpack_object(static_cast<std::size_t>(len));
            }

            case 0xDF: // map 32
            {
                std::uint32_t len;
                return get_number(input_format_t::msgpack, len) and get_msgpack_object(static_cast<std::size_t>(len));
            }

            // negative fixint
            case 0xE0:
            case 0xE1:
            case 0xE2:
            case 0xE3:
            case 0xE4:
            case 0xE5:
            case 0xE6:
            case 0xE7:
            case 0xE8:
            case 0xE9:
            case 0xEA:
            case 0xEB:
            case 0xEC:
            case 0xED:
            case 0xEE:
            case 0xEF:
            case 0xF0:
            case 0xF1:
            case 0xF2:
            case 0xF3:
            case 0xF4:
            case 0xF5:
            case 0xF6:
            case 0xF7:
            case 0xF8:
            case 0xF9:
            case 0xFA:
            case 0xFB:
            case 0xFC:
            case 0xFD:
            case 0xFE:
            case 0xFF:
                return sax->number_integer(static_cast<std::int8_t>(current));

            default: // anything else
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, exception_message(input_format_t::msgpack, "invalid byte: 0x" + last_token, "value")));
            }
        }
    }

    /*!
    @brief reads a MessagePack string

    This function first reads starting bytes to determine the expected
    string length and then copies this number of bytes into a string.

    @param[out] result  created string

    @return whether string creation completed
    */
    bool get_msgpack_string(string_t& result)
    {
        if (JSON_UNLIKELY(not unexpect_eof(input_format_t::msgpack, "string")))
        {
            return false;
        }

        switch (current)
        {
            // fixstr
            case 0xA0:
            case 0xA1:
            case 0xA2:
            case 0xA3:
            case 0xA4:
            case 0xA5:
            case 0xA6:
            case 0xA7:
            case 0xA8:
            case 0xA9:
            case 0xAA:
            case 0xAB:
            case 0xAC:
            case 0xAD:
            case 0xAE:
            case 0xAF:
            case 0xB0:
            case 0xB1:
            case 0xB2:
            case 0xB3:
            case 0xB4:
            case 0xB5:
            case 0xB6:
            case 0xB7:
            case 0xB8:
            case 0xB9:
            case 0xBA:
            case 0xBB:
            case 0xBC:
            case 0xBD:
            case 0xBE:
            case 0xBF:
            {
                return get_string(input_format_t::msgpack, static_cast<unsigned int>(current) & 0x1Fu, result);
            }

            case 0xD9: // str 8
            {
                std::uint8_t len;
                return get_number(input_format_t::msgpack, len) and get_string(input_format_t::msgpack, len, result);
            }

            case 0xDA: // str 16
            {
                std::uint16_t len;
                return get_number(input_format_t::msgpack, len) and get_string(input_format_t::msgpack, len, result);
            }

            case 0xDB: // str 32
            {
                std::uint32_t len;
                return get_number(input_format_t::msgpack, len) and get_string(input_format_t::msgpack, len, result);
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format_t::msgpack, "expected length specification (0xA0-0xBF, 0xD9-0xDB); last byte: 0x" + last_token, "string")));
            }
        }
    }

    /*!
    @param[in] len  the length of the array
    @return whether array creation completed
    */
    bool get_msgpack_array(const std::size_t len)
    {
        if (JSON_UNLIKELY(not sax->start_array(len)))
        {
            return false;
        }

        for (std::size_t i = 0; i < len; ++i)
        {
            if (JSON_UNLIKELY(not parse_msgpack_internal()))
            {
                return false;
            }
        }

        return sax->end_array();
    }

    /*!
    @param[in] len  the length of the object
    @return whether object creation completed
    */
    bool get_msgpack_object(const std::size_t len)
    {
        if (JSON_UNLIKELY(not sax->start_object(len)))
        {
            return false;
        }

        string_t key;
        for (std::size_t i = 0; i < len; ++i)
        {
            get();
            if (JSON_UNLIKELY(not get_msgpack_string(key) or not sax->key(key)))
            {
                return false;
            }

            if (JSON_UNLIKELY(not parse_msgpack_internal()))
            {
                return false;
            }
            key.clear();
        }

        return sax->end_object();
    }

    ////////////
    // UBJSON //
    ////////////

    /*!
    @param[in] get_char  whether a new character should be retrieved from the
                         input (true, default) or whether the last read
                         character should be considered instead

    @return whether a valid UBJSON value was passed to the SAX parser
    */
    bool parse_ubjson_internal(const bool get_char = true)
    {
        return get_ubjson_value(get_char ? get_ignore_noop() : current);
    }

    /*!
    @brief reads a UBJSON string

    This function is either called after reading the 'S' byte explicitly
    indicating a string, or in case of an object key where the 'S' byte can be
    left out.

    @param[out] result   created string
    @param[in] get_char  whether a new character should be retrieved from the
                         input (true, default) or whether the last read
                         character should be considered instead

    @return whether string creation completed
    */
    bool get_ubjson_string(string_t& result, const bool get_char = true)
    {
        if (get_char)
        {
            get();  // TODO(niels): may we ignore N here?
        }

        if (JSON_UNLIKELY(not unexpect_eof(input_format_t::ubjson, "value")))
        {
            return false;
        }

        switch (current)
        {
            case 'U':
            {
                std::uint8_t len;
                return get_number(input_format_t::ubjson, len) and get_string(input_format_t::ubjson, len, result);
            }

            case 'i':
            {
                std::int8_t len;
                return get_number(input_format_t::ubjson, len) and get_string(input_format_t::ubjson, len, result);
            }

            case 'I':
            {
                std::int16_t len;
                return get_number(input_format_t::ubjson, len) and get_string(input_format_t::ubjson, len, result);
            }

            case 'l':
            {
                std::int32_t len;
                return get_number(input_format_t::ubjson, len) and get_string(input_format_t::ubjson, len, result);
            }

            case 'L':
            {
                std::int64_t len;
                return get_number(input_format_t::ubjson, len) and get_string(input_format_t::ubjson, len, result);
            }

            default:
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format_t::ubjson, "expected length type specification (U, i, I, l, L); last byte: 0x" + last_token, "string")));
        }
    }

    /*!
    @param[out] result  determined size
    @return whether size determination completed
    */
    bool get_ubjson_size_value(std::size_t& result)
    {
        switch (get_ignore_noop())
        {
            case 'U':
            {
                std::uint8_t number;
                if (JSON_UNLIKELY(not get_number(input_format_t::ubjson, number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'i':
            {
                std::int8_t number;
                if (JSON_UNLIKELY(not get_number(input_format_t::ubjson, number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'I':
            {
                std::int16_t number;
                if (JSON_UNLIKELY(not get_number(input_format_t::ubjson, number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'l':
            {
                std::int32_t number;
                if (JSON_UNLIKELY(not get_number(input_format_t::ubjson, number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'L':
            {
                std::int64_t number;
                if (JSON_UNLIKELY(not get_number(input_format_t::ubjson, number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format_t::ubjson, "expected length type specification (U, i, I, l, L) after '#'; last byte: 0x" + last_token, "size")));
            }
        }
    }

    /*!
    @brief determine the type and size for a container

    In the optimized UBJSON format, a type and a size can be provided to allow
    for a more compact representation.

    @param[out] result  pair of the size and the type

    @return whether pair creation completed
    */
    bool get_ubjson_size_type(std::pair<std::size_t, int>& result)
    {
        result.first = string_t::npos; // size
        result.second = 0; // type

        get_ignore_noop();

        if (current == '$')
        {
            result.second = get();  // must not ignore 'N', because 'N' maybe the type
            if (JSON_UNLIKELY(not unexpect_eof(input_format_t::ubjson, "type")))
            {
                return false;
            }

            get_ignore_noop();
            if (JSON_UNLIKELY(current != '#'))
            {
                if (JSON_UNLIKELY(not unexpect_eof(input_format_t::ubjson, "value")))
                {
                    return false;
                }
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, exception_message(input_format_t::ubjson, "expected '#' after type information; last byte: 0x" + last_token, "size")));
            }

            return get_ubjson_size_value(result.first);
        }

        if (current == '#')
        {
            return get_ubjson_size_value(result.first);
        }

        return true;
    }

    /*!
    @param prefix  the previously read or set type prefix
    @return whether value creation completed
    */
    bool get_ubjson_value(const int prefix)
    {
        switch (prefix)
        {
            case std::char_traits<char>::eof():  // EOF
                return unexpect_eof(input_format_t::ubjson, "value");

            case 'T':  // true
                return sax->boolean(true);
            case 'F':  // false
                return sax->boolean(false);

            case 'Z':  // null
                return sax->null();

            case 'U':
            {
                std::uint8_t number;
                return get_number(input_format_t::ubjson, number) and sax->number_unsigned(number);
            }

            case 'i':
            {
                std::int8_t number;
                return get_number(input_format_t::ubjson, number) and sax->number_integer(number);
            }

            case 'I':
            {
                std::int16_t number;
                return get_number(input_format_t::ubjson, number) and sax->number_integer(number);
            }

            case 'l':
            {
                std::int32_t number;
                return get_number(input_format_t::ubjson, number) and sax->number_integer(number);
            }

            case 'L':
            {
                std::int64_t number;
                return get_number(input_format_t::ubjson, number) and sax->number_integer(number);
            }

            case 'd':
            {
                float number;
                return get_number(input_format_t::ubjson, number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 'D':
            {
                double number;
                return get_number(input_format_t::ubjson, number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 'C':  // char
            {
                get();
                if (JSON_UNLIKELY(not unexpect_eof(input_format_t::ubjson, "char")))
                {
                    return false;
                }
                if (JSON_UNLIKELY(current > 127))
                {
                    auto last_token = get_token_string();
                    return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format_t::ubjson, "byte after 'C' must be in range 0x00..0x7F; last byte: 0x" + last_token, "char")));
                }
                string_t s(1, static_cast<char>(current));
                return sax->string(s);
            }

            case 'S':  // string
            {
                string_t s;
                return get_ubjson_string(s) and sax->string(s);
            }

            case '[':  // array
                return get_ubjson_array();

            case '{':  // object
                return get_ubjson_object();

            default: // anything else
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, exception_message(input_format_t::ubjson, "invalid byte: 0x" + last_token, "value")));
            }
        }
    }

    /*!
    @return whether array creation completed
    */
    bool get_ubjson_array()
    {
        std::pair<std::size_t, int> size_and_type;
        if (JSON_UNLIKELY(not get_ubjson_size_type(size_and_type)))
        {
            return false;
        }

        if (size_and_type.first != string_t::npos)
        {
            if (JSON_UNLIKELY(not sax->start_array(size_and_type.first)))
            {
                return false;
            }

            if (size_and_type.second != 0)
            {
                if (size_and_type.second != 'N')
                {
                    for (std::size_t i = 0; i < size_and_type.first; ++i)
                    {
                        if (JSON_UNLIKELY(not get_ubjson_value(size_and_type.second)))
                        {
                            return false;
                        }
                    }
                }
            }
            else
            {
                for (std::size_t i = 0; i < size_and_type.first; ++i)
                {
                    if (JSON_UNLIKELY(not parse_ubjson_internal()))
                    {
                        return false;
                    }
                }
            }
        }
        else
        {
            if (JSON_UNLIKELY(not sax->start_array(std::size_t(-1))))
            {
                return false;
            }

            while (current != ']')
            {
                if (JSON_UNLIKELY(not parse_ubjson_internal(false)))
                {
                    return false;
                }
                get_ignore_noop();
            }
        }

        return sax->end_array();
    }

    /*!
    @return whether object creation completed
    */
    bool get_ubjson_object()
    {
        std::pair<std::size_t, int> size_and_type;
        if (JSON_UNLIKELY(not get_ubjson_size_type(size_and_type)))
        {
            return false;
        }

        string_t key;
        if (size_and_type.first != string_t::npos)
        {
            if (JSON_UNLIKELY(not sax->start_object(size_and_type.first)))
            {
                return false;
            }

            if (size_and_type.second != 0)
            {
                for (std::size_t i = 0; i < size_and_type.first; ++i)
                {
                    if (JSON_UNLIKELY(not get_ubjson_string(key) or not sax->key(key)))
                    {
                        return false;
                    }
                    if (JSON_UNLIKELY(not get_ubjson_value(size_and_type.second)))
                    {
                        return false;
                    }
                    key.clear();
                }
            }
            else
            {
                for (std::size_t i = 0; i < size_and_type.first; ++i)
                {
                    if (JSON_UNLIKELY(not get_ubjson_string(key) or not sax->key(key)))
                    {
                        return false;
                    }
                    if (JSON_UNLIKELY(not parse_ubjson_internal()))
                    {
                        return false;
                    }
                    key.clear();
                }
            }
        }
        else
        {
            if (JSON_UNLIKELY(not sax->start_object(std::size_t(-1))))
            {
                return false;
            }

            while (current != '}')
            {
                if (JSON_UNLIKELY(not get_ubjson_string(key, false) or not sax->key(key)))
                {
                    return false;
                }
                if (JSON_UNLIKELY(not parse_ubjson_internal()))
                {
                    return false;
                }
                get_ignore_noop();
                key.clear();
            }
        }

        return sax->end_object();
    }

    ///////////////////////
    // Utility functions //
    ///////////////////////

    /*!
    @brief get next character from the input

    This function provides the interface to the used input adapter. It does
    not throw in case the input reached EOF, but returns a -'ve valued
    `std::char_traits<char>::eof()` in that case.

    @return character read from the input
    */
    int get()
    {
        ++chars_read;
        return current = ia->get_character();
    }

    /*!
    @return character read from the input after ignoring all 'N' entries
    */
    int get_ignore_noop()
    {
        do
        {
            get();
        }
        while (current == 'N');

        return current;
    }

    /*
    @brief read a number from the input

    @tparam NumberType the type of the number
    @param[in] format   the current format (for diagnostics)
    @param[out] result  number of type @a NumberType

    @return whether conversion completed

    @note This function needs to respect the system's endianess, because
          bytes in CBOR, MessagePack, and UBJSON are stored in network order
          (big endian) and therefore need reordering on little endian systems.
    */
    template<typename NumberType, bool InputIsLittleEndian = false>
    bool get_number(const input_format_t format, NumberType& result)
    {
        // step 1: read input into array with system's byte order
        std::array<std::uint8_t, sizeof(NumberType)> vec;
        for (std::size_t i = 0; i < sizeof(NumberType); ++i)
        {
            get();
            if (JSON_UNLIKELY(not unexpect_eof(format, "number")))
            {
                return false;
            }

            // reverse byte order prior to conversion if necessary
            if (is_little_endian != InputIsLittleEndian)
            {
                vec[sizeof(NumberType) - i - 1] = static_cast<std::uint8_t>(current);
            }
            else
            {
                vec[i] = static_cast<std::uint8_t>(current); // LCOV_EXCL_LINE
            }
        }

        // step 2: convert array into number of type T and return
        std::memcpy(&result, vec.data(), sizeof(NumberType));
        return true;
    }

    /*!
    @brief create a string by reading characters from the input

    @tparam NumberType the type of the number
    @param[in] format the current format (for diagnostics)
    @param[in] len number of characters to read
    @param[out] result string created by reading @a len bytes

    @return whether string creation completed

    @note We can not reserve @a len bytes for the result, because @a len
          may be too large. Usually, @ref unexpect_eof() detects the end of
          the input before we run out of string memory.
    */
    template<typename NumberType>
    bool get_string(const input_format_t format,
                    const NumberType len,
                    string_t& result)
    {
        bool success = true;
        std::generate_n(std::back_inserter(result), len, [this, &success, &format]()
        {
            get();
            if (JSON_UNLIKELY(not unexpect_eof(format, "string")))
            {
                success = false;
            }
            return static_cast<char>(current);
        });
        return success;
    }

    /*!
    @param[in] format   the current format (for diagnostics)
    @param[in] context  further context information (for diagnostics)
    @return whether the last read character is not EOF
    */
    bool unexpect_eof(const input_format_t format, const char* context) const
    {
        if (JSON_UNLIKELY(current == std::char_traits<char>::eof()))
        {
            return sax->parse_error(chars_read, "<end of file>",
                                    parse_error::create(110, chars_read, exception_message(format, "unexpected end of input", context)));
        }
        return true;
    }

    /*!
    @return a string representation of the last read byte
    */
    std::string get_token_string() const
    {
        std::array<char, 3> cr{{}};
        (std::snprintf)(cr.data(), cr.size(), "%.2hhX", static_cast<unsigned char>(current));
        return std::string{cr.data()};
    }

    /*!
    @param[in] format   the current format
    @param[in] detail   a detailed error message
    @param[in] context  further contect information
    @return a message string to use in the parse_error exceptions
    */
    std::string exception_message(const input_format_t format,
                                  const std::string& detail,
                                  const std::string& context) const
    {
        std::string error_msg = "syntax error while parsing ";

        switch (format)
        {
            case input_format_t::cbor:
                error_msg += "CBOR";
                break;

            case input_format_t::msgpack:
                error_msg += "MessagePack";
                break;

            case input_format_t::ubjson:
                error_msg += "UBJSON";
                break;

            case input_format_t::bson:
                error_msg += "BSON";
                break;

            default:            // LCOV_EXCL_LINE
                assert(false);  // LCOV_EXCL_LINE
        }

        return error_msg + " " + context + ": " + detail;
    }

  private:
    /// input adapter
    input_adapter_t ia = nullptr;

    /// the current character
    int current = std::char_traits<char>::eof();

    /// the number of characters read
    std::size_t chars_read = 0;

    /// whether we can assume little endianess
    const bool is_little_endian = little_endianess();

    /// the SAX parser
    json_sax_t* sax = nullptr;
};
}  // namespace detail
}  // namespace nlohmann
