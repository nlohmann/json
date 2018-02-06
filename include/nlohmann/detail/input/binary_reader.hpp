#pragma once

#include <algorithm> // generate_n
#include <array> // array
#include <cassert> // assert
#include <cmath> // ldexp
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcpy
#include <iomanip> // setw, setfill
#include <ios> // hex
#include <iterator> // back_inserter
#include <limits> // numeric_limits
#include <sstream> // stringstream
#include <string> // char_traits, string
#include <utility> // make_pair, move

#include <nlohmann/detail/input/input_adapters.hpp>
#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/value_t.hpp>

namespace nlohmann
{
namespace detail
{
///////////////////
// binary reader //
///////////////////

/*!
@brief deserialization of CBOR and MessagePack values
*/
template<typename BasicJsonType>
class binary_reader
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using string_t = typename BasicJsonType::string_t;

  public:
    /*!
    @brief create a binary reader

    @param[in] adapter  input adapter to read from
    */
    explicit binary_reader(input_adapter_t adapter) : ia(std::move(adapter))
    {
        assert(ia);
    }

    /*!
    @brief create a JSON value from CBOR input

    @param[in] strict  whether to expect the input to be consumed completed
    @return JSON value created from CBOR input

    @throw parse_error.110 if input ended unexpectedly or the end of file was
                           not reached when @a strict was set to true
    @throw parse_error.112 if unsupported byte was read
    */
    BasicJsonType parse_cbor(const bool strict)
    {
        const auto res = parse_cbor_internal();
        if (strict)
        {
            get();
            expect_eof();
        }
        return res;
    }

    /*!
    @brief create a JSON value from MessagePack input

    @param[in] strict  whether to expect the input to be consumed completed
    @return JSON value created from MessagePack input

    @throw parse_error.110 if input ended unexpectedly or the end of file was
                           not reached when @a strict was set to true
    @throw parse_error.112 if unsupported byte was read
    */
    BasicJsonType parse_msgpack(const bool strict)
    {
        const auto res = parse_msgpack_internal();
        if (strict)
        {
            get();
            expect_eof();
        }
        return res;
    }

    /*!
    @brief create a JSON value from UBJSON input

    @param[in] strict  whether to expect the input to be consumed completed
    @return JSON value created from UBJSON input

    @throw parse_error.110 if input ended unexpectedly or the end of file was
                           not reached when @a strict was set to true
    @throw parse_error.112 if unsupported byte was read
    */
    BasicJsonType parse_ubjson(const bool strict)
    {
        const auto res = parse_ubjson_internal();
        if (strict)
        {
            get_ignore_noop();
            expect_eof();
        }
        return res;
    }

    /*!
    @brief determine system byte order

    @return true if and only if system's byte order is little endian

    @note from http://stackoverflow.com/a/1001328/266378
    */
    static constexpr bool little_endianess(int num = 1) noexcept
    {
        return (*reinterpret_cast<char*>(&num) == 1);
    }

  private:
    /*!
    @param[in] get_char  whether a new character should be retrieved from the
                         input (true, default) or whether the last read
                         character should be considered instead
    */
    BasicJsonType parse_cbor_internal(const bool get_char = true)
    {
        switch (get_char ? get() : current)
        {
            // EOF
            case std::char_traits<char>::eof():
                JSON_THROW(parse_error::create(110, chars_read, "unexpected end of input"));

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
                return static_cast<number_unsigned_t>(current);

            case 0x18: // Unsigned integer (one-byte uint8_t follows)
                return get_number<uint8_t>();

            case 0x19: // Unsigned integer (two-byte uint16_t follows)
                return get_number<uint16_t>();

            case 0x1A: // Unsigned integer (four-byte uint32_t follows)
                return get_number<uint32_t>();

            case 0x1B: // Unsigned integer (eight-byte uint64_t follows)
                return get_number<uint64_t>();

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
                return static_cast<int8_t>(0x20 - 1 - current);

            case 0x38: // Negative integer (one-byte uint8_t follows)
            {
                return static_cast<number_integer_t>(-1) - get_number<uint8_t>();
            }

            case 0x39: // Negative integer -1-n (two-byte uint16_t follows)
            {
                return static_cast<number_integer_t>(-1) - get_number<uint16_t>();
            }

            case 0x3A: // Negative integer -1-n (four-byte uint32_t follows)
            {
                return static_cast<number_integer_t>(-1) - get_number<uint32_t>();
            }

            case 0x3B: // Negative integer -1-n (eight-byte uint64_t follows)
            {
                return static_cast<number_integer_t>(-1) -
                       static_cast<number_integer_t>(get_number<uint64_t>());
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
                return get_cbor_string();
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
            {
                return get_cbor_array(current & 0x1F);
            }

            case 0x98: // array (one-byte uint8_t for n follows)
            {
                return get_cbor_array(get_number<uint8_t>());
            }

            case 0x99: // array (two-byte uint16_t for n follow)
            {
                return get_cbor_array(get_number<uint16_t>());
            }

            case 0x9A: // array (four-byte uint32_t for n follow)
            {
                return get_cbor_array(get_number<uint32_t>());
            }

            case 0x9B: // array (eight-byte uint64_t for n follow)
            {
                return get_cbor_array(get_number<uint64_t>());
            }

            case 0x9F: // array (indefinite length)
            {
                BasicJsonType result = value_t::array;
                while (get() != 0xFF)
                {
                    result.push_back(parse_cbor_internal(false));
                }
                return result;
            }

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
            {
                return get_cbor_object(current & 0x1F);
            }

            case 0xB8: // map (one-byte uint8_t for n follows)
            {
                return get_cbor_object(get_number<uint8_t>());
            }

            case 0xB9: // map (two-byte uint16_t for n follow)
            {
                return get_cbor_object(get_number<uint16_t>());
            }

            case 0xBA: // map (four-byte uint32_t for n follow)
            {
                return get_cbor_object(get_number<uint32_t>());
            }

            case 0xBB: // map (eight-byte uint64_t for n follow)
            {
                return get_cbor_object(get_number<uint64_t>());
            }

            case 0xBF: // map (indefinite length)
            {
                BasicJsonType result = value_t::object;
                while (get() != 0xFF)
                {
                    auto key = get_cbor_string();
                    result[key] = parse_cbor_internal();
                }
                return result;
            }

            case 0xF4: // false
            {
                return false;
            }

            case 0xF5: // true
            {
                return true;
            }

            case 0xF6: // null
            {
                return value_t::null;
            }

            case 0xF9: // Half-Precision Float (two-byte IEEE 754)
            {
                const int byte1 = get();
                unexpect_eof();
                const int byte2 = get();
                unexpect_eof();

                // code from RFC 7049, Appendix D, Figure 3:
                // As half-precision floating-point numbers were only added
                // to IEEE 754 in 2008, today's programming platforms often
                // still only have limited support for them. It is very
                // easy to include at least decoding support for them even
                // without such support. An example of a small decoder for
                // half-precision floating-point numbers in the C language
                // is shown in Fig. 3.
                const int half = (byte1 << 8) + byte2;
                const int exp = (half >> 10) & 0x1F;
                const int mant = half & 0x3FF;
                double val;
                if (exp == 0)
                {
                    val = std::ldexp(mant, -24);
                }
                else if (exp != 31)
                {
                    val = std::ldexp(mant + 1024, exp - 25);
                }
                else
                {
                    val = (mant == 0) ? std::numeric_limits<double>::infinity()
                          : std::numeric_limits<double>::quiet_NaN();
                }
                return (half & 0x8000) != 0 ? -val : val;
            }

            case 0xFA: // Single-Precision Float (four-byte IEEE 754)
            {
                return get_number<float>();
            }

            case 0xFB: // Double-Precision Float (eight-byte IEEE 754)
            {
                return get_number<double>();
            }

            default: // anything else (0xFF is handled inside the other types)
            {
                std::stringstream ss;
                ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << current;
                JSON_THROW(parse_error::create(112, chars_read, "error reading CBOR; last byte: 0x" + ss.str()));
            }
        }
    }

    BasicJsonType parse_msgpack_internal()
    {
        switch (get())
        {
            // EOF
            case std::char_traits<char>::eof():
                JSON_THROW(parse_error::create(110, chars_read, "unexpected end of input"));

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
                return static_cast<number_unsigned_t>(current);

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
            {
                return get_msgpack_object(current & 0x0F);
            }

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
            {
                return get_msgpack_array(current & 0x0F);
            }

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
                return get_msgpack_string();

            case 0xC0: // nil
                return value_t::null;

            case 0xC2: // false
                return false;

            case 0xC3: // true
                return true;

            case 0xCA: // float 32
                return get_number<float>();

            case 0xCB: // float 64
                return get_number<double>();

            case 0xCC: // uint 8
                return get_number<uint8_t>();

            case 0xCD: // uint 16
                return get_number<uint16_t>();

            case 0xCE: // uint 32
                return get_number<uint32_t>();

            case 0xCF: // uint 64
                return get_number<uint64_t>();

            case 0xD0: // int 8
                return get_number<int8_t>();

            case 0xD1: // int 16
                return get_number<int16_t>();

            case 0xD2: // int 32
                return get_number<int32_t>();

            case 0xD3: // int 64
                return get_number<int64_t>();

            case 0xD9: // str 8
            case 0xDA: // str 16
            case 0xDB: // str 32
                return get_msgpack_string();

            case 0xDC: // array 16
            {
                return get_msgpack_array(get_number<uint16_t>());
            }

            case 0xDD: // array 32
            {
                return get_msgpack_array(get_number<uint32_t>());
            }

            case 0xDE: // map 16
            {
                return get_msgpack_object(get_number<uint16_t>());
            }

            case 0xDF: // map 32
            {
                return get_msgpack_object(get_number<uint32_t>());
            }

            // positive fixint
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
                return static_cast<int8_t>(current);

            default: // anything else
            {
                std::stringstream ss;
                ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << current;
                JSON_THROW(parse_error::create(112, chars_read,
                                               "error reading MessagePack; last byte: 0x" + ss.str()));
            }
        }
    }

    /*!
    @param[in] get_char  whether a new character should be retrieved from the
                         input (true, default) or whether the last read
                         character should be considered instead
    */
    BasicJsonType parse_ubjson_internal(const bool get_char = true)
    {
        return get_ubjson_value(get_char ? get_ignore_noop() : current);
    }

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
        return (current = ia->get_character());
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

    @return number of type @a NumberType

    @note This function needs to respect the system's endianess, because
          bytes in CBOR and MessagePack are stored in network order (big
          endian) and therefore need reordering on little endian systems.

    @throw parse_error.110 if input has less than `sizeof(NumberType)` bytes
    */
    template<typename NumberType> NumberType get_number()
    {
        // step 1: read input into array with system's byte order
        std::array<uint8_t, sizeof(NumberType)> vec;
        for (std::size_t i = 0; i < sizeof(NumberType); ++i)
        {
            get();
            unexpect_eof();

            // reverse byte order prior to conversion if necessary
            if (is_little_endian)
            {
                vec[sizeof(NumberType) - i - 1] = static_cast<uint8_t>(current);
            }
            else
            {
                vec[i] = static_cast<uint8_t>(current); // LCOV_EXCL_LINE
            }
        }

        // step 2: convert array into number of type T and return
        NumberType result;
        std::memcpy(&result, vec.data(), sizeof(NumberType));
        return result;
    }

    /*!
    @brief create a string by reading characters from the input

    @param[in] len number of bytes to read

    @note We can not reserve @a len bytes for the result, because @a len
          may be too large. Usually, @ref unexpect_eof() detects the end of
          the input before we run out of string memory.

    @return string created by reading @a len bytes

    @throw parse_error.110 if input has less than @a len bytes
    */
    template<typename NumberType>
    string_t get_string(const NumberType len)
    {
        string_t result;
        std::generate_n(std::back_inserter(result), len, [this]()
        {
            get();
            unexpect_eof();
            return static_cast<char>(current);
        });
        return result;
    }

    /*!
    @brief reads a CBOR string

    This function first reads starting bytes to determine the expected
    string length and then copies this number of bytes into a string.
    Additionally, CBOR's strings with indefinite lengths are supported.

    @return string

    @throw parse_error.110 if input ended
    @throw parse_error.113 if an unexpected byte is read
    */
    string_t get_cbor_string()
    {
        unexpect_eof();

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
                return get_string(current & 0x1F);
            }

            case 0x78: // UTF-8 string (one-byte uint8_t for n follows)
            {
                return get_string(get_number<uint8_t>());
            }

            case 0x79: // UTF-8 string (two-byte uint16_t for n follow)
            {
                return get_string(get_number<uint16_t>());
            }

            case 0x7A: // UTF-8 string (four-byte uint32_t for n follow)
            {
                return get_string(get_number<uint32_t>());
            }

            case 0x7B: // UTF-8 string (eight-byte uint64_t for n follow)
            {
                return get_string(get_number<uint64_t>());
            }

            case 0x7F: // UTF-8 string (indefinite length)
            {
                string_t result;
                while (get() != 0xFF)
                {
                    result.append(get_cbor_string());
                }
                return result;
            }

            default:
            {
                std::stringstream ss;
                ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << current;
                JSON_THROW(parse_error::create(113, chars_read, "expected a CBOR string; last byte: 0x" + ss.str()));
            }
        }
    }

    template<typename NumberType>
    BasicJsonType get_cbor_array(const NumberType len)
    {
        BasicJsonType result = value_t::array;
        std::generate_n(std::back_inserter(*result.m_value.array), len, [this]()
        {
            return parse_cbor_internal();
        });
        return result;
    }

    template<typename NumberType>
    BasicJsonType get_cbor_object(const NumberType len)
    {
        BasicJsonType result = value_t::object;
        std::generate_n(std::inserter(*result.m_value.object,
                                      result.m_value.object->end()),
                        len, [this]()
        {
            get();
            auto key = get_cbor_string();
            auto val = parse_cbor_internal();
            return std::make_pair(std::move(key), std::move(val));
        });
        return result;
    }

    /*!
    @brief reads a MessagePack string

    This function first reads starting bytes to determine the expected
    string length and then copies this number of bytes into a string.

    @return string

    @throw parse_error.110 if input ended
    @throw parse_error.113 if an unexpected byte is read
    */
    string_t get_msgpack_string()
    {
        unexpect_eof();

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
                return get_string(current & 0x1F);
            }

            case 0xD9: // str 8
            {
                return get_string(get_number<uint8_t>());
            }

            case 0xDA: // str 16
            {
                return get_string(get_number<uint16_t>());
            }

            case 0xDB: // str 32
            {
                return get_string(get_number<uint32_t>());
            }

            default:
            {
                std::stringstream ss;
                ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << current;
                JSON_THROW(parse_error::create(113, chars_read,
                                               "expected a MessagePack string; last byte: 0x" + ss.str()));
            }
        }
    }

    template<typename NumberType>
    BasicJsonType get_msgpack_array(const NumberType len)
    {
        BasicJsonType result = value_t::array;
        std::generate_n(std::back_inserter(*result.m_value.array), len, [this]()
        {
            return parse_msgpack_internal();
        });
        return result;
    }

    template<typename NumberType>
    BasicJsonType get_msgpack_object(const NumberType len)
    {
        BasicJsonType result = value_t::object;
        std::generate_n(std::inserter(*result.m_value.object,
                                      result.m_value.object->end()),
                        len, [this]()
        {
            get();
            auto key = get_msgpack_string();
            auto val = parse_msgpack_internal();
            return std::make_pair(std::move(key), std::move(val));
        });
        return result;
    }

    /*!
    @brief reads a UBJSON string

    This function is either called after reading the 'S' byte explicitly
    indicating a string, or in case of an object key where the 'S' byte can be
    left out.

    @param[in] get_char  whether a new character should be retrieved from the
                         input (true, default) or whether the last read
                         character should be considered instead

    @return string

    @throw parse_error.110 if input ended
    @throw parse_error.113 if an unexpected byte is read
    */
    string_t get_ubjson_string(const bool get_char = true)
    {
        if (get_char)
        {
            get();  // TODO: may we ignore N here?
        }

        unexpect_eof();

        switch (current)
        {
            case 'U':
                return get_string(get_number<uint8_t>());
            case 'i':
                return get_string(get_number<int8_t>());
            case 'I':
                return get_string(get_number<int16_t>());
            case 'l':
                return get_string(get_number<int32_t>());
            case 'L':
                return get_string(get_number<int64_t>());
            default:
                std::stringstream ss;
                ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << current;
                JSON_THROW(parse_error::create(113, chars_read,
                                               "expected a UBJSON string; last byte: 0x" + ss.str()));
        }
    }

    /*!
    @brief determine the type and size for a container

    In the optimized UBJSON format, a type and a size can be provided to allow
    for a more compact representation.

    @return pair of the size and the type
    */
    std::pair<std::size_t, int> get_ubjson_size_type()
    {
        std::size_t sz = string_t::npos;
        int tc = 0;

        get_ignore_noop();

        if (current == '$')
        {
            tc = get();  // must not ignore 'N', because 'N' maybe the type
            unexpect_eof();

            get_ignore_noop();
            if (current != '#')
            {
                std::stringstream ss;
                ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << current;
                JSON_THROW(parse_error::create(112, chars_read,
                                               "expected '#' after UBJSON type information; last byte: 0x" + ss.str()));
            }
            sz = parse_ubjson_internal();
        }
        else if (current == '#')
        {
            sz = parse_ubjson_internal();
        }

        return std::make_pair(sz, tc);
    }

    BasicJsonType get_ubjson_value(const int prefix)
    {
        switch (prefix)
        {
            case std::char_traits<char>::eof():  // EOF
                JSON_THROW(parse_error::create(110, chars_read, "unexpected end of input"));

            case 'T':  // true
                return true;
            case 'F':  // false
                return false;

            case 'Z':  // null
                return nullptr;

            case 'U':
                return get_number<uint8_t>();
            case 'i':
                return get_number<int8_t>();
            case 'I':
                return get_number<int16_t>();
            case 'l':
                return get_number<int32_t>();
            case 'L':
                return get_number<int64_t>();
            case 'd':
                return get_number<float>();
            case 'D':
                return get_number<double>();

            case 'C':  // char
            {
                get();
                unexpect_eof();
                if (JSON_UNLIKELY(current > 127))
                {
                    std::stringstream ss;
                    ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << current;
                    JSON_THROW(parse_error::create(113, chars_read,
                                                   "byte after 'C' must be in range 0x00..0x7F; last byte: 0x" + ss.str()));
                }
                return string_t(1, static_cast<char>(current));
            }

            case 'S':  // string
                return get_ubjson_string();

            case '[':  // array
                return get_ubjson_array();

            case '{':  // object
                return get_ubjson_object();

            default: // anything else
                std::stringstream ss;
                ss << std::setw(2) << std::uppercase << std::setfill('0') << std::hex << current;
                JSON_THROW(parse_error::create(112, chars_read,
                                               "error reading UBJSON; last byte: 0x" + ss.str()));
        }
    }

    BasicJsonType get_ubjson_array()
    {
        BasicJsonType result = value_t::array;
        const auto size_and_type = get_ubjson_size_type();

        if (size_and_type.first != string_t::npos)
        {
            if (JSON_UNLIKELY(size_and_type.first > result.max_size()))
            {
                JSON_THROW(out_of_range::create(408,
                                                "excessive array size: " + std::to_string(size_and_type.first)));
            }

            if (size_and_type.second != 0)
            {
                if (size_and_type.second != 'N')
                {
                    std::generate_n(std::back_inserter(*result.m_value.array),
                                    size_and_type.first, [this, size_and_type]()
                    {
                        return get_ubjson_value(size_and_type.second);
                    });
                }
            }
            else
            {
                std::generate_n(std::back_inserter(*result.m_value.array),
                                size_and_type.first, [this]()
                {
                    return parse_ubjson_internal();
                });
            }
        }
        else
        {
            while (current != ']')
            {
                result.push_back(parse_ubjson_internal(false));
                get_ignore_noop();
            }
        }

        return result;
    }

    BasicJsonType get_ubjson_object()
    {
        BasicJsonType result = value_t::object;
        const auto size_and_type = get_ubjson_size_type();

        if (size_and_type.first != string_t::npos)
        {
            if (JSON_UNLIKELY(size_and_type.first > result.max_size()))
            {
                JSON_THROW(out_of_range::create(408,
                                                "excessive object size: " + std::to_string(size_and_type.first)));
            }

            if (size_and_type.second != 0)
            {
                std::generate_n(std::inserter(*result.m_value.object,
                                              result.m_value.object->end()),
                                size_and_type.first, [this, size_and_type]()
                {
                    auto key = get_ubjson_string();
                    auto val = get_ubjson_value(size_and_type.second);
                    return std::make_pair(std::move(key), std::move(val));
                });
            }
            else
            {
                std::generate_n(std::inserter(*result.m_value.object,
                                              result.m_value.object->end()),
                                size_and_type.first, [this]()
                {
                    auto key = get_ubjson_string();
                    auto val = parse_ubjson_internal();
                    return std::make_pair(std::move(key), std::move(val));
                });
            }
        }
        else
        {
            while (current != '}')
            {
                auto key = get_ubjson_string(false);
                result[std::move(key)] = parse_ubjson_internal();
                get_ignore_noop();
            }
        }

        return result;
    }

    /*!
    @brief throw if end of input is not reached
    @throw parse_error.110 if input not ended
    */
    void expect_eof() const
    {
        if (JSON_UNLIKELY(current != std::char_traits<char>::eof()))
        {
            JSON_THROW(parse_error::create(110, chars_read, "expected end of input"));
        }
    }

    /*!
    @briefthrow if end of input is reached
    @throw parse_error.110 if input ended
    */
    void unexpect_eof() const
    {
        if (JSON_UNLIKELY(current == std::char_traits<char>::eof()))
        {
            JSON_THROW(parse_error::create(110, chars_read, "unexpected end of input"));
        }
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
};
}
}
