#pragma once

#include <algorithm> // reverse
#include <array> // array
#include <cmath> // isnan, isinf
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcpy
#include <limits> // numeric_limits
#include <string> // string
#include <utility> // move

#include <nlohmann/detail/input/binary_reader.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/output/output_adapters.hpp>

namespace nlohmann
{
namespace detail
{
///////////////////
// binary writer //
///////////////////

/*!
@brief serialization to CBOR and MessagePack values
*/
template<typename BasicJsonType, typename CharType>
class binary_writer
{
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;
    using number_float_t = typename BasicJsonType::number_float_t;

  public:
    /*!
    @brief create a binary writer

    @param[in] adapter  output adapter to write to
    */
    explicit binary_writer(output_adapter_t<CharType> adapter) : oa(std::move(adapter))
    {
        JSON_ASSERT(oa);
    }

    /*!
    @param[in] j  JSON value to serialize
    @pre       j.type() == value_t::object
    */
    void write_bson(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::object:
            {
                write_bson_object(*j.m_value.object);
                break;
            }

            case value_t::null:
            case value_t::array:
            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            case value_t::discarded:
            default:
            {
                JSON_THROW(type_error::create(317, "to serialize to BSON, top-level type must be object, but is " + std::string(j.type_name()), j));
            }
        }
    }

    /*!
    @param[in] j  JSON value to serialize
    */
    void write_cbor(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null:
            {
                oa->write_character(to_char_type(0xF6));
                break;
            }

            case value_t::boolean:
            {
                oa->write_character(j.m_value.boolean
                                    ? to_char_type(0xF5)
                                    : to_char_type(0xF4));
                break;
            }

            case value_t::number_integer:
            {
                if (j.m_value.number_integer >= 0)
                {
                    // CBOR does not differentiate between positive signed
                    // integers and unsigned integers. Therefore, we used the
                    // code from the value_t::number_unsigned case here.
                    if (j.m_value.number_integer <= 0x17)
                    {
                        write_number(static_cast<std::uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<std::uint8_t>::max)())
                    {
                        oa->write_character(to_char_type(0x18));
                        write_number(static_cast<std::uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<std::uint16_t>::max)())
                    {
                        oa->write_character(to_char_type(0x19));
                        write_number(static_cast<std::uint16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<std::uint32_t>::max)())
                    {
                        oa->write_character(to_char_type(0x1A));
                        write_number(static_cast<std::uint32_t>(j.m_value.number_integer));
                    }
                    else
                    {
                        oa->write_character(to_char_type(0x1B));
                        write_number(static_cast<std::uint64_t>(j.m_value.number_integer));
                    }
                }
                else
                {
                    // The conversions below encode the sign in the first
                    // byte, and the value is converted to a positive number.
                    const auto positive_number = -1 - j.m_value.number_integer;
                    if (j.m_value.number_integer >= -24)
                    {
                        write_number(static_cast<std::uint8_t>(0x20 + positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<std::uint8_t>::max)())
                    {
                        oa->write_character(to_char_type(0x38));
                        write_number(static_cast<std::uint8_t>(positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<std::uint16_t>::max)())
                    {
                        oa->write_character(to_char_type(0x39));
                        write_number(static_cast<std::uint16_t>(positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<std::uint32_t>::max)())
                    {
                        oa->write_character(to_char_type(0x3A));
                        write_number(static_cast<std::uint32_t>(positive_number));
                    }
                    else
                    {
                        oa->write_character(to_char_type(0x3B));
                        write_number(static_cast<std::uint64_t>(positive_number));
                    }
                }
                break;
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned <= 0x17)
                {
                    write_number(static_cast<std::uint8_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    oa->write_character(to_char_type(0x18));
                    write_number(static_cast<std::uint8_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    oa->write_character(to_char_type(0x19));
                    write_number(static_cast<std::uint16_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    oa->write_character(to_char_type(0x1A));
                    write_number(static_cast<std::uint32_t>(j.m_value.number_unsigned));
                }
                else
                {
                    oa->write_character(to_char_type(0x1B));
                    write_number(static_cast<std::uint64_t>(j.m_value.number_unsigned));
                }
                break;
            }

            case value_t::number_float:
            {
                if (std::isnan(j.m_value.number_float))
                {
                    // NaN is 0xf97e00 in CBOR
                    oa->write_character(to_char_type(0xF9));
                    oa->write_character(to_char_type(0x7E));
                    oa->write_character(to_char_type(0x00));
                }
                else if (std::isinf(j.m_value.number_float))
                {
                    // Infinity is 0xf97c00, -Infinity is 0xf9fc00
                    oa->write_character(to_char_type(0xf9));
                    oa->write_character(j.m_value.number_float > 0 ? to_char_type(0x7C) : to_char_type(0xFC));
                    oa->write_character(to_char_type(0x00));
                }
                else
                {
                    write_compact_float(j.m_value.number_float, detail::input_format_t::cbor);
                }
                break;
            }

            case value_t::string:
            {
                // step 1: write control byte and the string length
                const auto N = j.m_value.string->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<std::uint8_t>(0x60 + N));
                }
                else if (N <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    oa->write_character(to_char_type(0x78));
                    write_number(static_cast<std::uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    oa->write_character(to_char_type(0x79));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    oa->write_character(to_char_type(0x7A));
                    write_number(static_cast<std::uint32_t>(N));
                }
                // LCOV_EXCL_START
                else if (N <= (std::numeric_limits<std::uint64_t>::max)())
                {
                    oa->write_character(to_char_type(0x7B));
                    write_number(static_cast<std::uint64_t>(N));
                }
                // LCOV_EXCL_STOP

                // step 2: write the string
                oa->write_characters(
                    reinterpret_cast<const CharType*>(j.m_value.string->c_str()),
                    j.m_value.string->size());
                break;
            }

            case value_t::array:
            {
                // step 1: write control byte and the array size
                const auto N = j.m_value.array->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<std::uint8_t>(0x80 + N));
                }
                else if (N <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    oa->write_character(to_char_type(0x98));
                    write_number(static_cast<std::uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    oa->write_character(to_char_type(0x99));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    oa->write_character(to_char_type(0x9A));
                    write_number(static_cast<std::uint32_t>(N));
                }
                // LCOV_EXCL_START
                else if (N <= (std::numeric_limits<std::uint64_t>::max)())
                {
                    oa->write_character(to_char_type(0x9B));
                    write_number(static_cast<std::uint64_t>(N));
                }
                // LCOV_EXCL_STOP

                // step 2: write each element
                for (const auto& el : *j.m_value.array)
                {
                    write_cbor(el);
                }
                break;
            }

            case value_t::binary:
            {
                if (j.m_value.binary->has_subtype())
                {
                    if (j.m_value.binary->subtype() <= (std::numeric_limits<std::uint8_t>::max)())
                    {
                        write_number(static_cast<std::uint8_t>(0xd8));
                        write_number(static_cast<std::uint8_t>(j.m_value.binary->subtype()));
                    }
                    else if (j.m_value.binary->subtype() <= (std::numeric_limits<std::uint16_t>::max)())
                    {
                        write_number(static_cast<std::uint8_t>(0xd9));
                        write_number(static_cast<std::uint16_t>(j.m_value.binary->subtype()));
                    }
                    else if (j.m_value.binary->subtype() <= (std::numeric_limits<std::uint32_t>::max)())
                    {
                        write_number(static_cast<std::uint8_t>(0xda));
                        write_number(static_cast<std::uint32_t>(j.m_value.binary->subtype()));
                    }
                    else if (j.m_value.binary->subtype() <= (std::numeric_limits<std::uint64_t>::max)())
                    {
                        write_number(static_cast<std::uint8_t>(0xdb));
                        write_number(static_cast<std::uint64_t>(j.m_value.binary->subtype()));
                    }
                }

                // step 1: write control byte and the binary array size
                const auto N = j.m_value.binary->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<std::uint8_t>(0x40 + N));
                }
                else if (N <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    oa->write_character(to_char_type(0x58));
                    write_number(static_cast<std::uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    oa->write_character(to_char_type(0x59));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    oa->write_character(to_char_type(0x5A));
                    write_number(static_cast<std::uint32_t>(N));
                }
                // LCOV_EXCL_START
                else if (N <= (std::numeric_limits<std::uint64_t>::max)())
                {
                    oa->write_character(to_char_type(0x5B));
                    write_number(static_cast<std::uint64_t>(N));
                }
                // LCOV_EXCL_STOP

                // step 2: write each element
                oa->write_characters(
                    reinterpret_cast<const CharType*>(j.m_value.binary->data()),
                    N);

                break;
            }

            case value_t::object:
            {
                // step 1: write control byte and the object size
                const auto N = j.m_value.object->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<std::uint8_t>(0xA0 + N));
                }
                else if (N <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    oa->write_character(to_char_type(0xB8));
                    write_number(static_cast<std::uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    oa->write_character(to_char_type(0xB9));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    oa->write_character(to_char_type(0xBA));
                    write_number(static_cast<std::uint32_t>(N));
                }
                // LCOV_EXCL_START
                else if (N <= (std::numeric_limits<std::uint64_t>::max)())
                {
                    oa->write_character(to_char_type(0xBB));
                    write_number(static_cast<std::uint64_t>(N));
                }
                // LCOV_EXCL_STOP

                // step 2: write each element
                for (const auto& el : *j.m_value.object)
                {
                    write_cbor(el.first);
                    write_cbor(el.second);
                }
                break;
            }

            case value_t::discarded:
            default:
                break;
        }
    }

    /*!
    @param[in] j  JSON value to serialize
    */
    void write_msgpack(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null: // nil
            {
                oa->write_character(to_char_type(0xC0));
                break;
            }

            case value_t::boolean: // true and false
            {
                oa->write_character(j.m_value.boolean
                                    ? to_char_type(0xC3)
                                    : to_char_type(0xC2));
                break;
            }

            case value_t::number_integer:
            {
                if (j.m_value.number_integer >= 0)
                {
                    // MessagePack does not differentiate between positive
                    // signed integers and unsigned integers. Therefore, we used
                    // the code from the value_t::number_unsigned case here.
                    if (j.m_value.number_unsigned < 128)
                    {
                        // positive fixnum
                        write_number(static_cast<std::uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint8_t>::max)())
                    {
                        // uint 8
                        oa->write_character(to_char_type(0xCC));
                        write_number(static_cast<std::uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint16_t>::max)())
                    {
                        // uint 16
                        oa->write_character(to_char_type(0xCD));
                        write_number(static_cast<std::uint16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint32_t>::max)())
                    {
                        // uint 32
                        oa->write_character(to_char_type(0xCE));
                        write_number(static_cast<std::uint32_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint64_t>::max)())
                    {
                        // uint 64
                        oa->write_character(to_char_type(0xCF));
                        write_number(static_cast<std::uint64_t>(j.m_value.number_integer));
                    }
                }
                else
                {
                    if (j.m_value.number_integer >= -32)
                    {
                        // negative fixnum
                        write_number(static_cast<std::int8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<std::int8_t>::min)() &&
                             j.m_value.number_integer <= (std::numeric_limits<std::int8_t>::max)())
                    {
                        // int 8
                        oa->write_character(to_char_type(0xD0));
                        write_number(static_cast<std::int8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<std::int16_t>::min)() &&
                             j.m_value.number_integer <= (std::numeric_limits<std::int16_t>::max)())
                    {
                        // int 16
                        oa->write_character(to_char_type(0xD1));
                        write_number(static_cast<std::int16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<std::int32_t>::min)() &&
                             j.m_value.number_integer <= (std::numeric_limits<std::int32_t>::max)())
                    {
                        // int 32
                        oa->write_character(to_char_type(0xD2));
                        write_number(static_cast<std::int32_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<std::int64_t>::min)() &&
                             j.m_value.number_integer <= (std::numeric_limits<std::int64_t>::max)())
                    {
                        // int 64
                        oa->write_character(to_char_type(0xD3));
                        write_number(static_cast<std::int64_t>(j.m_value.number_integer));
                    }
                }
                break;
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned < 128)
                {
                    // positive fixnum
                    write_number(static_cast<std::uint8_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    // uint 8
                    oa->write_character(to_char_type(0xCC));
                    write_number(static_cast<std::uint8_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    // uint 16
                    oa->write_character(to_char_type(0xCD));
                    write_number(static_cast<std::uint16_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    // uint 32
                    oa->write_character(to_char_type(0xCE));
                    write_number(static_cast<std::uint32_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<std::uint64_t>::max)())
                {
                    // uint 64
                    oa->write_character(to_char_type(0xCF));
                    write_number(static_cast<std::uint64_t>(j.m_value.number_integer));
                }
                break;
            }

            case value_t::number_float:
            {
                write_compact_float(j.m_value.number_float, detail::input_format_t::msgpack);
                break;
            }

            case value_t::string:
            {
                // step 1: write control byte and the string length
                const auto N = j.m_value.string->size();
                if (N <= 31)
                {
                    // fixstr
                    write_number(static_cast<std::uint8_t>(0xA0 | N));
                }
                else if (N <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    // str 8
                    oa->write_character(to_char_type(0xD9));
                    write_number(static_cast<std::uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    // str 16
                    oa->write_character(to_char_type(0xDA));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    // str 32
                    oa->write_character(to_char_type(0xDB));
                    write_number(static_cast<std::uint32_t>(N));
                }

                // step 2: write the string
                oa->write_characters(
                    reinterpret_cast<const CharType*>(j.m_value.string->c_str()),
                    j.m_value.string->size());
                break;
            }

            case value_t::array:
            {
                // step 1: write control byte and the array size
                const auto N = j.m_value.array->size();
                if (N <= 15)
                {
                    // fixarray
                    write_number(static_cast<std::uint8_t>(0x90 | N));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    // array 16
                    oa->write_character(to_char_type(0xDC));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    // array 32
                    oa->write_character(to_char_type(0xDD));
                    write_number(static_cast<std::uint32_t>(N));
                }

                // step 2: write each element
                for (const auto& el : *j.m_value.array)
                {
                    write_msgpack(el);
                }
                break;
            }

            case value_t::binary:
            {
                // step 0: determine if the binary type has a set subtype to
                // determine whether or not to use the ext or fixext types
                const bool use_ext = j.m_value.binary->has_subtype();

                // step 1: write control byte and the byte string length
                const auto N = j.m_value.binary->size();
                if (N <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    std::uint8_t output_type{};
                    bool fixed = true;
                    if (use_ext)
                    {
                        switch (N)
                        {
                            case 1:
                                output_type = 0xD4; // fixext 1
                                break;
                            case 2:
                                output_type = 0xD5; // fixext 2
                                break;
                            case 4:
                                output_type = 0xD6; // fixext 4
                                break;
                            case 8:
                                output_type = 0xD7; // fixext 8
                                break;
                            case 16:
                                output_type = 0xD8; // fixext 16
                                break;
                            default:
                                output_type = 0xC7; // ext 8
                                fixed = false;
                                break;
                        }

                    }
                    else
                    {
                        output_type = 0xC4; // bin 8
                        fixed = false;
                    }

                    oa->write_character(to_char_type(output_type));
                    if (!fixed)
                    {
                        write_number(static_cast<std::uint8_t>(N));
                    }
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    std::uint8_t output_type = use_ext
                                               ? 0xC8 // ext 16
                                               : 0xC5; // bin 16

                    oa->write_character(to_char_type(output_type));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    std::uint8_t output_type = use_ext
                                               ? 0xC9 // ext 32
                                               : 0xC6; // bin 32

                    oa->write_character(to_char_type(output_type));
                    write_number(static_cast<std::uint32_t>(N));
                }

                // step 1.5: if this is an ext type, write the subtype
                if (use_ext)
                {
                    write_number(static_cast<std::int8_t>(j.m_value.binary->subtype()));
                }

                // step 2: write the byte string
                oa->write_characters(
                    reinterpret_cast<const CharType*>(j.m_value.binary->data()),
                    N);

                break;
            }

            case value_t::object:
            {
                // step 1: write control byte and the object size
                const auto N = j.m_value.object->size();
                if (N <= 15)
                {
                    // fixmap
                    write_number(static_cast<std::uint8_t>(0x80 | (N & 0xF)));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    // map 16
                    oa->write_character(to_char_type(0xDE));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint32_t>::max)())
                {
                    // map 32
                    oa->write_character(to_char_type(0xDF));
                    write_number(static_cast<std::uint32_t>(N));
                }

                // step 2: write each element
                for (const auto& el : *j.m_value.object)
                {
                    write_msgpack(el.first);
                    write_msgpack(el.second);
                }
                break;
            }

            case value_t::discarded:
            default:
                break;
        }
    }

    /*!
    @param[in] j  JSON value to serialize
    @param[in] use_count   whether to use '#' prefixes (optimized format)
    @param[in] use_type    whether to use '$' prefixes (optimized format)
    @param[in] add_prefix  whether prefixes need to be used for this value
    */
    void write_ubjson(const BasicJsonType& j, const bool use_count,
                      const bool use_type, const bool add_prefix = true)
    {
        switch (j.type())
        {
            case value_t::null:
            {
                if (add_prefix)
                {
                    oa->write_character(to_char_type('Z'));
                }
                break;
            }

            case value_t::boolean:
            {
                if (add_prefix)
                {
                    oa->write_character(j.m_value.boolean
                                        ? to_char_type('T')
                                        : to_char_type('F'));
                }
                break;
            }

            case value_t::number_integer:
            {
                write_number_with_ubjson_prefix(j.m_value.number_integer, add_prefix);
                break;
            }

            case value_t::number_unsigned:
            {
                write_number_with_ubjson_prefix(j.m_value.number_unsigned, add_prefix);
                break;
            }

            case value_t::number_float:
            {
                write_number_with_ubjson_prefix(j.m_value.number_float, add_prefix);
                break;
            }

            case value_t::string:
            {
                if (add_prefix)
                {
                    oa->write_character(to_char_type('S'));
                }
                write_number_with_ubjson_prefix(j.m_value.string->size(), true);
                oa->write_characters(
                    reinterpret_cast<const CharType*>(j.m_value.string->c_str()),
                    j.m_value.string->size());
                break;
            }

            case value_t::array:
            {
                if (add_prefix)
                {
                    oa->write_character(to_char_type('['));
                }

                bool prefix_required = true;
                if (use_type && !j.m_value.array->empty())
                {
                    JSON_ASSERT(use_count);
                    const CharType first_prefix = ubjson_prefix(j.front());
                    const bool same_prefix = std::all_of(j.begin() + 1, j.end(),
                                                         [this, first_prefix](const BasicJsonType & v)
                    {
                        return ubjson_prefix(v) == first_prefix;
                    });

                    if (same_prefix)
                    {
                        prefix_required = false;
                        oa->write_character(to_char_type('$'));
                        oa->write_character(first_prefix);
                    }
                }

                if (use_count)
                {
                    oa->write_character(to_char_type('#'));
                    write_number_with_ubjson_prefix(j.m_value.array->size(), true);
                }

                for (const auto& el : *j.m_value.array)
                {
                    write_ubjson(el, use_count, use_type, prefix_required);
                }

                if (!use_count)
                {
                    oa->write_character(to_char_type(']'));
                }

                break;
            }

            case value_t::binary:
            {
                if (add_prefix)
                {
                    oa->write_character(to_char_type('['));
                }

                if (use_type && !j.m_value.binary->empty())
                {
                    JSON_ASSERT(use_count);
                    oa->write_character(to_char_type('$'));
                    oa->write_character('U');
                }

                if (use_count)
                {
                    oa->write_character(to_char_type('#'));
                    write_number_with_ubjson_prefix(j.m_value.binary->size(), true);
                }

                if (use_type)
                {
                    oa->write_characters(
                        reinterpret_cast<const CharType*>(j.m_value.binary->data()),
                        j.m_value.binary->size());
                }
                else
                {
                    for (size_t i = 0; i < j.m_value.binary->size(); ++i)
                    {
                        oa->write_character(to_char_type('U'));
                        oa->write_character(j.m_value.binary->data()[i]);
                    }
                }

                if (!use_count)
                {
                    oa->write_character(to_char_type(']'));
                }

                break;
            }

            case value_t::object:
            {
                if (add_prefix)
                {
                    oa->write_character(to_char_type('{'));
                }

                bool prefix_required = true;
                if (use_type && !j.m_value.object->empty())
                {
                    JSON_ASSERT(use_count);
                    const CharType first_prefix = ubjson_prefix(j.front());
                    const bool same_prefix = std::all_of(j.begin(), j.end(),
                                                         [this, first_prefix](const BasicJsonType & v)
                    {
                        return ubjson_prefix(v) == first_prefix;
                    });

                    if (same_prefix)
                    {
                        prefix_required = false;
                        oa->write_character(to_char_type('$'));
                        oa->write_character(first_prefix);
                    }
                }

                if (use_count)
                {
                    oa->write_character(to_char_type('#'));
                    write_number_with_ubjson_prefix(j.m_value.object->size(), true);
                }

                for (const auto& el : *j.m_value.object)
                {
                    write_number_with_ubjson_prefix(el.first.size(), true);
                    oa->write_characters(
                        reinterpret_cast<const CharType*>(el.first.c_str()),
                        el.first.size());
                    write_ubjson(el.second, use_count, use_type, prefix_required);
                }

                if (!use_count)
                {
                    oa->write_character(to_char_type('}'));
                }

                break;
            }

            case value_t::discarded:
            default:
                break;
        }
    }

  private:
    //////////
    // BSON //
    //////////

    /*!
    @return The size of a BSON document entry header, including the id marker
            and the entry name size (and its null-terminator).
    */
    static std::size_t calc_bson_entry_header_size(const string_t& name, const BasicJsonType& j)
    {
        const auto it = name.find(static_cast<typename string_t::value_type>(0));
        if (JSON_HEDLEY_UNLIKELY(it != BasicJsonType::string_t::npos))
        {
            JSON_THROW(out_of_range::create(409, "BSON key cannot contain code point U+0000 (at byte " + std::to_string(it) + ")", j));
            static_cast<void>(j);
        }

        return /*id*/ 1ul + name.size() + /*zero-terminator*/1u;
    }

    /*!
    @brief Writes the given @a element_type and @a name to the output adapter
    */
    void write_bson_entry_header(const string_t& name,
                                 const std::uint8_t element_type)
    {
        oa->write_character(to_char_type(element_type)); // boolean
        oa->write_characters(
            reinterpret_cast<const CharType*>(name.c_str()),
            name.size() + 1u);
    }

    /*!
    @brief Writes a BSON element with key @a name and boolean value @a value
    */
    void write_bson_boolean(const string_t& name,
                            const bool value)
    {
        write_bson_entry_header(name, 0x08);
        oa->write_character(value ? to_char_type(0x01) : to_char_type(0x00));
    }

    /*!
    @brief Writes a BSON element with key @a name and double value @a value
    */
    void write_bson_double(const string_t& name,
                           const double value)
    {
        write_bson_entry_header(name, 0x01);
        write_number<double, true>(value);
    }

    /*!
    @return The size of the BSON-encoded string in @a value
    */
    static std::size_t calc_bson_string_size(const string_t& value)
    {
        return sizeof(std::int32_t) + value.size() + 1ul;
    }

    /*!
    @brief Writes a BSON element with key @a name and string value @a value
    */
    void write_bson_string(const string_t& name,
                           const string_t& value)
    {
        write_bson_entry_header(name, 0x02);

        write_number<std::int32_t, true>(static_cast<std::int32_t>(value.size() + 1ul));
        oa->write_characters(
            reinterpret_cast<const CharType*>(value.c_str()),
            value.size() + 1);
    }

    /*!
    @brief Writes a BSON element with key @a name and null value
    */
    void write_bson_null(const string_t& name)
    {
        write_bson_entry_header(name, 0x0A);
    }

    /*!
    @return The size of the BSON-encoded integer @a value
    */
    static std::size_t calc_bson_integer_size(const std::int64_t value)
    {
        return (std::numeric_limits<std::int32_t>::min)() <= value && value <= (std::numeric_limits<std::int32_t>::max)()
               ? sizeof(std::int32_t)
               : sizeof(std::int64_t);
    }

    /*!
    @brief Writes a BSON element with key @a name and integer @a value
    */
    void write_bson_integer(const string_t& name,
                            const std::int64_t value)
    {
        if ((std::numeric_limits<std::int32_t>::min)() <= value && value <= (std::numeric_limits<std::int32_t>::max)())
        {
            write_bson_entry_header(name, 0x10); // int32
            write_number<std::int32_t, true>(static_cast<std::int32_t>(value));
        }
        else
        {
            write_bson_entry_header(name, 0x12); // int64
            write_number<std::int64_t, true>(static_cast<std::int64_t>(value));
        }
    }

    /*!
    @return The size of the BSON-encoded unsigned integer in @a j
    */
    static constexpr std::size_t calc_bson_unsigned_size(const std::uint64_t value) noexcept
    {
        return (value <= static_cast<std::uint64_t>((std::numeric_limits<std::int32_t>::max)()))
               ? sizeof(std::int32_t)
               : sizeof(std::int64_t);
    }

    /*!
    @brief Writes a BSON element with key @a name and unsigned @a value
    */
    void write_bson_unsigned(const string_t& name,
                             const BasicJsonType& j)
    {
        if (j.m_value.number_unsigned <= static_cast<std::uint64_t>((std::numeric_limits<std::int32_t>::max)()))
        {
            write_bson_entry_header(name, 0x10 /* int32 */);
            write_number<std::int32_t, true>(static_cast<std::int32_t>(j.m_value.number_unsigned));
        }
        else if (j.m_value.number_unsigned <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
        {
            write_bson_entry_header(name, 0x12 /* int64 */);
            write_number<std::int64_t, true>(static_cast<std::int64_t>(j.m_value.number_unsigned));
        }
        else
        {
            JSON_THROW(out_of_range::create(407, "integer number " + std::to_string(j.m_value.number_unsigned) + " cannot be represented by BSON as it does not fit int64", j));
        }
    }

    /*!
    @brief Writes a BSON element with key @a name and object @a value
    */
    void write_bson_object_entry(const string_t& name,
                                 const typename BasicJsonType::object_t& value)
    {
        write_bson_entry_header(name, 0x03); // object
        write_bson_object(value);
    }

    /*!
    @return The size of the BSON-encoded array @a value
    */
    static std::size_t calc_bson_array_size(const typename BasicJsonType::array_t& value)
    {
        std::size_t array_index = 0ul;

        const std::size_t embedded_document_size = std::accumulate(std::begin(value), std::end(value), static_cast<std::size_t>(0), [&array_index](std::size_t result, const typename BasicJsonType::array_t::value_type & el)
        {
            return result + calc_bson_element_size(std::to_string(array_index++), el);
        });

        return sizeof(std::int32_t) + embedded_document_size + 1ul;
    }

    /*!
    @return The size of the BSON-encoded binary array @a value
    */
    static std::size_t calc_bson_binary_size(const typename BasicJsonType::binary_t& value)
    {
        return sizeof(std::int32_t) + value.size() + 1ul;
    }

    /*!
    @brief Writes a BSON element with key @a name and array @a value
    */
    void write_bson_array(const string_t& name,
                          const typename BasicJsonType::array_t& value)
    {
        write_bson_entry_header(name, 0x04); // array
        write_number<std::int32_t, true>(static_cast<std::int32_t>(calc_bson_array_size(value)));

        std::size_t array_index = 0ul;

        for (const auto& el : value)
        {
            write_bson_element(std::to_string(array_index++), el);
        }

        oa->write_character(to_char_type(0x00));
    }

    /*!
    @brief Writes a BSON element with key @a name and binary value @a value
    */
    void write_bson_binary(const string_t& name,
                           const binary_t& value)
    {
        write_bson_entry_header(name, 0x05);

        write_number<std::int32_t, true>(static_cast<std::int32_t>(value.size()));
        write_number(value.has_subtype() ? static_cast<std::uint8_t>(value.subtype()) : static_cast<std::uint8_t>(0x00));

        oa->write_characters(reinterpret_cast<const CharType*>(value.data()), value.size());
    }

    /*!
    @brief Calculates the size necessary to serialize the JSON value @a j with its @a name
    @return The calculated size for the BSON document entry for @a j with the given @a name.
    */
    static std::size_t calc_bson_element_size(const string_t& name,
            const BasicJsonType& j)
    {
        const auto header_size = calc_bson_entry_header_size(name, j);
        switch (j.type())
        {
            case value_t::object:
                return header_size + calc_bson_object_size(*j.m_value.object);

            case value_t::array:
                return header_size + calc_bson_array_size(*j.m_value.array);

            case value_t::binary:
                return header_size + calc_bson_binary_size(*j.m_value.binary);

            case value_t::boolean:
                return header_size + 1ul;

            case value_t::number_float:
                return header_size + 8ul;

            case value_t::number_integer:
                return header_size + calc_bson_integer_size(j.m_value.number_integer);

            case value_t::number_unsigned:
                return header_size + calc_bson_unsigned_size(j.m_value.number_unsigned);

            case value_t::string:
                return header_size + calc_bson_string_size(*j.m_value.string);

            case value_t::null:
                return header_size + 0ul;

            // LCOV_EXCL_START
            case value_t::discarded:
            default:
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert)
                return 0ul;
                // LCOV_EXCL_STOP
        }
    }

    /*!
    @brief Serializes the JSON value @a j to BSON and associates it with the
           key @a name.
    @param name The name to associate with the JSON entity @a j within the
                current BSON document
    */
    void write_bson_element(const string_t& name,
                            const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::object:
                return write_bson_object_entry(name, *j.m_value.object);

            case value_t::array:
                return write_bson_array(name, *j.m_value.array);

            case value_t::binary:
                return write_bson_binary(name, *j.m_value.binary);

            case value_t::boolean:
                return write_bson_boolean(name, j.m_value.boolean);

            case value_t::number_float:
                return write_bson_double(name, j.m_value.number_float);

            case value_t::number_integer:
                return write_bson_integer(name, j.m_value.number_integer);

            case value_t::number_unsigned:
                return write_bson_unsigned(name, j);

            case value_t::string:
                return write_bson_string(name, *j.m_value.string);

            case value_t::null:
                return write_bson_null(name);

            // LCOV_EXCL_START
            case value_t::discarded:
            default:
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert)
                return;
                // LCOV_EXCL_STOP
        }
    }

    /*!
    @brief Calculates the size of the BSON serialization of the given
           JSON-object @a j.
    @param[in] value  JSON value to serialize
    @pre       value.type() == value_t::object
    */
    static std::size_t calc_bson_object_size(const typename BasicJsonType::object_t& value)
    {
        std::size_t document_size = std::accumulate(value.begin(), value.end(), static_cast<std::size_t>(0),
                                    [](size_t result, const typename BasicJsonType::object_t::value_type & el)
        {
            return result += calc_bson_element_size(el.first, el.second);
        });

        return sizeof(std::int32_t) + document_size + 1ul;
    }

    /*!
    @param[in] value  JSON value to serialize
    @pre       value.type() == value_t::object
    */
    void write_bson_object(const typename BasicJsonType::object_t& value)
    {
        write_number<std::int32_t, true>(static_cast<std::int32_t>(calc_bson_object_size(value)));

        for (const auto& el : value)
        {
            write_bson_element(el.first, el.second);
        }

        oa->write_character(to_char_type(0x00));
    }

    //////////
    // CBOR //
    //////////

    static constexpr CharType get_cbor_float_prefix(float /*unused*/)
    {
        return to_char_type(0xFA);  // Single-Precision Float
    }

    static constexpr CharType get_cbor_float_prefix(double /*unused*/)
    {
        return to_char_type(0xFB);  // Double-Precision Float
    }

    /////////////
    // MsgPack //
    /////////////

    static constexpr CharType get_msgpack_float_prefix(float /*unused*/)
    {
        return to_char_type(0xCA);  // float 32
    }

    static constexpr CharType get_msgpack_float_prefix(double /*unused*/)
    {
        return to_char_type(0xCB);  // float 64
    }

    ////////////
    // UBJSON //
    ////////////

    // UBJSON: write number (floating point)
    template<typename NumberType, typename std::enable_if<
                 std::is_floating_point<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if (add_prefix)
        {
            oa->write_character(get_ubjson_float_prefix(n));
        }
        write_number(n);
    }

    // UBJSON: write number (unsigned integer)
    template<typename NumberType, typename std::enable_if<
                 std::is_unsigned<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if (n <= static_cast<std::uint64_t>((std::numeric_limits<std::int8_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('i'));  // int8
            }
            write_number(static_cast<std::uint8_t>(n));
        }
        else if (n <= (std::numeric_limits<std::uint8_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('U'));  // uint8
            }
            write_number(static_cast<std::uint8_t>(n));
        }
        else if (n <= static_cast<std::uint64_t>((std::numeric_limits<std::int16_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('I'));  // int16
            }
            write_number(static_cast<std::int16_t>(n));
        }
        else if (n <= static_cast<std::uint64_t>((std::numeric_limits<std::int32_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('l'));  // int32
            }
            write_number(static_cast<std::int32_t>(n));
        }
        else if (n <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('L'));  // int64
            }
            write_number(static_cast<std::int64_t>(n));
        }
        else
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('H'));  // high-precision number
            }

            const auto number = BasicJsonType(n).dump();
            write_number_with_ubjson_prefix(number.size(), true);
            for (std::size_t i = 0; i < number.size(); ++i)
            {
                oa->write_character(to_char_type(static_cast<std::uint8_t>(number[i])));
            }
        }
    }

    // UBJSON: write number (signed integer)
    template < typename NumberType, typename std::enable_if <
                   std::is_signed<NumberType>::value&&
                   !std::is_floating_point<NumberType>::value, int >::type = 0 >
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if ((std::numeric_limits<std::int8_t>::min)() <= n && n <= (std::numeric_limits<std::int8_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('i'));  // int8
            }
            write_number(static_cast<std::int8_t>(n));
        }
        else if (static_cast<std::int64_t>((std::numeric_limits<std::uint8_t>::min)()) <= n && n <= static_cast<std::int64_t>((std::numeric_limits<std::uint8_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('U'));  // uint8
            }
            write_number(static_cast<std::uint8_t>(n));
        }
        else if ((std::numeric_limits<std::int16_t>::min)() <= n && n <= (std::numeric_limits<std::int16_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('I'));  // int16
            }
            write_number(static_cast<std::int16_t>(n));
        }
        else if ((std::numeric_limits<std::int32_t>::min)() <= n && n <= (std::numeric_limits<std::int32_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('l'));  // int32
            }
            write_number(static_cast<std::int32_t>(n));
        }
        else if ((std::numeric_limits<std::int64_t>::min)() <= n && n <= (std::numeric_limits<std::int64_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('L'));  // int64
            }
            write_number(static_cast<std::int64_t>(n));
        }
        // LCOV_EXCL_START
        else
        {
            if (add_prefix)
            {
                oa->write_character(to_char_type('H'));  // high-precision number
            }

            const auto number = BasicJsonType(n).dump();
            write_number_with_ubjson_prefix(number.size(), true);
            for (std::size_t i = 0; i < number.size(); ++i)
            {
                oa->write_character(to_char_type(static_cast<std::uint8_t>(number[i])));
            }
        }
        // LCOV_EXCL_STOP
    }

    /*!
    @brief determine the type prefix of container values
    */
    CharType ubjson_prefix(const BasicJsonType& j) const noexcept
    {
        switch (j.type())
        {
            case value_t::null:
                return 'Z';

            case value_t::boolean:
                return j.m_value.boolean ? 'T' : 'F';

            case value_t::number_integer:
            {
                if ((std::numeric_limits<std::int8_t>::min)() <= j.m_value.number_integer && j.m_value.number_integer <= (std::numeric_limits<std::int8_t>::max)())
                {
                    return 'i';
                }
                if ((std::numeric_limits<std::uint8_t>::min)() <= j.m_value.number_integer && j.m_value.number_integer <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    return 'U';
                }
                if ((std::numeric_limits<std::int16_t>::min)() <= j.m_value.number_integer && j.m_value.number_integer <= (std::numeric_limits<std::int16_t>::max)())
                {
                    return 'I';
                }
                if ((std::numeric_limits<std::int32_t>::min)() <= j.m_value.number_integer && j.m_value.number_integer <= (std::numeric_limits<std::int32_t>::max)())
                {
                    return 'l';
                }
                if ((std::numeric_limits<std::int64_t>::min)() <= j.m_value.number_integer && j.m_value.number_integer <= (std::numeric_limits<std::int64_t>::max)())
                {
                    return 'L';
                }
                // anything else is treated as high-precision number
                return 'H'; // LCOV_EXCL_LINE
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned <= static_cast<std::uint64_t>((std::numeric_limits<std::int8_t>::max)()))
                {
                    return 'i';
                }
                if (j.m_value.number_unsigned <= static_cast<std::uint64_t>((std::numeric_limits<std::uint8_t>::max)()))
                {
                    return 'U';
                }
                if (j.m_value.number_unsigned <= static_cast<std::uint64_t>((std::numeric_limits<std::int16_t>::max)()))
                {
                    return 'I';
                }
                if (j.m_value.number_unsigned <= static_cast<std::uint64_t>((std::numeric_limits<std::int32_t>::max)()))
                {
                    return 'l';
                }
                if (j.m_value.number_unsigned <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
                {
                    return 'L';
                }
                // anything else is treated as high-precision number
                return 'H'; // LCOV_EXCL_LINE
            }

            case value_t::number_float:
                return get_ubjson_float_prefix(j.m_value.number_float);

            case value_t::string:
                return 'S';

            case value_t::array: // fallthrough
            case value_t::binary:
                return '[';

            case value_t::object:
                return '{';

            case value_t::discarded:
            default:  // discarded values
                return 'N';
        }
    }

    static constexpr CharType get_ubjson_float_prefix(float /*unused*/)
    {
        return 'd';  // float 32
    }

    static constexpr CharType get_ubjson_float_prefix(double /*unused*/)
    {
        return 'D';  // float 64
    }

    ///////////////////////
    // Utility functions //
    ///////////////////////

    /*
    @brief write a number to output input
    @param[in] n number of type @a NumberType
    @tparam NumberType the type of the number
    @tparam OutputIsLittleEndian Set to true if output data is
                                 required to be little endian

    @note This function needs to respect the system's endianness, because bytes
          in CBOR, MessagePack, and UBJSON are stored in network order (big
          endian) and therefore need reordering on little endian systems.
    */
    template<typename NumberType, bool OutputIsLittleEndian = false>
    void write_number(const NumberType n)
    {
        // step 1: write number to array of length NumberType
        std::array<CharType, sizeof(NumberType)> vec{};
        std::memcpy(vec.data(), &n, sizeof(NumberType));

        // step 2: write array to output (with possible reordering)
        if (is_little_endian != OutputIsLittleEndian)
        {
            // reverse byte order prior to conversion if necessary
            std::reverse(vec.begin(), vec.end());
        }

        oa->write_characters(vec.data(), sizeof(NumberType));
    }

    void write_compact_float(const number_float_t n, detail::input_format_t format)
    {
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
#endif
        if (static_cast<double>(n) >= static_cast<double>(std::numeric_limits<float>::lowest()) &&
                static_cast<double>(n) <= static_cast<double>((std::numeric_limits<float>::max)()) &&
                static_cast<double>(static_cast<float>(n)) == static_cast<double>(n))
        {
            oa->write_character(format == detail::input_format_t::cbor
                                ? get_cbor_float_prefix(static_cast<float>(n))
                                : get_msgpack_float_prefix(static_cast<float>(n)));
            write_number(static_cast<float>(n));
        }
        else
        {
            oa->write_character(format == detail::input_format_t::cbor
                                ? get_cbor_float_prefix(n)
                                : get_msgpack_float_prefix(n));
            write_number(n);
        }
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
    }

  public:
    // The following to_char_type functions are implement the conversion
    // between uint8_t and CharType. In case CharType is not unsigned,
    // such a conversion is required to allow values greater than 128.
    // See <https://github.com/nlohmann/json/issues/1286> for a discussion.
    template < typename C = CharType,
               enable_if_t < std::is_signed<C>::value && std::is_signed<char>::value > * = nullptr >
    static constexpr CharType to_char_type(std::uint8_t x) noexcept
    {
        return *reinterpret_cast<char*>(&x);
    }

    template < typename C = CharType,
               enable_if_t < std::is_signed<C>::value && std::is_unsigned<char>::value > * = nullptr >
    static CharType to_char_type(std::uint8_t x) noexcept
    {
        static_assert(sizeof(std::uint8_t) == sizeof(CharType), "size of CharType must be equal to std::uint8_t");
        static_assert(std::is_trivial<CharType>::value, "CharType must be trivial");
        CharType result;
        std::memcpy(&result, &x, sizeof(x));
        return result;
    }

    template<typename C = CharType,
             enable_if_t<std::is_unsigned<C>::value>* = nullptr>
    static constexpr CharType to_char_type(std::uint8_t x) noexcept
    {
        return x;
    }

    template < typename InputCharType, typename C = CharType,
               enable_if_t <
                   std::is_signed<C>::value &&
                   std::is_signed<char>::value &&
                   std::is_same<char, typename std::remove_cv<InputCharType>::type>::value
                   > * = nullptr >
    static constexpr CharType to_char_type(InputCharType x) noexcept
    {
        return x;
    }

  private:
    /// whether we can assume little endianness
    const bool is_little_endian = little_endianness();

    /// the output
    output_adapter_t<CharType> oa = nullptr;
};
}  // namespace detail
}  // namespace nlohmann
