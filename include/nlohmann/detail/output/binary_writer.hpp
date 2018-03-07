#pragma once

#include <algorithm> // reverse
#include <array> // array
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcpy
#include <limits> // numeric_limits

#include <nlohmann/detail/input/binary_reader.hpp>
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
  public:
    /*!
    @brief create a binary writer

    @param[in] adapter  output adapter to write to
    */
    explicit binary_writer(output_adapter_t<CharType> adapter) : oa(adapter)
    {
        assert(oa);
    }

    /*!
    @brief[in] j  JSON value to serialize
    */
    void write_cbor(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null:
            {
                oa->write_character(static_cast<CharType>(0xF6));
                break;
            }

            case value_t::boolean:
            {
                oa->write_character(j.m_value.boolean
                                    ? static_cast<CharType>(0xF5)
                                    : static_cast<CharType>(0xF4));
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
                        write_number(static_cast<uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<uint8_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x18));
                        write_number(static_cast<uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<uint16_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x19));
                        write_number(static_cast<uint16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<uint32_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x1A));
                        write_number(static_cast<uint32_t>(j.m_value.number_integer));
                    }
                    else
                    {
                        oa->write_character(static_cast<CharType>(0x1B));
                        write_number(static_cast<uint64_t>(j.m_value.number_integer));
                    }
                }
                else
                {
                    // The conversions below encode the sign in the first
                    // byte, and the value is converted to a positive number.
                    const auto positive_number = -1 - j.m_value.number_integer;
                    if (j.m_value.number_integer >= -24)
                    {
                        write_number(static_cast<uint8_t>(0x20 + positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<uint8_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x38));
                        write_number(static_cast<uint8_t>(positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<uint16_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x39));
                        write_number(static_cast<uint16_t>(positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<uint32_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x3A));
                        write_number(static_cast<uint32_t>(positive_number));
                    }
                    else
                    {
                        oa->write_character(static_cast<CharType>(0x3B));
                        write_number(static_cast<uint64_t>(positive_number));
                    }
                }
                break;
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned <= 0x17)
                {
                    write_number(static_cast<uint8_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x18));
                    write_number(static_cast<uint8_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x19));
                    write_number(static_cast<uint16_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x1A));
                    write_number(static_cast<uint32_t>(j.m_value.number_unsigned));
                }
                else
                {
                    oa->write_character(static_cast<CharType>(0x1B));
                    write_number(static_cast<uint64_t>(j.m_value.number_unsigned));
                }
                break;
            }

            case value_t::number_float: // Double-Precision Float
            {
                oa->write_character(static_cast<CharType>(0xFB));
                write_number(j.m_value.number_float);
                break;
            }

            case value_t::string:
            {
                // step 1: write control byte and the string length
                const auto N = j.m_value.string->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<uint8_t>(0x60 + N));
                }
                else if (N <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x78));
                    write_number(static_cast<uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x79));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x7A));
                    write_number(static_cast<uint32_t>(N));
                }
                // LCOV_EXCL_START
                else if (N <= (std::numeric_limits<uint64_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x7B));
                    write_number(static_cast<uint64_t>(N));
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
                    write_number(static_cast<uint8_t>(0x80 + N));
                }
                else if (N <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x98));
                    write_number(static_cast<uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x99));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x9A));
                    write_number(static_cast<uint32_t>(N));
                }
                // LCOV_EXCL_START
                else if (N <= (std::numeric_limits<uint64_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x9B));
                    write_number(static_cast<uint64_t>(N));
                }
                // LCOV_EXCL_STOP

                // step 2: write each element
                for (const auto& el : *j.m_value.array)
                {
                    write_cbor(el);
                }
                break;
            }

            case value_t::object:
            {
                // step 1: write control byte and the object size
                const auto N = j.m_value.object->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<uint8_t>(0xA0 + N));
                }
                else if (N <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xB8));
                    write_number(static_cast<uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xB9));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xBA));
                    write_number(static_cast<uint32_t>(N));
                }
                // LCOV_EXCL_START
                else if (N <= (std::numeric_limits<uint64_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xBB));
                    write_number(static_cast<uint64_t>(N));
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

            default:
                break;
        }
    }

    /*!
    @brief[in] j  JSON value to serialize
    */
    void write_msgpack(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null: // nil
            {
                oa->write_character(static_cast<CharType>(0xC0));
                break;
            }

            case value_t::boolean: // true and false
            {
                oa->write_character(j.m_value.boolean
                                    ? static_cast<CharType>(0xC3)
                                    : static_cast<CharType>(0xC2));
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
                        write_number(static_cast<uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<uint8_t>::max)())
                    {
                        // uint 8
                        oa->write_character(static_cast<CharType>(0xCC));
                        write_number(static_cast<uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<uint16_t>::max)())
                    {
                        // uint 16
                        oa->write_character(static_cast<CharType>(0xCD));
                        write_number(static_cast<uint16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<uint32_t>::max)())
                    {
                        // uint 32
                        oa->write_character(static_cast<CharType>(0xCE));
                        write_number(static_cast<uint32_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<uint64_t>::max)())
                    {
                        // uint 64
                        oa->write_character(static_cast<CharType>(0xCF));
                        write_number(static_cast<uint64_t>(j.m_value.number_integer));
                    }
                }
                else
                {
                    if (j.m_value.number_integer >= -32)
                    {
                        // negative fixnum
                        write_number(static_cast<int8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<int8_t>::min)() and
                             j.m_value.number_integer <= (std::numeric_limits<int8_t>::max)())
                    {
                        // int 8
                        oa->write_character(static_cast<CharType>(0xD0));
                        write_number(static_cast<int8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<int16_t>::min)() and
                             j.m_value.number_integer <= (std::numeric_limits<int16_t>::max)())
                    {
                        // int 16
                        oa->write_character(static_cast<CharType>(0xD1));
                        write_number(static_cast<int16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<int32_t>::min)() and
                             j.m_value.number_integer <= (std::numeric_limits<int32_t>::max)())
                    {
                        // int 32
                        oa->write_character(static_cast<CharType>(0xD2));
                        write_number(static_cast<int32_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<int64_t>::min)() and
                             j.m_value.number_integer <= (std::numeric_limits<int64_t>::max)())
                    {
                        // int 64
                        oa->write_character(static_cast<CharType>(0xD3));
                        write_number(static_cast<int64_t>(j.m_value.number_integer));
                    }
                }
                break;
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned < 128)
                {
                    // positive fixnum
                    write_number(static_cast<uint8_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint8_t>::max)())
                {
                    // uint 8
                    oa->write_character(static_cast<CharType>(0xCC));
                    write_number(static_cast<uint8_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint16_t>::max)())
                {
                    // uint 16
                    oa->write_character(static_cast<CharType>(0xCD));
                    write_number(static_cast<uint16_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint32_t>::max)())
                {
                    // uint 32
                    oa->write_character(static_cast<CharType>(0xCE));
                    write_number(static_cast<uint32_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint64_t>::max)())
                {
                    // uint 64
                    oa->write_character(static_cast<CharType>(0xCF));
                    write_number(static_cast<uint64_t>(j.m_value.number_integer));
                }
                break;
            }

            case value_t::number_float: // float 64
            {
                oa->write_character(static_cast<CharType>(0xCB));
                write_number(j.m_value.number_float);
                break;
            }

            case value_t::string:
            {
                // step 1: write control byte and the string length
                const auto N = j.m_value.string->size();
                if (N <= 31)
                {
                    // fixstr
                    write_number(static_cast<uint8_t>(0xA0 | N));
                }
                else if (N <= (std::numeric_limits<uint8_t>::max)())
                {
                    // str 8
                    oa->write_character(static_cast<CharType>(0xD9));
                    write_number(static_cast<uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    // str 16
                    oa->write_character(static_cast<CharType>(0xDA));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    // str 32
                    oa->write_character(static_cast<CharType>(0xDB));
                    write_number(static_cast<uint32_t>(N));
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
                    write_number(static_cast<uint8_t>(0x90 | N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    // array 16
                    oa->write_character(static_cast<CharType>(0xDC));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    // array 32
                    oa->write_character(static_cast<CharType>(0xDD));
                    write_number(static_cast<uint32_t>(N));
                }

                // step 2: write each element
                for (const auto& el : *j.m_value.array)
                {
                    write_msgpack(el);
                }
                break;
            }

            case value_t::object:
            {
                // step 1: write control byte and the object size
                const auto N = j.m_value.object->size();
                if (N <= 15)
                {
                    // fixmap
                    write_number(static_cast<uint8_t>(0x80 | (N & 0xF)));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    // map 16
                    oa->write_character(static_cast<CharType>(0xDE));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    // map 32
                    oa->write_character(static_cast<CharType>(0xDF));
                    write_number(static_cast<uint32_t>(N));
                }

                // step 2: write each element
                for (const auto& el : *j.m_value.object)
                {
                    write_msgpack(el.first);
                    write_msgpack(el.second);
                }
                break;
            }

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
                    oa->write_character(static_cast<CharType>('Z'));
                }
                break;
            }

            case value_t::boolean:
            {
                if (add_prefix)
                    oa->write_character(j.m_value.boolean
                                        ? static_cast<CharType>('T')
                                        : static_cast<CharType>('F'));
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
                    oa->write_character(static_cast<CharType>('S'));
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
                    oa->write_character(static_cast<CharType>('['));
                }

                bool prefix_required = true;
                if (use_type and not j.m_value.array->empty())
                {
                    assert(use_count);
                    const char first_prefix = ubjson_prefix(j.front());
                    const bool same_prefix = std::all_of(j.begin() + 1, j.end(),
                                                         [this, first_prefix](const BasicJsonType & v)
                    {
                        return ubjson_prefix(v) == first_prefix;
                    });

                    if (same_prefix)
                    {
                        prefix_required = false;
                        oa->write_character(static_cast<CharType>('$'));
                        oa->write_character(static_cast<CharType>(first_prefix));
                    }
                }

                if (use_count)
                {
                    oa->write_character(static_cast<CharType>('#'));
                    write_number_with_ubjson_prefix(j.m_value.array->size(), true);
                }

                for (const auto& el : *j.m_value.array)
                {
                    write_ubjson(el, use_count, use_type, prefix_required);
                }

                if (not use_count)
                {
                    oa->write_character(static_cast<CharType>(']'));
                }

                break;
            }

            case value_t::object:
            {
                if (add_prefix)
                {
                    oa->write_character(static_cast<CharType>('{'));
                }

                bool prefix_required = true;
                if (use_type and not j.m_value.object->empty())
                {
                    assert(use_count);
                    const char first_prefix = ubjson_prefix(j.front());
                    const bool same_prefix = std::all_of(j.begin(), j.end(),
                                                         [this, first_prefix](const BasicJsonType & v)
                    {
                        return ubjson_prefix(v) == first_prefix;
                    });

                    if (same_prefix)
                    {
                        prefix_required = false;
                        oa->write_character(static_cast<CharType>('$'));
                        oa->write_character(static_cast<CharType>(first_prefix));
                    }
                }

                if (use_count)
                {
                    oa->write_character(static_cast<CharType>('#'));
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

                if (not use_count)
                {
                    oa->write_character(static_cast<CharType>('}'));
                }

                break;
            }

            default:
                break;
        }
    }

  private:
    /*
    @brief write a number to output input

    @param[in] n number of type @a NumberType
    @tparam NumberType the type of the number

    @note This function needs to respect the system's endianess, because bytes
          in CBOR, MessagePack, and UBJSON are stored in network order (big
          endian) and therefore need reordering on little endian systems.
    */
    template<typename NumberType>
    void write_number(const NumberType n)
    {
        // step 1: write number to array of length NumberType
        std::array<CharType, sizeof(NumberType)> vec;
        std::memcpy(vec.data(), &n, sizeof(NumberType));

        // step 2: write array to output (with possible reordering)
        if (is_little_endian)
        {
            // reverse byte order prior to conversion if necessary
            std::reverse(vec.begin(), vec.end());
        }

        oa->write_characters(vec.data(), sizeof(NumberType));
    }

    // UBJSON: write number (floating point)
    template<typename NumberType, typename std::enable_if<
                 std::is_floating_point<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if (add_prefix)
        {
            oa->write_character(static_cast<CharType>('D'));  // float64
        }
        write_number(n);
    }

    // UBJSON: write number (unsigned integer)
    template<typename NumberType, typename std::enable_if<
                 std::is_unsigned<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if (n <= static_cast<uint64_t>((std::numeric_limits<int8_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('i'));  // int8
            }
            write_number(static_cast<uint8_t>(n));
        }
        else if (n <= (std::numeric_limits<uint8_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('U'));  // uint8
            }
            write_number(static_cast<uint8_t>(n));
        }
        else if (n <= static_cast<uint64_t>((std::numeric_limits<int16_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('I'));  // int16
            }
            write_number(static_cast<int16_t>(n));
        }
        else if (n <= static_cast<uint64_t>((std::numeric_limits<int32_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('l'));  // int32
            }
            write_number(static_cast<int32_t>(n));
        }
        else if (n <= static_cast<uint64_t>((std::numeric_limits<int64_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('L'));  // int64
            }
            write_number(static_cast<int64_t>(n));
        }
        else
        {
            JSON_THROW(out_of_range::create(407, "number overflow serializing " + std::to_string(n)));
        }
    }

    // UBJSON: write number (signed integer)
    template<typename NumberType, typename std::enable_if<
                 std::is_signed<NumberType>::value and
                 not std::is_floating_point<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if ((std::numeric_limits<int8_t>::min)() <= n and n <= (std::numeric_limits<int8_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('i'));  // int8
            }
            write_number(static_cast<int8_t>(n));
        }
        else if (static_cast<int64_t>((std::numeric_limits<uint8_t>::min)()) <= n and n <= static_cast<int64_t>((std::numeric_limits<uint8_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('U'));  // uint8
            }
            write_number(static_cast<uint8_t>(n));
        }
        else if ((std::numeric_limits<int16_t>::min)() <= n and n <= (std::numeric_limits<int16_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('I'));  // int16
            }
            write_number(static_cast<int16_t>(n));
        }
        else if ((std::numeric_limits<int32_t>::min)() <= n and n <= (std::numeric_limits<int32_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('l'));  // int32
            }
            write_number(static_cast<int32_t>(n));
        }
        else if ((std::numeric_limits<int64_t>::min)() <= n and n <= (std::numeric_limits<int64_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('L'));  // int64
            }
            write_number(static_cast<int64_t>(n));
        }
        // LCOV_EXCL_START
        else
        {
            JSON_THROW(out_of_range::create(407, "number overflow serializing " + std::to_string(n)));
        }
        // LCOV_EXCL_STOP
    }

    /*!
    @brief determine the type prefix of container values

    @note This function does not need to be 100% accurate when it comes to
          integer limits. In case a number exceeds the limits of int64_t,
          this will be detected by a later call to function
          write_number_with_ubjson_prefix. Therefore, we return 'L' for any
          value that does not fit the previous limits.
    */
    char ubjson_prefix(const BasicJsonType& j) const noexcept
    {
        switch (j.type())
        {
            case value_t::null:
                return 'Z';

            case value_t::boolean:
                return j.m_value.boolean ? 'T' : 'F';

            case value_t::number_integer:
            {
                if ((std::numeric_limits<int8_t>::min)() <= j.m_value.number_integer and j.m_value.number_integer <= (std::numeric_limits<int8_t>::max)())
                {
                    return 'i';
                }
                else if ((std::numeric_limits<uint8_t>::min)() <= j.m_value.number_integer and j.m_value.number_integer <= (std::numeric_limits<uint8_t>::max)())
                {
                    return 'U';
                }
                else if ((std::numeric_limits<int16_t>::min)() <= j.m_value.number_integer and j.m_value.number_integer <= (std::numeric_limits<int16_t>::max)())
                {
                    return 'I';
                }
                else if ((std::numeric_limits<int32_t>::min)() <= j.m_value.number_integer and j.m_value.number_integer <= (std::numeric_limits<int32_t>::max)())
                {
                    return 'l';
                }
                else  // no check and assume int64_t (see note above)
                {
                    return 'L';
                }
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned <= (std::numeric_limits<int8_t>::max)())
                {
                    return 'i';
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint8_t>::max)())
                {
                    return 'U';
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<int16_t>::max)())
                {
                    return 'I';
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<int32_t>::max)())
                {
                    return 'l';
                }
                else  // no check and assume int64_t (see note above)
                {
                    return 'L';
                }
            }

            case value_t::number_float:
                return 'D';

            case value_t::string:
                return 'S';

            case value_t::array:
                return '[';

            case value_t::object:
                return '{';

            default:  // discarded values
                return 'N';
        }
    }

  private:
    /// whether we can assume little endianess
    const bool is_little_endian = binary_reader<BasicJsonType>::little_endianess();

    /// the output
    output_adapter_t<CharType> oa = nullptr;
};
}
}
