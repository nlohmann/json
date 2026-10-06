//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // reverse
#include <array> // array
#include <cmath> // isnan, isinf
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcpy
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // enable_if, is_constructible
#include <utility> // move
#include <vector> // vector

#ifdef _MSC_VER
    #include <cstdlib> // _byteswap_ushort, _byteswap_ulong, _byteswap_uint64
#endif

#include <nlohmann/detail/input/binary_reader.hpp>
#include <nlohmann/detail/input/string_scan.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/output/error_handler.hpp>
#include <nlohmann/detail/output/output_adapters.hpp>
#include <nlohmann/detail/string_concat.hpp>
#include <nlohmann/detail/string_utils.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// how to encode BJData
enum class bjdata_version_t
{
    draft2,
    draft3,
};

///////////////////
// binary writer //
///////////////////

/*!
@brief capacity hint for binary serialization into a std::vector

Returns a *lower* bound on the number of bytes the serialization will produce,
so that writing an array/object of many elements does not start reallocating
from an empty buffer. Every array element occupies at least one byte in every
supported binary format, and every object entry at least two (a key of at least
one byte plus a value of at least one), plus one byte for the container header,
so the hint can never exceed the final size and the returned vector is never
left holding capacity the caller did not ask for. The buffer still grows
geometrically past the hint, so under-reserving only costs a few later
reallocations. Only the top-level element count is consulted (O(1), no walk of
the DOM); a single scalar, string, or binary value is written in one shot and
needs no hint.
*/
template<typename BasicJsonType>
std::size_t binary_reserve_hint(const BasicJsonType& j)
{
    if (j.is_array())
    {
        return j.size() + 1;
    }

    if (j.is_object())
    {
        return (j.size() * 2) + 1;
    }

    return 0;
}

/*!
@brief serialization to BJData, BON8, BSON, CBOR, MessagePack, and UBJSON values
*/
template<typename BasicJsonType, typename CharType, typename OutputSinkType = output_adapter_sink<CharType>>
class binary_writer
{
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;
    using number_float_t = typename BasicJsonType::number_float_t;

  public:
    /*!
    @brief create a binary writer

    @param[in] sink  output sink to write to (a value-type sink such as
                     output_vector_sink, or output_adapter_sink wrapping a
                     type-erased output adapter)
    @param[in] error_handler_  how to treat a string value or object key that
               is not valid UTF-8 (CBOR, MessagePack, UBJSON, BJData, and BSON;
               never consulted by @ref write_bon8)
    */
    explicit binary_writer(OutputSinkType sink, const error_handler_t error_handler_ = binary_writer_default_error_handler())
        : oa(std::move(sink)), error_handler(error_handler_)
    {}

    /*!
    @brief create a binary writer from a type-erased output adapter

    Convenience constructor for the default (output_adapter_sink) sink so the
    `output_adapter`-based overloads keep constructing the writer directly from
    an adapter. Constrained to sinks that can actually be built from an adapter,
    so that a writer over some other sink type is not advertised as constructible
    from one.

    @param[in] adapter  output adapter to write to
    @param[in] error_handler_  how to treat a string value or object key that
               is not valid UTF-8 (CBOR, MessagePack, UBJSON, BJData, and BSON;
               never consulted by @ref write_bon8)
    */
    template < typename SinkType = OutputSinkType,
               typename std::enable_if < std::is_constructible<SinkType, output_adapter_t<CharType>>::value, int >::type = 0 >
    explicit binary_writer(output_adapter_t<CharType> adapter, const error_handler_t error_handler_ = binary_writer_default_error_handler())
        : oa(SinkType(std::move(adapter))), error_handler(error_handler_)
    {}

    /*!
    @param[in] j  JSON value to serialize
    @throw type_error.316 if a string value or an object key is not valid
           UTF-8
    @throw type_error.317 if @a j is not an object
    @throw type_error.321 if a value nested in @a j is discarded
    */
    void write_bson(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::object:
            {
                write_bson_document(j);
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
                JSON_THROW(type_error::create(317, concat("to serialize to BSON, top-level type must be object, but is ", j.type_name()), &j));
            }
        }
    }

    /*!
    @param[in] j  JSON value to serialize
    @throw type_error.316 if a string value or an object key is not valid
           UTF-8
    @throw type_error.321 if @a j or a value nested in it is discarded
    */
    void write_cbor(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null:
            {
                oa.write_character(to_char_type(0xF6));
                break;
            }

            case value_t::boolean:
            {
                oa.write_character(j.m_data.m_value.boolean
                                   ? to_char_type(0xF5)
                                   : to_char_type(0xF4));
                break;
            }

            case value_t::number_integer:
            {
                if (j.m_data.m_value.number_integer >= 0)
                {
                    // CBOR does not differentiate between positive signed
                    // integers and unsigned integers
                    write_cbor_head(0x00, static_cast<std::uint64_t>(j.m_data.m_value.number_integer));
                }
                else
                {
                    // a negative integer n is encoded as -1 - n
                    write_cbor_head(0x20, static_cast<std::uint64_t>(-1 - j.m_data.m_value.number_integer));
                }
                break;
            }

            case value_t::number_unsigned:
            {
                write_cbor_head(0x00, j.m_data.m_value.number_unsigned);
                break;
            }

            case value_t::number_float:
            {
                if (std::isnan(j.m_data.m_value.number_float))
                {
                    // NaN is 0xf97e00 in CBOR
                    oa.write_character(to_char_type(0xF9));
                    oa.write_character(to_char_type(0x7E));
                    oa.write_character(to_char_type(0x00));
                }
                else if (std::isinf(j.m_data.m_value.number_float))
                {
                    // Infinity is 0xf97c00, -Infinity is 0xf9fc00
                    oa.write_character(to_char_type(0xf9));
                    oa.write_character(j.m_data.m_value.number_float > 0 ? to_char_type(0x7C) : to_char_type(0xFC));
                    oa.write_character(to_char_type(0x00));
                }
                else
                {
                    write_compact_float(j.m_data.m_value.number_float, to_char_type(0xFA), to_char_type(0xFB));
                }
                break;
            }

            case value_t::string:
            {
                string_t storage;
                const string_t& value = sanitize_utf8_for_write(*j.m_data.m_value.string, j, storage);

                // step 1: write control byte and the string length
                write_cbor_head(0x60, value.size());

                // step 2: write the string
                oa.write_characters(
                      reinterpret_cast<const CharType*>(value.data()),
                      value.size());
                break;
            }

            case value_t::array:
            {
                // step 1: write control byte and the array size
                write_cbor_head(0x80, j.m_data.m_value.array->size());

                // step 2: write each element
                for (const auto& el : *j.m_data.m_value.array)
                {
                    write_cbor(el);
                }
                break;
            }

            case value_t::binary:
            {
                if (j.m_data.m_value.binary->has_subtype())
                {
                    // The subtype is always written as a tag with a 0xD8..0xDB
                    // head, never in the one-byte form 0xC0..0xD7 that CBOR
                    // allows for tags 0..23 (so this is not write_cbor_head).
                    // binary_reader with cbor_tag_handler_t::store only turns
                    // 0xD8..0xDB into a subtype and ignores the one-byte tags,
                    // so the shorter form would lose subtypes 0..23 on a round
                    // trip.
                    if (j.m_data.m_value.binary->subtype() <= (std::numeric_limits<std::uint8_t>::max)())
                    {
                        write_number(static_cast<std::uint8_t>(0xd8));
                        write_number(static_cast<std::uint8_t>(j.m_data.m_value.binary->subtype()));
                    }
                    else if (j.m_data.m_value.binary->subtype() <= (std::numeric_limits<std::uint16_t>::max)())
                    {
                        write_number(static_cast<std::uint8_t>(0xd9));
                        write_number(static_cast<std::uint16_t>(j.m_data.m_value.binary->subtype()));
                    }
                    else if (j.m_data.m_value.binary->subtype() <= (std::numeric_limits<std::uint32_t>::max)())
                    {
                        write_number(static_cast<std::uint8_t>(0xda));
                        write_number(static_cast<std::uint32_t>(j.m_data.m_value.binary->subtype()));
                    }
                    else
                    {
                        write_number(static_cast<std::uint8_t>(0xdb));
                        write_number(static_cast<std::uint64_t>(j.m_data.m_value.binary->subtype()));
                    }
                }

                // step 1: write control byte and the binary array size
                const auto N = j.m_data.m_value.binary->size();
                write_cbor_head(0x40, N);

                // step 2: write each element
                oa.write_characters(
                      reinterpret_cast<const CharType*>(j.m_data.m_value.binary->data()),
                      N);

                break;
            }

            case value_t::object:
            {
                // step 1: write control byte and the object size
                write_cbor_head(0xA0, j.m_data.m_value.object->size());

                // step 2: write each element
                for (const auto& el : *j.m_data.m_value.object)
                {
                    // el.first is checked here, against the object as
                    // diagnostics context, because write_cbor(el.first)
                    // converts it to a temporary basic_json that would be
                    // used as the context instead; for error_handler_t::keep
                    // and ::replace/::ignore the recursive write_cbor(el.first)
                    // call below handles the key like any other string, so no
                    // separate check is needed here for those
                    if (error_handler == error_handler_t::strict)
                    {
                        check_utf8(el.first, j);
                    }
                    write_cbor(el.first);
                    write_cbor(el.second);
                }
                break;
            }

            case value_t::discarded:
            default:
                throw_on_discarded(j, "CBOR");
        }
    }

    /*!
    @brief check that @a length fits into the 32 bits that MessagePack stores
           the length of a string, binary value, array, or object in
    @return the length as an unsigned 32-bit integer
    @throw out_of_range.412 if @a length exceeds the range of std::uint32_t
    */
    static std::uint32_t to_msgpack_length(const std::size_t length, const BasicJsonType& j)
    {
        if (JSON_HEDLEY_UNLIKELY(!value_in_range_of<std::uint32_t>(length)))
        {
            JSON_THROW(out_of_range::create(412, concat("MessagePack length ", std::to_string(length), " exceeds maximum of ", std::to_string((std::numeric_limits<std::uint32_t>::max)())), &j));
        }

        static_cast<void>(j);
        return static_cast<std::uint32_t>(length);
    }

    /*!
    @brief write a non-negative integer using the MessagePack fixint/uint ladder
    @param[in] n  the value to write, already known to be non-negative
    */
    void write_msgpack_unsigned(const std::uint64_t n)
    {
        if (n < 128)
        {
            // positive fixnum
            write_number(static_cast<std::uint8_t>(n));
        }
        else if (n <= (std::numeric_limits<std::uint8_t>::max)())
        {
            // uint 8
            oa.write_character(to_char_type(0xCC));
            write_number(static_cast<std::uint8_t>(n));
        }
        else if (n <= (std::numeric_limits<std::uint16_t>::max)())
        {
            // uint 16
            oa.write_character(to_char_type(0xCD));
            write_number(static_cast<std::uint16_t>(n));
        }
        else if (n <= (std::numeric_limits<std::uint32_t>::max)())
        {
            // uint 32
            oa.write_character(to_char_type(0xCE));
            write_number(static_cast<std::uint32_t>(n));
        }
        else
        {
            // uint 64
            oa.write_character(to_char_type(0xCF));
            write_number(n);
        }
    }

    /*!
    @param[in] j  JSON value to serialize
    @throw type_error.321 if @a j or a value nested in it is discarded
    */
    void write_msgpack(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null: // nil
            {
                oa.write_character(to_char_type(0xC0));
                break;
            }

            case value_t::boolean: // true and false
            {
                oa.write_character(j.m_data.m_value.boolean
                                   ? to_char_type(0xC3)
                                   : to_char_type(0xC2));
                break;
            }

            case value_t::number_integer:
            {
                if (j.m_data.m_value.number_integer >= 0)
                {
                    // MessagePack does not differentiate between positive
                    // signed integers and unsigned integers.
                    write_msgpack_unsigned(static_cast<std::uint64_t>(j.m_data.m_value.number_integer));
                }
                else
                {
                    if (j.m_data.m_value.number_integer >= -32)
                    {
                        // negative fixnum
                        write_number(static_cast<std::int8_t>(j.m_data.m_value.number_integer));
                    }
                    else if (j.m_data.m_value.number_integer >= (std::numeric_limits<std::int8_t>::min)() &&
                             j.m_data.m_value.number_integer <= (std::numeric_limits<std::int8_t>::max)())
                    {
                        // int 8
                        oa.write_character(to_char_type(0xD0));
                        write_number(static_cast<std::int8_t>(j.m_data.m_value.number_integer));
                    }
                    else if (j.m_data.m_value.number_integer >= (std::numeric_limits<std::int16_t>::min)() &&
                             j.m_data.m_value.number_integer <= (std::numeric_limits<std::int16_t>::max)())
                    {
                        // int 16
                        oa.write_character(to_char_type(0xD1));
                        write_number(static_cast<std::int16_t>(j.m_data.m_value.number_integer));
                    }
                    else if (j.m_data.m_value.number_integer >= (std::numeric_limits<std::int32_t>::min)() &&
                             j.m_data.m_value.number_integer <= (std::numeric_limits<std::int32_t>::max)())
                    {
                        // int 32
                        oa.write_character(to_char_type(0xD2));
                        write_number(static_cast<std::int32_t>(j.m_data.m_value.number_integer));
                    }
                    else
                    {
                        // int 64
                        oa.write_character(to_char_type(0xD3));
                        write_number(static_cast<std::int64_t>(j.m_data.m_value.number_integer));
                    }
                }
                break;
            }

            case value_t::number_unsigned:
            {
                write_msgpack_unsigned(static_cast<std::uint64_t>(j.m_data.m_value.number_unsigned));
                break;
            }

            case value_t::number_float:
            {
                write_compact_float(j.m_data.m_value.number_float, to_char_type(0xCA), to_char_type(0xCB));
                break;
            }

            case value_t::string:
            {
                string_t storage;
                const string_t& value = sanitize_utf8_for_write(*j.m_data.m_value.string, j, storage);

                // step 1: write control byte and the string length
                const auto N = to_msgpack_length(value.size(), j);
                if (N <= 31)
                {
                    // fixstr
                    write_number(static_cast<std::uint8_t>(0xA0 | N));
                }
                else if (N <= (std::numeric_limits<std::uint8_t>::max)())
                {
                    // str 8
                    oa.write_character(to_char_type(0xD9));
                    write_number(static_cast<std::uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    // str 16
                    oa.write_character(to_char_type(0xDA));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else
                {
                    // str 32
                    oa.write_character(to_char_type(0xDB));
                    write_number(static_cast<std::uint32_t>(N));
                }

                // step 2: write the string
                oa.write_characters(
                      reinterpret_cast<const CharType*>(value.data()),
                      value.size());
                break;
            }

            case value_t::array:
            {
                // step 1: write control byte and the array size
                const auto N = to_msgpack_length(j.m_data.m_value.array->size(), j);
                if (N <= 15)
                {
                    // fixarray
                    write_number(static_cast<std::uint8_t>(0x90 | N));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    // array 16
                    oa.write_character(to_char_type(0xDC));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else
                {
                    // array 32
                    oa.write_character(to_char_type(0xDD));
                    write_number(static_cast<std::uint32_t>(N));
                }

                // step 2: write each element
                for (const auto& el : *j.m_data.m_value.array)
                {
                    write_msgpack(el);
                }
                break;
            }

            case value_t::binary:
            {
                // step 0: determine if the binary type has a set subtype to
                // determine whether to use the ext or fixext types
                const bool use_ext = j.m_data.m_value.binary->has_subtype();

                // step 1: write control byte and the byte string length
                const auto N = to_msgpack_length(j.m_data.m_value.binary->size(), j);
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

                    oa.write_character(to_char_type(output_type));
                    if (!fixed)
                    {
                        write_number(static_cast<std::uint8_t>(N));
                    }
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    const std::uint8_t output_type = use_ext
                                                     ? 0xC8 // ext 16
                                                     : 0xC5; // bin 16

                    oa.write_character(to_char_type(output_type));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else
                {
                    const std::uint8_t output_type = use_ext
                                                     ? 0xC9 // ext 32
                                                     : 0xC6; // bin 32

                    oa.write_character(to_char_type(output_type));
                    write_number(static_cast<std::uint32_t>(N));
                }

                // step 1.5: if this is an ext type, write the subtype
                if (use_ext)
                {
                    if (JSON_HEDLEY_UNLIKELY(j.m_data.m_value.binary->subtype() > (std::numeric_limits<std::uint8_t>::max)()))
                    {
                        JSON_THROW(out_of_range::create(415, concat("subtype ", std::to_string(j.m_data.m_value.binary->subtype()), " is too large for the MessagePack ext type (max 255)"), &j));
                    }

                    write_number(static_cast<std::int8_t>(j.m_data.m_value.binary->subtype()));
                }

                // step 2: write the byte string
                oa.write_characters(
                      reinterpret_cast<const CharType*>(j.m_data.m_value.binary->data()),
                      N);

                break;
            }

            case value_t::object:
            {
                // step 1: write control byte and the object size
                const auto N = to_msgpack_length(j.m_data.m_value.object->size(), j);
                if (N <= 15)
                {
                    // fixmap
                    write_number(static_cast<std::uint8_t>(0x80 | (N & 0xF)));
                }
                else if (N <= (std::numeric_limits<std::uint16_t>::max)())
                {
                    // map 16
                    oa.write_character(to_char_type(0xDE));
                    write_number(static_cast<std::uint16_t>(N));
                }
                else
                {
                    // map 32
                    oa.write_character(to_char_type(0xDF));
                    write_number(static_cast<std::uint32_t>(N));
                }

                // step 2: write each element
                for (const auto& el : *j.m_data.m_value.object)
                {
                    // as in write_cbor, el.first is checked here against the
                    // object as diagnostics context; the recursive call below
                    // handles keep/replace/ignore like any other string
                    if (error_handler == error_handler_t::strict)
                    {
                        check_utf8(el.first, j);
                    }
                    write_msgpack(el.first);
                    write_msgpack(el.second);
                }
                break;
            }

            case value_t::discarded:
            default:
                throw_on_discarded(j, "MessagePack");
        }
    }

    /*!
    @param[in] j  JSON value to serialize
    @param[in] use_count   whether to use '#' prefixes (optimized format)
    @param[in] use_type    whether to use '$' prefixes (optimized format)
    @param[in] add_prefix  whether prefixes need to be used for this value
    @param[in] use_bjdata  whether write in BJData format, default is false
    @param[in] bjdata_version  which BJData version to use, default is draft2
    @throw type_error.316 if a string value or an object key is not valid
           UTF-8
    @throw type_error.321 if @a j or a value nested in it is discarded
    */
    void write_ubjson(const BasicJsonType& j, const bool use_count,
                      const bool use_type, const bool add_prefix = true,
                      const bool use_bjdata = false, const bjdata_version_t bjdata_version = bjdata_version_t::draft2)
    {
        const bool bjdata_draft3 = use_bjdata && bjdata_version == bjdata_version_t::draft3;

        switch (j.type())
        {
            case value_t::null:
            {
                if (add_prefix)
                {
                    oa.write_character(to_char_type('Z'));
                }
                break;
            }

            case value_t::boolean:
            {
                if (add_prefix)
                {
                    oa.write_character(j.m_data.m_value.boolean
                                       ? to_char_type('T')
                                       : to_char_type('F'));
                }
                break;
            }

            case value_t::number_integer:
            {
                write_number_with_ubjson_prefix(j.m_data.m_value.number_integer, add_prefix, use_bjdata);
                break;
            }

            case value_t::number_unsigned:
            {
                write_number_with_ubjson_prefix(j.m_data.m_value.number_unsigned, add_prefix, use_bjdata);
                break;
            }

            case value_t::number_float:
            {
                write_number_with_ubjson_prefix(j.m_data.m_value.number_float, add_prefix, use_bjdata);
                break;
            }

            case value_t::string:
            {
                string_t storage;
                const string_t& value = sanitize_utf8_for_write(*j.m_data.m_value.string, j, storage);

                if (add_prefix)
                {
                    oa.write_character(to_char_type('S'));
                }
                write_number_with_ubjson_prefix(value.size(), true, use_bjdata);
                oa.write_characters(
                      reinterpret_cast<const CharType*>(value.data()),
                      value.size());
                break;
            }

            case value_t::array:
            {
                if (add_prefix)
                {
                    oa.write_character(to_char_type('['));
                }

                bool prefix_required = true;
                if (use_type && !j.m_data.m_value.array->empty())
                {
                    if (!use_count)
                    {
                        JSON_THROW(other_error::create(502, "use_type requires use_size = true", &j));
                    }
                    const CharType first_prefix = ubjson_prefix(j.front(), use_bjdata);
                    const bool same_prefix = std::all_of(j.begin() + 1, j.end(),
                                                         [this, first_prefix, use_bjdata](const BasicJsonType & v)
                    {
                        return ubjson_prefix(v, use_bjdata) == first_prefix;
                    });

                    // an optimized array of a valueless type carries no payload, so a
                    // reader has nothing but the declared count to bound the allocation
                    // by and refuses an excessive one. Write the unoptimized form for
                    // those, at one byte per element, so the result can be read back.
                    // Objects are not affected: every element is preceded by its key.
                    const bool valueless_type = (first_prefix == 'Z' || first_prefix == 'T' || first_prefix == 'F');
                    const bool excessive_valueless = valueless_type
                                                     && j.m_data.m_value.array->size() > detail::max_valueless_container_size;

                    if (same_prefix && !excessive_valueless
                            && !(use_bjdata && is_bjdata_excluded_type_marker(first_prefix)))
                    {
                        prefix_required = false;
                        oa.write_character(to_char_type('$'));
                        oa.write_character(first_prefix);
                    }
                }

                if (use_count)
                {
                    oa.write_character(to_char_type('#'));
                    write_number_with_ubjson_prefix(j.m_data.m_value.array->size(), true, use_bjdata);
                }

                for (const auto& el : *j.m_data.m_value.array)
                {
                    write_ubjson(el, use_count, use_type, prefix_required, use_bjdata, bjdata_version);
                }

                if (!use_count)
                {
                    oa.write_character(to_char_type(']'));
                }

                break;
            }

            case value_t::binary:
            {
                if (add_prefix)
                {
                    oa.write_character(to_char_type('['));
                }

                if (use_type && (bjdata_draft3 || !j.m_data.m_value.binary->empty()))
                {
                    if (!use_count)
                    {
                        JSON_THROW(other_error::create(502, "use_type requires use_size = true", &j));
                    }
                    oa.write_character(to_char_type('$'));
                    oa.write_character(bjdata_draft3 ? 'B' : 'U');
                }

                if (use_count)
                {
                    oa.write_character(to_char_type('#'));
                    write_number_with_ubjson_prefix(j.m_data.m_value.binary->size(), true, use_bjdata);
                }

                if (use_type)
                {
                    oa.write_characters(
                          reinterpret_cast<const CharType*>(j.m_data.m_value.binary->data()),
                          j.m_data.m_value.binary->size());
                }
                else
                {
                    for (size_t i = 0; i < j.m_data.m_value.binary->size(); ++i)
                    {
                        oa.write_character(to_char_type(bjdata_draft3 ? 'B' : 'U'));
                        // the cast is needed for binary types whose value type
                        // is not an integer (e.g., std::byte)
                        oa.write_character(to_char_type(static_cast<std::uint8_t>(j.m_data.m_value.binary->data()[i])));
                    }
                }

                if (!use_count)
                {
                    oa.write_character(to_char_type(']'));
                }

                break;
            }

            case value_t::object:
            {
                if (use_bjdata && j.m_data.m_value.object->size() == 3 && j.m_data.m_value.object->find("_ArrayType_") != j.m_data.m_value.object->end() && j.m_data.m_value.object->find("_ArraySize_") != j.m_data.m_value.object->end() && j.m_data.m_value.object->find("_ArrayData_") != j.m_data.m_value.object->end())
                {
                    if (!write_bjdata_ndarray(*j.m_data.m_value.object, use_count, use_type, bjdata_version))  // decode bjdata ndarray in the JData format (https://github.com/NeuroJSON/jdata)
                    {
                        break;
                    }
                }

                if (add_prefix)
                {
                    oa.write_character(to_char_type('{'));
                }

                bool prefix_required = true;
                if (use_type && !j.m_data.m_value.object->empty())
                {
                    if (!use_count)
                    {
                        JSON_THROW(other_error::create(502, "use_type requires use_size = true", &j));
                    }
                    const CharType first_prefix = ubjson_prefix(j.front(), use_bjdata);
                    const bool same_prefix = std::all_of(j.begin(), j.end(),
                                                         [this, first_prefix, use_bjdata](const BasicJsonType & v)
                    {
                        return ubjson_prefix(v, use_bjdata) == first_prefix;
                    });

                    if (same_prefix && !(use_bjdata && is_bjdata_excluded_type_marker(first_prefix)))
                    {
                        prefix_required = false;
                        oa.write_character(to_char_type('$'));
                        oa.write_character(first_prefix);
                    }
                }

                if (use_count)
                {
                    oa.write_character(to_char_type('#'));
                    write_number_with_ubjson_prefix(j.m_data.m_value.object->size(), true, use_bjdata);
                }

                for (const auto& el : *j.m_data.m_value.object)
                {
                    string_t storage;
                    const string_t& key = sanitize_utf8_for_write(el.first, j, storage);
                    write_number_with_ubjson_prefix(key.size(), true, use_bjdata);
                    oa.write_characters(
                          reinterpret_cast<const CharType*>(key.data()),
                          key.size());
                    write_ubjson(el.second, use_count, use_type, prefix_required, use_bjdata, bjdata_version);
                }

                if (!use_count)
                {
                    oa.write_character(to_char_type('}'));
                }

                break;
            }

            case value_t::discarded:
            default:
                throw_on_discarded(j, use_bjdata ? "BJData" : "UBJSON");
        }
    }

    /*!
    @param[in] j  JSON value to serialize
    */
    void write_bon8(const BasicJsonType& j)
    {
        bool string_open = false;
        write_bon8_value(j, string_open);

        // the last string of a message must be terminated
        if (string_open)
        {
            oa.write_character(to_char_type(0xFF));
        }
    }

  private:
    /*!
    @brief throws because @a j is discarded and cannot be serialized
    @throw type_error.321 always
    */
    JSON_HEDLEY_NO_RETURN static void throw_on_discarded(const BasicJsonType& j, const char* format_name)
    {
        JSON_THROW(type_error::create(321, concat("cannot serialize discarded value to ", format_name), &j));
    }

    //////////
    // BSON //
    //////////

    /*!
    @return The size of a BSON document entry header, including the id marker
            and the entry name size (and its null-terminator).
    @throw out_of_range.409 if @a name contains U+0000, before anything is
           written
    @throw type_error.316 if @a name is not valid UTF-8, before anything is
           written
    */
    std::size_t calc_bson_entry_header_size(const string_t& name, const BasicJsonType& j)
    {
        const auto it = name.find(static_cast<typename string_t::value_type>(0));
        if (JSON_HEDLEY_UNLIKELY(it != BasicJsonType::string_t::npos))
        {
            JSON_THROW(out_of_range::create(409, concat("BSON key cannot contain code point U+0000 (at byte ", std::to_string(it), ")"), &j));
        }

        string_t storage;
        const string_t& sanitized = sanitize_utf8_for_write(name, j, storage);

        return /*id*/ 1ul + sanitized.size() + /*zero-terminator*/1u;
    }

    /*!
    @brief Checks that @a size fits into the 32-bit length field used by BSON
    @return The size as a signed 32-bit integer
    @throw out_of_range.412 if @a size exceeds the range of std::int32_t
    */
    static std::int32_t to_bson_length(const std::size_t size)
    {
        if (JSON_HEDLEY_UNLIKELY(!value_in_range_of<std::int32_t>(size)))
        {
            JSON_THROW(out_of_range::create(412, concat("BSON length ", std::to_string(size), " exceeds maximum of ", std::to_string((std::numeric_limits<std::int32_t>::max)())), nullptr));
        }

        return static_cast<std::int32_t>(size);
    }

    /*!
    @brief Writes the given @a element_type and @a name to the output adapter

    @a name has already been validated (and, for @ref error_handler_t::strict,
    found well-formed) by @ref calc_bson_entry_header_size during the earlier
    size pass, so only @ref error_handler_t::replace / @ref
    error_handler_t::ignore need to sanitize it again here, to actually write
    the bytes that size was computed from.
    */
    void write_bson_entry_header(const string_t& name,
                                 const std::uint8_t element_type)
    {
        oa.write_character(to_char_type(element_type));

        if (error_handler == error_handler_t::keep || error_handler == error_handler_t::strict || is_valid_utf8(name))
        {
            oa.write_characters(reinterpret_cast<const CharType*>(name.data()), name.size());
        }
        else
        {
            const string_t sanitized = sanitize_utf8(name, error_handler);
            oa.write_characters(reinterpret_cast<const CharType*>(sanitized.data()), sanitized.size());
        }

        // the terminating null byte is written explicitly rather than taken
        // from the buffer, so that string_t::data() need not be null-terminated
        oa.write_character(to_char_type(0x00));
    }

    /*!
    @brief Writes a BSON element with key @a name and boolean value @a value
    */
    void write_bson_boolean(const string_t& name,
                            const bool value)
    {
        write_bson_entry_header(name, 0x08);
        oa.write_character(value ? to_char_type(0x01) : to_char_type(0x00));
    }

    /*!
    @brief Writes a BSON element with key @a name and double value @a value
    */
    void write_bson_double(const string_t& name,
                           const double value)
    {
        write_bson_entry_header(name, 0x01);
        write_number<double>(value, true);
    }

    /*!
    @return The size of the BSON-encoded string in @a value
    @throw type_error.316 if @a value is not valid UTF-8, before anything is
           written

    @note The UTF-8 check is skipped if @a value is already too long for the
          32-bit BSON length field (@ref to_bson_length rejects it later, once
          the size of the whole document is known); this also keeps the check
          from reading past a StringType that reports a size larger than what
          it actually holds.
    */
    std::size_t calc_bson_string_size(const string_t& value, const BasicJsonType& j)
    {
        if (JSON_HEDLEY_LIKELY(value_in_range_of<std::int32_t>(value.size())))
        {
            string_t storage;
            const string_t& sanitized = sanitize_utf8_for_write(value, j, storage);
            return sizeof(std::int32_t) + sanitized.size() + 1ul;
        }
        return sizeof(std::int32_t) + value.size() + 1ul;
    }

    /*!
    @brief Writes a BSON element with key @a name and string value @a value

    @a value has already been validated (and, for @ref error_handler_t::strict,
    found well-formed) by @ref calc_bson_string_size during the earlier size
    pass, so only @ref error_handler_t::replace / @ref error_handler_t::ignore
    need to sanitize it again here, to actually write the bytes that size was
    computed from.
    */
    void write_bson_string(const string_t& name,
                           const string_t& value)
    {
        write_bson_entry_header(name, 0x02);

        const bool sanitize = error_handler != error_handler_t::keep
                              && error_handler != error_handler_t::strict
                              && !is_valid_utf8(value);
        const string_t sanitized = sanitize ? sanitize_utf8(value, error_handler) : string_t{};
        const string_t& written = sanitize ? sanitized : value;

        write_number<std::int32_t>(to_bson_length(written.size() + 1ul), true);
        oa.write_characters(
              reinterpret_cast<const CharType*>(written.data()),
              written.size());
        // the terminating null byte is written explicitly rather than taken
        // from the buffer, so that string_t::data() need not be null-terminated
        oa.write_character(to_char_type(0x00));
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
            write_number<std::int32_t>(static_cast<std::int32_t>(value), true);
        }
        else
        {
            write_bson_entry_header(name, 0x12); // int64
            write_number<std::int64_t>(static_cast<std::int64_t>(value), true);
        }
    }

    /*!
    @return The size of the BSON-encoded unsigned integer @a value
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
                             const std::uint64_t value)
    {
        if (value <= static_cast<std::uint64_t>((std::numeric_limits<std::int32_t>::max)()))
        {
            write_bson_entry_header(name, 0x10 /* int32 */);
            write_number<std::int32_t>(static_cast<std::int32_t>(value), true);
        }
        else if (value <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
        {
            write_bson_entry_header(name, 0x12 /* int64 */);
            write_number<std::int64_t>(static_cast<std::int64_t>(value), true);
        }
        else
        {
            write_bson_entry_header(name, 0x11 /* uint64 */);
            write_number<std::uint64_t>(value, true);
        }
    }

    /*!
    @return The size of the BSON-encoded binary array in @a j
    @throw out_of_range.415 if the subtype of @a j does not fit into a byte,
           before anything is written
    */
    static std::size_t calc_bson_binary_size(const BasicJsonType& j)
    {
        const auto& value = *j.m_data.m_value.binary;

        if (value.has_subtype() && JSON_HEDLEY_UNLIKELY(value.subtype() > (std::numeric_limits<std::uint8_t>::max)()))
        {
            JSON_THROW(out_of_range::create(415, concat("subtype ", std::to_string(value.subtype()), " is too large for the BSON binary subtype (max 255)"), &j));
        }

        return sizeof(std::int32_t) + value.size() + 1ul;
    }

    /*!
    @brief Writes a BSON element with key @a name and binary value @a value
    @pre    @a value's subtype, if any, fits into a byte; @ref calc_bson_sizes
            checks this for every binary value in the document beforehand.
    */
    void write_bson_binary(const string_t& name,
                           const binary_t& value)
    {
        write_bson_entry_header(name, 0x05);

        write_number<std::int32_t>(to_bson_length(value.size()), true);

        write_number(value.has_subtype() ? static_cast<std::uint8_t>(value.subtype()) : static_cast<std::uint8_t>(0x00));

        oa.write_characters(reinterpret_cast<const CharType*>(value.data()), value.size());
    }

    /*!
    @return The size of the value of the BSON document entry for @a j, which
            is neither an object nor an array
    @throw out_of_range.415 if @a j is binary with a subtype that does not fit
           into a byte, before anything is written
    @throw type_error.316 if @a j is a string that is not valid UTF-8, before
           anything is written
    @throw type_error.321 if @a j is discarded
    */
    std::size_t calc_bson_value_size(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::binary:
                return calc_bson_binary_size(j);

            case value_t::boolean:
                return 1ul;

            case value_t::number_float:
                return 8ul;

            case value_t::number_integer:
                return calc_bson_integer_size(j.m_data.m_value.number_integer);

            case value_t::number_unsigned:
                return calc_bson_unsigned_size(j.m_data.m_value.number_unsigned);

            case value_t::string:
                return calc_bson_string_size(*j.m_data.m_value.string, j);

            case value_t::null:
                return 0ul;

            case value_t::discarded:
                throw_on_discarded(j, "BSON");

            // LCOV_EXCL_START
            case value_t::object:
            case value_t::array:
            default:
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert)
                return 0ul;
                // LCOV_EXCL_STOP
        }
    }

    /*!
    @brief Writes the BSON document entry with key @a name for @a j, which is
           neither an object nor an array
    */
    void write_bson_value(const string_t& name, const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::binary:
                return write_bson_binary(name, *j.m_data.m_value.binary);

            case value_t::boolean:
                return write_bson_boolean(name, j.m_data.m_value.boolean);

            case value_t::number_float:
                return write_bson_double(name, j.m_data.m_value.number_float);

            case value_t::number_integer:
                return write_bson_integer(name, j.m_data.m_value.number_integer);

            case value_t::number_unsigned:
                return write_bson_unsigned(name, j.m_data.m_value.number_unsigned);

            case value_t::string:
                return write_bson_string(name, *j.m_data.m_value.string);

            case value_t::null:
                return write_bson_null(name);

            case value_t::discarded:
                throw_on_discarded(j, "BSON");

            // LCOV_EXCL_START
            case value_t::object:
            case value_t::array:
            default:
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert)
                return;
                // LCOV_EXCL_STOP
        }
    }

    /// @brief an object or array of the BSON document being sized or written
    struct bson_frame
    {
        explicit bson_frame(const BasicJsonType* value_, const std::size_t size_slot_ = 0)
            : value(value_)
            , size_slot(size_slot_)
        {
            if (value->is_object())
            {
                member = value->m_data.m_value.object->cbegin();
            }
        }

        /// the object or array
        const BasicJsonType* value;
        /// objects: the next member
        typename BasicJsonType::object_t::const_iterator member{};
        /// arrays: the index of the next element
        std::size_t index = 0;
        /// @ref calc_bson_sizes only: where its size goes in the table
        std::size_t size_slot;
        /// @ref calc_bson_sizes only: the size of its entries seen so far
        std::size_t entries_size = 0;
    };

    /*!
    @brief creates the name BSON gives the array element with index @a index
    @param[out] name  receives the decimal index
    */
    static void create_bson_index_name(const std::size_t index, string_t& name)
    {
        // the index is built as a std::string; convert explicitly, as the
        // two are only implicitly convertible for some string types
        const auto key = std::to_string(index);
        name = string_t(key.data(), key.size());
    }

    /*!
    @brief Calculates the size of every object and array in the BSON document
           @a document, including the document itself.

    BSON prefixes every document and array with its size, so all of them have
    to be known before the first byte is written. They are computed in a
    single pass, each one from the sizes of its entries, which keeps
    serializing linear in the size of the document; computing each size by
    walking the entire value below it made it quadratic in the nesting depth.
    The pass keeps the objects and arrays it has entered on an explicit stack,
    so a deeply nested value cannot exhaust the call stack.

    @param[in] document  the JSON object to serialize
    @param[out] nested_sizes  the sizes of the objects and arrays in
                              @a document, in the order they are written
    @return the size of @a document
    @throw out_of_range.409 if a key contains U+0000, before anything is
           written
    @throw out_of_range.415 if a binary value's subtype does not fit into a
           byte, before anything is written
    @throw type_error.316 if a string value or a key is not valid UTF-8,
           before anything is written
    @throw type_error.321 if a value nested in @a document is discarded,
           before anything is written
    */
    std::size_t calc_bson_sizes(const BasicJsonType& document, std::vector<std::size_t>& nested_sizes)
    {
        // the object or array whose entries are being sized, and the ones it
        // is in; nothing is allocated unless the document nests
        bson_frame current(&document);
        std::vector<bson_frame> parents;
        // string_t need not be default constructible
        string_t index_name("", 0);

        while (true)
        {
            // size entries until the current object or array is done, or an
            // entry is an object or array itself
            const BasicJsonType* nested = nullptr;
            if (current.value->is_object())
            {
                const auto& object = *current.value->m_data.m_value.object;
                while (nested == nullptr && current.member != object.cend())
                {
                    const auto& el = *current.member;
                    ++current.member;
                    current.entries_size += calc_bson_entry_header_size(el.first, el.second);
                    if (el.second.is_structured())
                    {
                        nested = &el.second;
                    }
                    else
                    {
                        current.entries_size += calc_bson_value_size(el.second);
                    }
                }
            }
            else
            {
                const auto& array = *current.value->m_data.m_value.array;
                while (nested == nullptr && current.index < array.size())
                {
                    const BasicJsonType& el = array[current.index];
                    create_bson_index_name(current.index, index_name);
                    current.entries_size += calc_bson_entry_header_size(index_name, el);
                    ++current.index;
                    if (el.is_structured())
                    {
                        nested = &el;
                    }
                    else
                    {
                        current.entries_size += calc_bson_value_size(el);
                    }
                }
            }

            if (nested != nullptr)
            {
                // its size is added to the current one's once it is done
                nested_sizes.push_back(0);
                parents.push_back(std::move(current));
                current = bson_frame(nested, nested_sizes.size() - 1);
                continue;
            }

            // the int32 size, the entries, and the terminating null byte
            const std::size_t size = sizeof(std::int32_t) + current.entries_size + 1ul;
            if (parents.empty())
            {
                return size;
            }
            nested_sizes[current.size_slot] = size;
            current = std::move(parents.back());
            parents.pop_back();
            current.entries_size += size;
        }
    }

    /*!
    @brief Serializes the JSON object @a document as a BSON document

    Writes the objects and arrays in it without the call stack, keeping the
    ones it has entered on an explicit stack, so a deeply nested value
    cannot exhaust the call stack.

    @param[in] document  the JSON object to serialize
    @pre       document.type() == value_t::object
    */
    void write_bson_document(const BasicJsonType& document)
    {
        std::vector<std::size_t> nested_sizes;
        const std::size_t document_size = calc_bson_sizes(document, nested_sizes);
        write_number<std::int32_t>(to_bson_length(document_size), true);

        // the object or array whose entries are being written, and the ones
        // it is in
        bson_frame current(&document);
        std::vector<bson_frame> parents;
        std::size_t next_size = 0;
        // string_t need not be default constructible
        string_t index_name("", 0);

        while (true)
        {
            // write entries until the current object or array is done, or an
            // entry is an object or array itself
            const string_t* nested_name = nullptr;
            const BasicJsonType* nested = nullptr;
            if (current.value->is_object())
            {
                const auto& object = *current.value->m_data.m_value.object;
                while (nested == nullptr && current.member != object.cend())
                {
                    const auto& el = *current.member;
                    ++current.member;
                    if (el.second.is_structured())
                    {
                        nested_name = &el.first;
                        nested = &el.second;
                    }
                    else
                    {
                        write_bson_value(el.first, el.second);
                    }
                }
            }
            else
            {
                const auto& array = *current.value->m_data.m_value.array;
                while (nested == nullptr && current.index < array.size())
                {
                    const BasicJsonType& el = array[current.index];
                    create_bson_index_name(current.index, index_name);
                    ++current.index;
                    if (el.is_structured())
                    {
                        nested_name = &index_name;
                        nested = &el;
                    }
                    else
                    {
                        write_bson_value(index_name, el);
                    }
                }
            }

            if (nested != nullptr)
            {
                write_bson_entry_header(*nested_name, nested->is_object() ? 0x03 : 0x04);
                write_number<std::int32_t>(to_bson_length(nested_sizes[next_size++]), true);
                parents.push_back(std::move(current));
                current = bson_frame(nested);
                continue;
            }

            oa.write_character(to_char_type(0x00));
            if (parents.empty())
            {
                // calc_bson_sizes() and write_bson_document() are two
                // hand-synchronized passes over the same structure, linked
                // only by nested_sizes' visiting order; this checks that the
                // write pass consumed exactly the sizes the size pass
                // produced, so a future change that desyncs them (skips or
                // rejects an entry in only one pass) is caught immediately
                // instead of silently writing wrong length prefixes.
                JSON_ASSERT(next_size == nested_sizes.size());
                return;
            }
            current = std::move(parents.back());
            parents.pop_back();
        }
    }

    //////////
    // CBOR //
    //////////

    /*!
    @brief write the head of a CBOR data item

    The head is the major type in the upper three bits of the first byte and
    an argument - an unsigned integer, the length of a string, the number of
    elements of a container - in the shortest of its encodings: in the lower
    five bits of the first byte itself if it is at most 23, otherwise in the
    1, 2, 4, or 8 bytes that follow (RFC 8949, section 3).

    @param[in] major_type  the major type, shifted into the upper three bits
    @param[in] argument    the argument of the data item
    */
    void write_cbor_head(const std::uint8_t major_type, const std::uint64_t argument)
    {
        if (argument <= 0x17)
        {
            write_number(static_cast<std::uint8_t>(major_type + argument));
        }
        else if (argument <= (std::numeric_limits<std::uint8_t>::max)())
        {
            oa.write_character(to_char_type(static_cast<std::uint8_t>(major_type + 0x18)));
            write_number(static_cast<std::uint8_t>(argument));
        }
        else if (argument <= (std::numeric_limits<std::uint16_t>::max)())
        {
            oa.write_character(to_char_type(static_cast<std::uint8_t>(major_type + 0x19)));
            write_number(static_cast<std::uint16_t>(argument));
        }
        else if (argument <= (std::numeric_limits<std::uint32_t>::max)())
        {
            oa.write_character(to_char_type(static_cast<std::uint8_t>(major_type + 0x1A)));
            write_number(static_cast<std::uint32_t>(argument));
        }
        else
        {
            oa.write_character(to_char_type(static_cast<std::uint8_t>(major_type + 0x1B)));
            write_number(argument);
        }
    }

    ////////////
    // UBJSON //
    ////////////

    // UBJSON: write number (floating point)
    template<typename NumberType, typename std::enable_if<
                 std::is_floating_point<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix,
                                         const bool use_bjdata)
    {
        if (add_prefix)
        {
            oa.write_character(get_ubjson_float_prefix<NumberType>());
        }
        write_number(n, use_bjdata);
    }

    // UBJSON: write number (integer)
    template<typename NumberType, typename std::enable_if<
                 std::is_integral<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix,
                                         const bool use_bjdata)
    {
        const CharType prefix = ubjson_integer_prefix(n, use_bjdata);
        if (add_prefix)
        {
            oa.write_character(prefix);
        }
        write_ubjson_integer_payload(prefix, n, use_bjdata);
    }

    /*!
    @brief determine the UBJSON/BJData type marker of an integer

    This is the only place that picks the marker of an integer: both
    write_number_with_ubjson_prefix() and ubjson_prefix() use it. An optimized
    container announces the marker of its first value after `$` and then
    writes every value without a marker, so the two must never disagree.

    @param[in] n           the integer
    @param[in] use_bjdata  whether the BJData-only markers `u`, `m`, and `M`
                           may be used

    @return the first marker of `i`, `U`, `I`, `u` (BJData), `l`, `m` (BJData),
            `L`, `M` (BJData, unsigned types only), and `H` (high-precision
            number) whose range contains @a n
    */
    template<typename NumberType>
    static CharType ubjson_integer_prefix(const NumberType n, const bool use_bjdata) noexcept
    {
        if (value_in_range_of<std::int8_t>(n))
        {
            return 'i';
        }
        if (value_in_range_of<std::uint8_t>(n))
        {
            return 'U';
        }
        if (value_in_range_of<std::int16_t>(n))
        {
            return 'I';
        }
        if (use_bjdata && value_in_range_of<std::uint16_t>(n))
        {
            return 'u';
        }
        if (value_in_range_of<std::int32_t>(n))
        {
            return 'l';
        }
        if (use_bjdata && value_in_range_of<std::uint32_t>(n))
        {
            return 'm';
        }
        if (value_in_range_of<std::int64_t>(n))
        {
            return 'L';
        }
        if (use_bjdata && std::is_unsigned<NumberType>::value)
        {
            return 'M';
        }
        // anything else is treated as a high-precision number
        return 'H';
    }

    /*!
    @brief write the value of an integer for the marker chosen by
           ubjson_integer_prefix()
    */
    template<typename NumberType>
    void write_ubjson_integer_payload(const CharType prefix, const NumberType n, const bool use_bjdata)
    {
        switch (prefix)
        {
            case 'i':
                write_number(static_cast<std::int8_t>(n), use_bjdata);
                break;
            case 'U':
                write_number(static_cast<std::uint8_t>(n), use_bjdata);
                break;
            case 'I':
                write_number(static_cast<std::int16_t>(n), use_bjdata);
                break;
            case 'u':
                write_number(static_cast<std::uint16_t>(n), use_bjdata);
                break;
            case 'l':
                write_number(static_cast<std::int32_t>(n), use_bjdata);
                break;
            case 'm':
                write_number(static_cast<std::uint32_t>(n), use_bjdata);
                break;
            case 'L':
                write_number(static_cast<std::int64_t>(n), use_bjdata);
                break;
            case 'M':
                write_number(static_cast<std::uint64_t>(n), use_bjdata);
                break;
            default:
            {
                // high-precision number: the decimal digits as a string
                JSON_ASSERT(prefix == 'H');
                const auto number = BasicJsonType(n).dump();
                write_number_with_ubjson_prefix(number.size(), true, use_bjdata);
                for (std::size_t i = 0; i < number.size(); ++i)
                {
                    oa.write_character(to_char_type(static_cast<std::uint8_t>(number[i])));
                }
                break;
            }
        }
    }

    /*!
    @brief determine the type prefix of container values
    */
    CharType ubjson_prefix(const BasicJsonType& j, const bool use_bjdata) const noexcept
    {
        switch (j.type())
        {
            case value_t::null:
                return 'Z';

            case value_t::boolean:
                return j.m_data.m_value.boolean ? 'T' : 'F';

            case value_t::number_integer:
                return ubjson_integer_prefix(j.m_data.m_value.number_integer, use_bjdata);

            case value_t::number_unsigned:
                return ubjson_integer_prefix(j.m_data.m_value.number_unsigned, use_bjdata);

            case value_t::number_float:
                return get_ubjson_float_prefix<number_float_t>();

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

    /*!
    @brief whether BJData forbids @a marker as the type of an optimized array
           or object

    Containers, strings, high-precision numbers, booleans and null cannot be
    declared as the single type of an optimized container in BJData; such a
    container is written unoptimized. The reader rejects them with the same
    list (binary_reader::is_bjd_excluded_optimized_type()).
    */
    static constexpr bool is_bjdata_excluded_type_marker(const CharType marker) noexcept
    {
        return marker == '[' || marker == '{' || marker == 'S' || marker == 'H'
               || marker == 'T' || marker == 'F' || marker == 'N' || marker == 'Z';
    }

    /// @return the UBJSON/BJData type marker for a float or double value
    ///
    /// number_float_t must be float or double; a static_assert (rather than
    /// an ambiguous overload) reports an unsupported number_float_t clearly.
    template<typename FloatType>
    static constexpr CharType get_ubjson_float_prefix()
    {
        static_assert(std::is_same<FloatType, float>::value || std::is_same<FloatType, double>::value,
                      "number_float_t must be float or double for the UBJSON/BJData writer");
        return std::is_same<FloatType, float>::value ? 'd' : 'D';  // float 32 / float 64
    }

    /*!
    @brief checks whether a JSON number fits into @a TargetType
    @param[in] el a JSON number of either the signed or unsigned integer kind
    @return whether @a el's value can be represented by @a TargetType without
            wrapping, regardless of which of the two kinds it is stored as
    */
    template<typename TargetType>
    static bool bjdata_ndarray_value_in_range(const BasicJsonType& el)
    {
        return el.is_number_unsigned()
               ? value_in_range_of<TargetType>(el.template get<std::uint64_t>())
               : value_in_range_of<TargetType>(el.template get<std::int64_t>());
    }

    /*!
    @brief look up the BJData ND-array dtype marker for an `_ArrayType_` name
    @return the one-character marker, or '\0' if @a name does not name a known dtype

    A C++11 `constexpr` function cannot contain a `switch`, so this is a plain
    comparison chain instead; it is only reached once per ND-array candidate
    object. Keep in sync with binary_reader's `bjd_type_name()`, which maps
    the other way.
    */
    static CharType bjdata_ndarray_type_marker(const string_t& name)
    {
        if (name == "uint8")
        {
            return 'U';
        }
        if (name == "int8")
        {
            return 'i';
        }
        if (name == "uint16")
        {
            return 'u';
        }
        if (name == "int16")
        {
            return 'I';
        }
        if (name == "uint32")
        {
            return 'm';
        }
        if (name == "int32")
        {
            return 'l';
        }
        if (name == "uint64")
        {
            return 'M';
        }
        if (name == "int64")
        {
            return 'L';
        }
        if (name == "single")
        {
            return 'd';
        }
        if (name == "double")
        {
            return 'D';
        }
        if (name == "char")
        {
            return 'C';
        }
        if (name == "byte")
        {
            return 'B';
        }
        return '\0';
    }

    /*!
    @brief validate (dry_run) or write one BJData ND-array element of integer dtype @a T
    @return whether @a el's value is in range of @a T; always true when @a dry_run is false
    */
    template<typename T>
    bool write_bjdata_ndarray_element(const BasicJsonType& el, const bool dry_run)
    {
        if (dry_run)
        {
            return bjdata_ndarray_value_in_range<T>(el);
        }
        using storage_type = typename std::conditional<std::is_unsigned<T>::value, std::uint64_t, std::int64_t>::type;
        write_number(static_cast<T>(el.template get<storage_type>()), true);
        return true;
    }

    /*!
    @brief validate (dry_run) or write one BJData ND-array element of dtype 'd' (single precision)
    @return whether @a el's value fits a float without overflow; always true when @a dry_run is false
    */
    bool write_bjdata_ndarray_float_element(const BasicJsonType& el, const bool dry_run)
    {
        const auto dval = el.template get<double>();
        if (dry_run)
        {
            return !std::isfinite(dval) ||
                   (dval >= static_cast<double>(std::numeric_limits<float>::lowest()) &&
                    dval <= static_cast<double>((std::numeric_limits<float>::max)()));
        }
        write_number(static_cast<float>(dval), true);
        return true;
    }

    /*!
    @brief validate or write every element of a BJData ND-array's `_ArrayData_`
    @param[in] array_data  the `_ArrayData_` array
    @param[in] dtype       the ND-array dtype marker, as returned by bjdata_ndarray_type_marker()
    @param[in] dry_run     true to only range-check each element, false to write it
    @return whether every element is in range for @a dtype (always true when @a dry_run is false)
    */
    bool write_bjdata_ndarray_elements(const BasicJsonType& array_data, const CharType dtype, const bool dry_run)
    {
        for (const auto& el : array_data)
        {
            bool ok = true;
            switch (dtype)
            {
                case 'U':
                case 'C':
                case 'B':
                    ok = write_bjdata_ndarray_element<std::uint8_t>(el, dry_run);
                    break;
                case 'i':
                    ok = write_bjdata_ndarray_element<std::int8_t>(el, dry_run);
                    break;
                case 'u':
                    ok = write_bjdata_ndarray_element<std::uint16_t>(el, dry_run);
                    break;
                case 'I':
                    ok = write_bjdata_ndarray_element<std::int16_t>(el, dry_run);
                    break;
                case 'm':
                    ok = write_bjdata_ndarray_element<std::uint32_t>(el, dry_run);
                    break;
                case 'l':
                    ok = write_bjdata_ndarray_element<std::int32_t>(el, dry_run);
                    break;
                case 'M':
                    ok = write_bjdata_ndarray_element<std::uint64_t>(el, dry_run);
                    break;
                case 'L':
                    ok = write_bjdata_ndarray_element<std::int64_t>(el, dry_run);
                    break;
                case 'd':
                    ok = write_bjdata_ndarray_float_element(el, dry_run);
                    break;
                case 'D':
                default:
                    // 'D' (double) already spans the full range of number_float_t
                    if (!dry_run)
                    {
                        write_number(el.template get<double>(), true);
                    }
                    break;
            }
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    /*!
    @return false if the object is successfully converted to a bjdata ndarray, true if the type or size is invalid
    */
    bool write_bjdata_ndarray(const typename BasicJsonType::object_t& value, const bool use_count, const bool use_type, const bjdata_version_t bjdata_version)
    {
        const auto& array_type = value.at("_ArrayType_");
        // the type name is looked up as a string below; a non-string
        // annotation (e.g. a number, null, or an array) cannot name a known
        // dtype, so it is treated the same as an unrecognized type name and
        // falls back to a plain object encoding instead of throwing
        // type_error.302 out of get<string_t>()
        if (!array_type.is_string())
        {
            return true;
        }

        // use get<string_t>() instead of static_cast<string_t> to avoid an
        // ambiguous conversion under explicit instantiation on C++17 (see #4825)
        const CharType dtype = bjdata_ndarray_type_marker(array_type.template get<string_t>());
        if (dtype == '\0')
        {
            return true;
        }

        // the 'B' (byte) marker is only defined from BJData Draft 3 onward;
        // emitting it under an earlier draft would produce a stream that an
        // earlier-draft reader rejects, so such an object falls back to a
        // plain object encoding instead (see the "Binary values" section of
        // the BJData documentation)
        if (dtype == 'B' && bjdata_version < bjdata_version_t::draft3)
        {
            return true;
        }

        const auto& array_size = value.at("_ArraySize_");
        // the dimensions are written verbatim as the header length below, so a
        // value that is not an array cannot produce a valid one: null emits 'Z'
        // and an object emits '{', neither of which a reader accepts after '#'.
        // Such an object is not a valid ndarray and falls back to a plain object.
        if (!array_size.is_array())
        {
            return true;
        }

        // the reader only restores an annotated object from an ND-array header
        // with at least two dimensions: an empty dimension vector, a single
        // dimension, or a 1xN row vector is read back as a plain array, which
        // would silently drop the annotation, so such an object falls back to
        // a plain object encoding instead
        const auto& dims = array_size;
        if (dims.size() < 2 || (dims.size() == 2 && dims.at(0).is_number_integer() && dims.at(0).template get<std::int64_t>() == 1))
        {
            return true;
        }

        std::size_t len = 1;
        for (const auto& el : dims)
        {
            // a dimension is read as an unsigned value below, so anything that
            // is not a non-negative integer is rejected: a non-integer entry
            // would pun unrelated bytes as the dimension, and a negative one
            // would wrap into a nonsensical length
            if (!el.is_number_integer() || (!el.is_number_unsigned() && el.template get<std::int64_t>() < 0))
            {
                return true;
            }

            // a dimension that does not fit into std::size_t, or a product that
            // overflows it, would wrap around and could match the size of
            // _ArrayData_ by accident; the resulting header announces an
            // element count that no reader can honor (the binary reader rejects
            // it with out_of_range.408), so encode as a plain object instead
            const auto dim = el.template get<std::uint64_t>();
            if (!value_in_range_of<std::size_t>(dim))
            {
                return true;
            }
            const auto dim_size = static_cast<std::size_t>(dim);

            // the reader turns an ND-array with any zero dimension into an
            // empty plain array, dropping the annotation, so keep the object
            if (dim_size == 0)
            {
                return true;
            }
            if (len > (std::numeric_limits<std::size_t>::max)() / dim_size)
            {
                return true;
            }
            len *= dim_size;
        }

        // the elements are written from _ArrayData_ as a flat list, so it has
        // to be an array: size() is 0 for null and 1 for any other scalar, and
        // iterating an object visits its values, so any of these could match
        // the dimensions by accident and be encoded as an unrelated ND-array
        const auto& array_data = value.at("_ArrayData_");
        if (!array_data.is_array() || array_data.size() != len)
        {
            return true;
        }

        // every element is written below as the number kind dtype names, so it
        // has to actually be a number of that category: an element of any other
        // type would reinterpret unrelated bytes, e.g. a string's heap pointer,
        // as that number. Such an object falls back to a plain object encoding.
        // dtype names the wire type, not the storage type: whether an integer
        // is held as number_integer or number_unsigned depends on how the value
        // was built (parsing stores non-negative integers as unsigned, the C++
        // API stores int literals as signed), so both are accepted here and the
        // writes below go through get<>, which reads the member that is active.
        const bool ndarray_is_float = (dtype == 'd' || dtype == 'D');
        for (const auto& el : array_data)
        {
            if (ndarray_is_float ? !el.is_number_float() : !el.is_number_integer())
            {
                return true;
            }
        }

        // every element is cast to the (possibly narrower) C++ type matching
        // dtype below; a value that does not fit that type would silently
        // wrap (integers) or overflow to infinity (the "single" precision
        // float) instead of being reported, so such an object falls back to
        // a plain object encoding as well
        if (!write_bjdata_ndarray_elements(array_data, dtype, true))
        {
            return true;
        }

        oa.write_character(to_char_type('['));
        oa.write_character(to_char_type('$'));
        oa.write_character(dtype);
        oa.write_character(to_char_type('#'));

        write_ubjson(array_size, use_count, use_type, true,  true, bjdata_version);

        write_bjdata_ndarray_elements(array_data, dtype, false);
        return false;
    }

    //////////
    // BON8 //
    //////////

    /*!
    @brief write a BON8 value

    A string is written without length or terminator: it ends at the first
    byte that cannot continue it, which is the first byte of any non-string
    value and of the end-of-container marker 0xFE. It only needs an explicit
    end-of-string marker (0xFF) when it is empty, when another string follows,
    or when it is the last thing in the message.

    @param[in] j                JSON value to serialize
    @param[in,out] string_open  whether the output ends with a non-empty
                                string that has not been terminated with 0xFF
    */
    void write_bon8_value(const BasicJsonType& j, bool& string_open)
    {
        switch (j.type())
        {
            case value_t::null:
            {
                write_bon8_marker(0xFA, string_open);
                break;
            }

            case value_t::boolean:
            {
                write_bon8_marker(j.m_data.m_value.boolean ? 0xF9 : 0xF8, string_open);
                break;
            }

            case value_t::number_unsigned:
            {
                if (j.m_data.m_value.number_unsigned > static_cast<typename BasicJsonType::number_unsigned_t>((std::numeric_limits<std::int64_t>::max)()))
                {
                    JSON_THROW(out_of_range::create(407, concat("integer number ", std::to_string(j.m_data.m_value.number_unsigned), " cannot be represented by BON8 as it does not fit int64"), &j));
                }
                write_bon8_integer(static_cast<std::int64_t>(j.m_data.m_value.number_unsigned));
                string_open = false;
                break;
            }

            case value_t::number_integer:
            {
                write_bon8_integer(static_cast<std::int64_t>(j.m_data.m_value.number_integer));
                string_open = false;
                break;
            }

            case value_t::number_float:
            {
                write_bon8_float(j.m_data.m_value.number_float);
                string_open = false;
                break;
            }

            case value_t::string:
            {
                write_bon8_string(*j.m_data.m_value.string, string_open, j);
                break;
            }

            case value_t::array:
            {
                const auto N = j.m_data.m_value.array->size();
                // 0x80..0x84: array with 0..4 elements; 0x85: array ended by 0xFE
                write_bon8_marker(static_cast<std::uint8_t>(N <= 4 ? 0x80 + N : 0x85), string_open);

                for (const auto& el : *j.m_data.m_value.array)
                {
                    write_bon8_value(el, string_open);
                }

                if (N > 4)
                {
                    write_bon8_marker(0xFE, string_open);
                }
                break;
            }

            case value_t::object:
            {
                const auto N = j.m_data.m_value.object->size();
                // 0x86..0x8A: object with 0..4 members; 0x8B: object ended by 0xFE
                write_bon8_marker(static_cast<std::uint8_t>(N <= 4 ? 0x86 + N : 0x8B), string_open);

                for (const auto& el : *j.m_data.m_value.object)
                {
                    write_bon8_string(el.first, string_open, j);
                    write_bon8_value(el.second, string_open);
                }

                if (N > 4)
                {
                    write_bon8_marker(0xFE, string_open);
                }
                break;
            }

            case value_t::binary:
            {
                // BON8 has no binary type: write the bytes as an array of
                // integers, like UBJSON and BJData do
                const auto N = j.m_data.m_value.binary->size();
                write_bon8_marker(static_cast<std::uint8_t>(N <= 4 ? 0x80 + N : 0x85), string_open);

                for (std::size_t i = 0; i < N; ++i)
                {
                    // the cast is needed for binary types whose value type
                    // is not an integer (e.g., std::byte)
                    write_bon8_integer(static_cast<std::uint8_t>(j.m_data.m_value.binary->data()[i]));
                }

                if (N > 4)
                {
                    write_bon8_marker(0xFE, string_open);
                }
                break;
            }

            case value_t::discarded:
            default:
                break;
        }
    }

    /*!
    @brief write a single byte that is not part of a string

    @param[in] marker        the byte to write
    @param[out] string_open  set to false, because the output no longer ends
                             with a string; see @ref write_bon8_value
    */
    void write_bon8_marker(const std::uint8_t marker, bool& string_open)
    {
        oa.write_character(to_char_type(marker));
        string_open = false;
    }

    /*!
    @brief write a string

    @param[in] s                the string to write
    @param[in,out] string_open  see @ref write_bon8_value
    @param[in] context          the value the string belongs to (for diagnostics)

    @throw type_error.316 if @a s is not valid UTF-8, because the end of a
           string is determined from its encoding
    */
    void write_bon8_string(const string_t& s, bool& string_open, const BasicJsonType& context)
    {
        check_utf8(s, context);

        // a string that follows another string terminates it
        if (string_open)
        {
            oa.write_character(to_char_type(0xFF));
        }

        if (s.empty())
        {
            // the empty string is just the end-of-string marker
            oa.write_character(to_char_type(0xFF));
            string_open = false;
        }
        else
        {
            oa.write_characters(reinterpret_cast<const CharType*>(s.data()), s.size());
            string_open = true;
        }
    }

    /*!
    @brief check that a string is valid UTF-8 (RFC 3629)

    @param[in] s        the string to check
    @param[in] context  the value the string belongs to (for diagnostics)

    @throw type_error.316 if @a s is not valid UTF-8; the message names the
           first byte of the first invalid or incomplete sequence
    */
    static void check_utf8(const string_t& s, const BasicJsonType& context)
    {
        static_cast<void>(context); // only used when exceptions are enabled
        const auto* data = reinterpret_cast<const unsigned char*>(s.data());
        const std::size_t valid = valid_utf8_prefix(data, s.size());
        if (JSON_HEDLEY_UNLIKELY(valid != s.size()))
        {
            JSON_THROW(type_error::create(316, concat("invalid UTF-8 byte at index ", std::to_string(valid), ": 0x", detail::hex_byte(data[valid])), &context));
        }
    }

    /*!
    @brief return @a s as it should be written, honoring @ref error_handler

    Used by @ref write_cbor, @ref write_msgpack, @ref write_ubjson (and so
    @ref write_bjdata), and the BSON writing functions for string values and
    object keys; never by @ref write_bon8, which always validates, since UTF-8
    lead bytes are structural there.

    - @ref error_handler_t::keep: @a s is returned unchanged, without even
      checking it (the behavior of release 3.12.0 and earlier).
    - @ref error_handler_t::strict: @ref check_utf8 is called, which throws
      type_error.316 if @a s is not valid UTF-8.
    - @ref error_handler_t::replace / @ref error_handler_t::ignore: @a s is
      sanitized into @a storage with exactly the rules @ref
      serializer::dump_escaped_impl uses, so that parsing what @ref
      basic_json::dump produces for the same string and the same handler
      yields the same result.

    Well-formed input is never copied: this returns a reference to @a s
    itself in every case but a sanitized `replace`/`ignore` one, so @a
    storage must outlive the returned reference only then.

    @param[in] s        the string (value or object key) to write
    @param[in] context  the value @a s belongs to (for diagnostics)
    @param[out] storage  backing storage for a sanitized copy

    @return a reference to @a s, or to @a storage once it holds a sanitized copy
    */
    const string_t& sanitize_utf8_for_write(const string_t& s, const BasicJsonType& context, string_t& storage) const
    {
        switch (error_handler)
        {
            case error_handler_t::keep:
                return s; // NOLINT(bugprone-return-const-ref-from-parameter): callers pass lvalues that outlive the call

            case error_handler_t::strict:
                check_utf8(s, context);
                return s; // NOLINT(bugprone-return-const-ref-from-parameter): callers pass lvalues that outlive the call

            case error_handler_t::replace:
            case error_handler_t::ignore:
            default:
                if (is_valid_utf8(s))
                {
                    return s; // NOLINT(bugprone-return-const-ref-from-parameter): callers pass lvalues that outlive the call
                }
                storage = sanitize_utf8(s, error_handler);
                return storage;
        }
    }

    /*!
    @brief write an integer in the shortest encoding

    Integers from -10 to 39 take one byte. Up to -33818506 and 67637031, an
    integer takes 2 to 4 bytes that begin with a UTF-8 lead byte (0xC2..0xF7)
    followed by a byte that is not a continuation byte: 0x00..0x7F for
    positive and 0xC0..0xFF for negative integers. Each range starts where the
    shorter one ends. Larger integers are written as int32 (0x8C) or int64
    (0x8D) in big-endian byte order.

    @param[in] value  the integer to write
    */
    void write_bon8_integer(std::int64_t value)
    {
        if (value < (std::numeric_limits<std::int32_t>::min)() || value > (std::numeric_limits<std::int32_t>::max)())
        {
            oa.write_character(to_char_type(0x8D));
            write_number(value);
        }
        else if (value < -33818506 || value > 67637031)
        {
            oa.write_character(to_char_type(0x8C));
            write_number(static_cast<std::int32_t>(value));
        }
        else if (value <= -264075)
        {
            value = -(value + 264075);
            write_bon8_bytes(0xF0 + ((value >> 22) & 0x07), 0xC0 + ((value >> 16) & 0x3F), value >> 8, value);
        }
        else if (value <= -1931)
        {
            value = -(value + 1931);
            write_bon8_bytes(0xE0 + ((value >> 14) & 0x0F), 0xC0 + ((value >> 8) & 0x3F), value);
        }
        else if (value <= -11)
        {
            value = -(value + 11);
            write_bon8_bytes(0xC2 + ((value >> 6) & 0x1F), 0xC0 + (value & 0x3F));
        }
        else if (value <= -1)
        {
            write_bon8_bytes(0xB8 - (value + 1));
        }
        else if (value <= 39)
        {
            write_bon8_bytes(0x90 + value);
        }
        else if (value <= 3879)
        {
            value -= 40;
            write_bon8_bytes(0xC2 + ((value >> 7) & 0x1F), value & 0x7F);
        }
        else if (value <= 528167)
        {
            value -= 3880;
            write_bon8_bytes(0xE0 + ((value >> 15) & 0x0F), (value >> 8) & 0x7F, value);
        }
        else
        {
            value -= 528168;
            write_bon8_bytes(0xF0 + ((value >> 23) & 0x07), (value >> 16) & 0x7F, value >> 8, value);
        }
    }

    /// write the low byte of each argument
    template<typename... Bytes>
    void write_bon8_bytes(const Bytes... bytes)
    {
        const std::array<CharType, sizeof...(Bytes)> buffer{{to_char_type(static_cast<std::uint8_t>(bytes & 0xFF))...}};
        oa.write_characters(buffer.data(), buffer.size());
    }

    /*!
    @brief write a floating-point number

    -1.0, +0.0, and 1.0 take one byte. Other numbers are written as binary32
    (0x8E) if that loses no precision, and as binary64 (0x8F) otherwise; -0.0,
    infinities, and NaN are always written as binary32, NaN as 0x7F800001.

    @param[in] n  the number to write
    */
    void write_bon8_float(const number_float_t n)
    {
#ifdef __GNUC__
        JSON_HEDLEY_DIAGNOSTIC_PUSH
        JSON_HEDLEY_PRAGMA(GCC diagnostic ignored "-Wfloat-equal")
#endif
        if (n == static_cast<number_float_t>(-1))
        {
            oa.write_character(to_char_type(0xFB));
        }
        else if (n == static_cast<number_float_t>(0) && !std::signbit(n))
        {
            oa.write_character(to_char_type(0xFC));
        }
        else if (n == static_cast<number_float_t>(1))
        {
            oa.write_character(to_char_type(0xFD));
        }
        else if (std::isnan(n))
        {
            write_bon8_bytes(0x8E, 0x7F, 0x80, 0x00, 0x01);
        }
        else
        {
            write_compact_float(n, to_char_type(0x8E), to_char_type(0x8F));
        }
#ifdef __GNUC__
        JSON_HEDLEY_DIAGNOSTIC_POP
#endif
    }

    ///////////////////////
    // Utility functions //
    ///////////////////////

    // single-instruction byte swaps (compilers lower these to bswap/rev/movbe);
    // used to emit big-endian numbers without a per-byte std::reverse loop
    static std::uint16_t byte_swap(std::uint16_t x) noexcept
    {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap16(x);
#elif defined(_MSC_VER)
        return _byteswap_ushort(x);
#else
        return static_cast<std::uint16_t>((x >> 8) | (x << 8));
#endif
    }

    static std::uint32_t byte_swap(std::uint32_t x) noexcept
    {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(x);
#elif defined(_MSC_VER)
        return _byteswap_ulong(x);
#else
        return ((x & 0x000000FFu) << 24) | ((x & 0x0000FF00u) << 8)
               | ((x & 0x00FF0000u) >> 8) | ((x & 0xFF000000u) >> 24);
#endif
    }

    static std::uint64_t byte_swap(std::uint64_t x) noexcept
    {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap64(x);
#elif defined(_MSC_VER)
        return _byteswap_uint64(x);
#else
        x = ((x & 0x00000000FFFFFFFFull) << 32) | ((x & 0xFFFFFFFF00000000ull) >> 32);
        x = ((x & 0x0000FFFF0000FFFFull) << 16) | ((x & 0xFFFF0000FFFF0000ull) >> 16);
        x = ((x & 0x00FF00FF00FF00FFull) << 8) | ((x & 0xFF00FF00FF00FF00ull) >> 8);
        return x;
#endif
    }

    /*!
    @brief reverse the bytes of a buffer by byte-swapping it as UIntType

    Loading the buffer into an unsigned integer of the same width and swapping
    that is what lets the compiler emit a single bswap/rev/movbe; reversing the
    buffer element by element does not reliably get there (clang keeps a scalar
    shuffle). The two memcpy calls are the only portable way to reinterpret the
    bytes and are folded away by every optimizer.
    */
    template<typename UIntType, std::size_t N>
    static void byte_swap_buffer(std::array<CharType, N>& a) noexcept
    {
        static_assert(sizeof(UIntType) == N, "swap width must match the buffer size");
        UIntType v{};
        std::memcpy(&v, a.data(), sizeof(v));
        v = byte_swap(v);
        std::memcpy(a.data(), &v, sizeof(v));
    }

    // reverse the bytes of a fixed-size buffer; a single byte_swap() for the
    // common 2/4/8-byte number payloads, std::reverse for any other size
    static void reverse_bytes(std::array<CharType, 2>& a) noexcept
    {
        byte_swap_buffer<std::uint16_t>(a);
    }

    static void reverse_bytes(std::array<CharType, 4>& a) noexcept
    {
        byte_swap_buffer<std::uint32_t>(a);
    }

    static void reverse_bytes(std::array<CharType, 8>& a) noexcept
    {
        byte_swap_buffer<std::uint64_t>(a);
    }

    template<std::size_t N>
    static void reverse_bytes(std::array<CharType, N>& a) noexcept
    {
        std::reverse(a.begin(), a.end());
    }

    /*!
    @brief write a number to the output
    @param[in] n number of type @a NumberType
    @param[in] OutputIsLittleEndian Set to true if output data is
                                 required to be little endian
    @tparam NumberType the type of the number

    @note This function needs to respect the system's endianness, because bytes
          in CBOR, MessagePack, UBJSON, and BON8 are stored in network order
          (big endian) and therefore need reordering on little endian systems.
          On the other hand, BSON and BJData use little endian and should
          reorder on big endian systems.
    */
    template<typename NumberType>
    void write_number(const NumberType n, const bool OutputIsLittleEndian = false)
    {
        // step 1: write the number to an array of length NumberType
        std::array<CharType, sizeof(NumberType)> vec{};
        std::memcpy(vec.data(), &n, sizeof(NumberType));

        // step 2: write the array to output (with possible reordering)
        if (is_little_endian != OutputIsLittleEndian)
        {
            // reverse byte order prior to conversion if necessary
            reverse_bytes(vec);
        }

        oa.write_characters(vec.data(), sizeof(NumberType));
    }

    /// @brief write @a n using @a float32_marker if it round-trips through
    ///        float, otherwise using @a float64_marker
    ///
    /// @a float32_marker and @a float64_marker are the format-specific type
    /// markers (CBOR: 0xFA/0xFB, MessagePack: 0xCA/0xCB, BON8: 0x8E/0x8F);
    /// each caller already knows them at compile time, so the format itself
    /// no longer needs to be passed in.
    void write_compact_float(const number_float_t n, const CharType float32_marker, const CharType float64_marker)
    {
        static_assert(std::is_same<number_float_t, float>::value || std::is_same<number_float_t, double>::value,
                      "number_float_t must be float or double for the CBOR/MessagePack/BON8 writer");
#ifdef __GNUC__
        JSON_HEDLEY_DIAGNOSTIC_PUSH
        JSON_HEDLEY_PRAGMA(GCC diagnostic ignored "-Wfloat-equal")
#endif
        // When number_float_t is float, static_cast<float>(n) is the identity and
        // both branches below are intentionally identical (the "compact" float
        // representation is the value itself). Only GCC diagnoses this, and only
        // when the sink calls are inlined; clang has no such warning.
        // (-Wduplicated-branches only exists from GCC 7 on; naming it on an older
        // GCC would itself warn under -Wpragmas)
#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 7)
        JSON_HEDLEY_PRAGMA(GCC diagnostic ignored "-Wduplicated-branches")
#endif
        if (!std::isfinite(n) || ((static_cast<double>(n) >= static_cast<double>(std::numeric_limits<float>::lowest()) &&
                                   static_cast<double>(n) <= static_cast<double>((std::numeric_limits<float>::max)()) &&
                                   static_cast<double>(static_cast<float>(n)) == static_cast<double>(n))))
        {
            oa.write_character(float32_marker);
            write_number(static_cast<float>(n));
        }
        else
        {
            oa.write_character(float64_marker);
            write_number(n);
        }
#ifdef __GNUC__
        JSON_HEDLEY_DIAGNOSTIC_POP
#endif
    }

  public:
    // The following to_char_type functions implement the conversion
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
        // The std::is_trivial trait is deprecated in C++26. The replacement is to use
        // std::is_trivially_copyable and std::is_trivially_default_constructible.
        // However, some older library implementations support std::is_trivial
        // but not all the std::is_trivially_* traits.
        // Since detecting full support across all libraries is difficult,
        // we use std::is_trivial unless we are using a standard where it has been deprecated.
        // For more details, see: https://github.com/nlohmann/json/pull/4775#issuecomment-2884361627
#ifdef JSON_HAS_CPP_26
        static_assert(std::is_trivially_copyable<CharType>::value, "CharType must be trivially copyable");
        static_assert(std::is_trivially_default_constructible<CharType>::value, "CharType must be trivially default constructible");
#else
        static_assert(std::is_trivial<CharType>::value, "CharType must be trivial");
#endif

        static_assert(sizeof(std::uint8_t) == sizeof(CharType), "size of CharType must be equal to std::uint8_t");
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
    OutputSinkType oa;

    /// how to treat a string value or object key that is not valid UTF-8
    /// (CBOR, MessagePack, UBJSON, BJData, and BSON; not BON8)
    const error_handler_t error_handler = binary_writer_default_error_handler();
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
