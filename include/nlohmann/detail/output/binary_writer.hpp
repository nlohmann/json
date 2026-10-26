//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // max, min, reverse
#include <array> // array
#include <cmath> // isnan, isinf
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcpy
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // enable_if, is_constructible
#include <utility> // move
#include <vector> // vector

#include <nlohmann/detail/bit_ops.hpp>
#include <nlohmann/detail/input/binary_reader.hpp>
#include <nlohmann/detail/input/input_adapters.hpp>
#include <nlohmann/detail/input/string_scan.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/output/error_handler.hpp>
#include <nlohmann/detail/output/output_adapters.hpp>
#include <nlohmann/detail/recursion_depth_limit.hpp>
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
@brief the capacity to reserve for the result of a binary serialization into a
       std::vector

The hint of @ref binary_reserve_hint, but not less than the 64 characters that
output_vector_sink grows an empty vector to on its first write anyway. A small
document then costs one allocation, instead of an allocation of a few bytes that
the first write replaces with one of 64.
*/
template<typename BasicJsonType>
std::size_t binary_initial_capacity(const BasicJsonType& j)
{
    return (std::max)(binary_reserve_hint(j), min_vector_sink_capacity);
}

/*!
@brief serialization to BJData, BON8, BSON, CBOR, MessagePack, and UBJSON values
*/
template<typename BasicJsonType, typename CharType, typename OutputSinkType = output_adapter_sink<CharType>>
class binary_writer
{
    using string_t = typename BasicJsonType::string_t;

    /// an object key as string_t: a reference when object_t::key_type already is
    /// string_t, otherwise a converted copy that outlives sanitize_utf8_for_write's result
    using object_key_string_t = typename std::conditional <
                                std::is_same<typename BasicJsonType::object_t::key_type, string_t>::value,
                                const string_t&, string_t >::type;
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
        : oa(std::move(adapter)), error_handler(error_handler_)
    {}

    /*!
    @brief pass on everything written so far to the output adapter

    A writer over an output_adapter_sink buffers what it writes; this has to
    be called after the last write, or the buffered end is only passed on, and
    an error of the adapter lost, when the writer is destroyed. A writer over
    an output_vector_sink writes straight into the vector.
    */
    void flush()
    {
        oa.flush();
    }

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
                JSON_THROW(type_error::create(exception_id::type_not_serializable, concat("to serialize to BSON, top-level type must be object, but is ", j.type_name()), &j));
            }
        }
    }

    /*!
    @param[in] j      JSON value to serialize
    @param[in] depth  nesting level of @a j, counted from the top-level value
                      passed to @ref basic_json::to_cbor
    @throw type_error.316 if a string value or an object key is not valid
           UTF-8
    @throw type_error.321 if @a j or a value nested in it is discarded

    Serializing a container descends into its elements, so a value nested deeply
    enough used to exhaust the call stack and terminate the process with no
    exception to catch. The descent is bounded here: once @ref recursion_depth_limit
    levels have been entered, @ref write_cbor_iterative writes out what is left
    without the call stack. A value nested less deeply than that - all but a
    vanishing minority - is written by exactly the code that always wrote it.

    @sa https://github.com/nlohmann/json/issues/5392
    */
    void write_cbor(const BasicJsonType& j, const std::size_t depth = 0)
    {
        if (JSON_HEDLEY_UNLIKELY(depth >= recursion_depth_limit()) && (j.is_array() || j.is_object()))
        {
            write_cbor_iterative(j);
            return;
        }

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
            case value_t::number_unsigned:
            {
                // one case for both, so that an array mixing negative
                // (number_integer) and non-negative (number_unsigned) values
                // does not mispredict the switch
                write_cbor_integer(j, std::integral_constant<bool, integers_fit_64_bits()>());
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
                write_cbor_string(*j.m_data.m_value.string, j);
                break;
            }

            case value_t::array:
            {
                write_cbor_array(j, depth);
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
                write_bytes(j.m_data.m_value.binary->data(), N);

                break;
            }

            case value_t::object:
            {
                write_cbor_object(j, depth);
                break;
            }

            case value_t::discarded:
            default:
                throw_on_discarded(j, input_format_t::cbor);
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
            throw_msgpack_length_too_large(length, j);
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
    @param[in] j      JSON value to serialize
    @param[in] depth  nesting level of @a j, counted from the top-level value
                      passed to @ref basic_json::to_msgpack
    @throw type_error.321 if @a j or a value nested in it is discarded

    @sa @ref write_cbor
    @sa https://github.com/nlohmann/json/issues/5392
    */
    void write_msgpack(const BasicJsonType& j, const std::size_t depth = 0)
    {
        if (JSON_HEDLEY_UNLIKELY(depth >= recursion_depth_limit()) && (j.is_array() || j.is_object()))
        {
            write_msgpack_iterative(j);
            return;
        }

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
            case value_t::number_unsigned:
            {
                // one case for both, so that an array mixing negative
                // (number_integer) and non-negative (number_unsigned) values
                // does not mispredict the switch
                write_msgpack_integer(j, std::integral_constant<bool, integers_fit_64_bits()>());
                break;
            }

            case value_t::number_float:
            {
                write_msgpack_float(j.m_data.m_value.number_float);
                break;
            }

            case value_t::string:
            {
                write_msgpack_string(*j.m_data.m_value.string, j);
                break;
            }

            case value_t::array:
            {
                write_msgpack_array(j, depth);
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
                        throw_subtype_out_of_range(j.m_data.m_value.binary->subtype(), "the MessagePack ext type", j);
                    }

                    write_number(static_cast<std::int8_t>(j.m_data.m_value.binary->subtype()));
                }

                // step 2: write the byte string
                write_bytes(j.m_data.m_value.binary->data(), N);

                break;
            }

            case value_t::object:
            {
                // step 1: write control byte and the object size
                write_msgpack_object(j, depth);
                break;
            }

            case value_t::discarded:
            default:
                throw_on_discarded(j, input_format_t::msgpack);
        }
    }

    /*!
    @param[in] j  JSON value to serialize
    @param[in] use_count   whether to use '#' prefixes (optimized format)
    @param[in] use_type    whether to use '$' prefixes (optimized format)
    @param[in] add_prefix  whether prefixes need to be used for this value
    @param[in] use_bjdata  whether write in BJData format, default is false
    @param[in] bjdata_version  which BJData version to use, default is draft2
    @param[in] depth  nesting level of @a j, counted from the top-level value
                      passed to @ref basic_json::to_ubjson or @ref basic_json::to_bjdata
    @throw type_error.316 if a string value or an object key is not valid
           UTF-8
    @throw type_error.321 if @a j or a value nested in it is discarded

    @sa @ref write_cbor
    @sa https://github.com/nlohmann/json/issues/5392
    */
    void write_ubjson(const BasicJsonType& j, const bool use_count,
                      const bool use_type, const bool add_prefix = true,
                      const bool use_bjdata = false, const bjdata_version_t bjdata_version = bjdata_version_t::draft2,
                      const std::size_t depth = 0)
    {
        if (JSON_HEDLEY_UNLIKELY(depth >= recursion_depth_limit()) && (j.is_array() || j.is_object()))
        {
            write_ubjson_iterative(j, use_count, use_type, add_prefix, use_bjdata, bjdata_version);
            return;
        }

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
            case value_t::number_unsigned:
            {
                if (j.m_data.m_type == value_t::number_integer)
                {
                    write_number_with_ubjson_prefix(j.m_data.m_value.number_integer, add_prefix, use_bjdata);
                }
                else
                {
                    write_number_with_ubjson_prefix(j.m_data.m_value.number_unsigned, add_prefix, use_bjdata);
                }
                break;
            }

            case value_t::number_float:
            {
                write_number_with_ubjson_prefix(j.m_data.m_value.number_float, add_prefix, use_bjdata);
                break;
            }

            case value_t::string:
            {
                write_ubjson_text(*j.m_data.m_value.string, j, add_prefix, use_bjdata);
                break;
            }

            case value_t::array:
            {
                bool prefix_required = true;
                const bool write_closer = write_ubjson_start_container<true>(j, use_count, use_type, add_prefix, use_bjdata, prefix_required);

                {
                    const auto& array = *j.m_data.m_value.array;
                    if (starts_with_ubjson_number(array, use_bjdata, std::integral_constant<bool, ubjson_integers_fit_64_bits()>()))
                    {
                        write_ubjson_array_elements(array, use_count, use_type, prefix_required, use_bjdata, bjdata_version, depth);
                    }
                    else
                    {
                        for (const auto& el : array)
                        {
                            write_ubjson(el, use_count, use_type, prefix_required, use_bjdata, bjdata_version, depth + 1);
                        }
                    }
                }

                if (write_closer)
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
                        throw_size_marker_required(j);
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
                    write_bytes(j.m_data.m_value.binary->data(), j.m_data.m_value.binary->size());
                }
                else
                {
                    write_ubjson_binary_bytes(*j.m_data.m_value.binary, bjdata_draft3);
                }

                if (!use_count)
                {
                    oa.write_character(to_char_type(']'));
                }

                break;
            }

            case value_t::object:
            {
                if (use_bjdata && is_bjdata_ndarray(j))
                {
                    if (!write_bjdata_ndarray(*j.m_data.m_value.object, use_count, use_type, bjdata_version))  // decode bjdata ndarray in the JData format (https://github.com/NeuroJSON/jdata)
                    {
                        break;
                    }
                }

                bool prefix_required = true;
                const bool write_closer = write_ubjson_start_container<false>(j, use_count, use_type, add_prefix, use_bjdata, prefix_required);

                write_ubjson_members(j, use_count, use_type, prefix_required, use_bjdata, bjdata_version, depth);

                if (write_closer)
                {
                    oa.write_character(to_char_type('}'));
                }

                break;
            }

            case value_t::discarded:
            default:
                throw_on_discarded(j, use_bjdata ? input_format_t::bjdata : input_format_t::ubjson);
        }
    }

    /*!
    @param[in] j  JSON value to serialize

    @throw type_error.321 if @a j or a value nested in it is discarded
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
    JSON_HEDLEY_NO_RETURN static void throw_on_discarded(const BasicJsonType& j, const input_format_t format)
    {
        static_cast<void>(j); // unused when JSON_NOEXCEPTION is defined
        static_cast<void>(format);
        JSON_THROW(type_error::create(exception_id::discarded_value_used, concat("cannot serialize discarded value to ", input_format_name(format)), &j));
    }

    /// how the range of integer type @a NumberType relates to that of @a TargetType
    template<typename TargetType, typename NumberType>
    struct integer_range
    {
        /// whether NumberType can hold values above the maximum of TargetType
        static constexpr bool may_exceed_max = std::numeric_limits<NumberType>::digits > std::numeric_limits<TargetType>::digits;
        /// whether NumberType can hold values below the minimum of TargetType
        static constexpr bool may_fall_below_min = std::numeric_limits<NumberType>::is_signed
            && (!std::numeric_limits<TargetType>::is_signed || may_exceed_max);
    };

    /*!
    @brief whether integer @a n does not exceed the maximum of @a TargetType

    The binary formats store integers in at most 64 bits, but number_integer_t
    and number_unsigned_t may be wider (e.g., __int128). The range of the
    integer is taken from std::numeric_limits, so a number type whose range
    fits into @a TargetType is never checked: the function is then constant
    true, and the default int64_t/uint64_t types pay nothing.
    */
    template<typename TargetType, typename NumberType>
    static constexpr bool integer_fits_max(const NumberType n) noexcept
    {
        return integer_fits_max<TargetType>(n, std::integral_constant<bool, integer_range<TargetType, NumberType>::may_exceed_max>());
    }

    template<typename TargetType, typename NumberType>
    static constexpr bool integer_fits_max(const NumberType /*unused*/, std::false_type /*may_exceed*/) noexcept
    {
        return true;
    }

    template<typename TargetType, typename NumberType>
    static constexpr bool integer_fits_max(const NumberType n, std::true_type /*may_exceed*/) noexcept
    {
        // NumberType has more digits than TargetType, so it can hold its maximum
        return n <= static_cast<NumberType>((std::numeric_limits<TargetType>::max)());
    }

    /*!
    @brief whether integer @a n is not below the minimum of @a TargetType;
           constant true if NumberType cannot hold such a value
    */
    template<typename TargetType, typename NumberType>
    static constexpr bool integer_fits_min(const NumberType n) noexcept
    {
        return integer_fits_min<TargetType>(n, std::integral_constant<bool, integer_range<TargetType, NumberType>::may_fall_below_min>());
    }

    template<typename TargetType, typename NumberType>
    static constexpr bool integer_fits_min(const NumberType /*unused*/, std::false_type /*may_fall_below*/) noexcept
    {
        return true;
    }

    template<typename TargetType, typename NumberType>
    static constexpr bool integer_fits_min(const NumberType n, std::true_type /*may_fall_below*/) noexcept
    {
        // NumberType is signed and either TargetType is unsigned (minimum 0)
        // or NumberType has more digits, so it can hold the minimum
        return n >= static_cast<NumberType>((std::numeric_limits<TargetType>::min)());
    }

    /*!
    @brief whether integer @a n lies in the range of @a TargetType
    */
    template<typename TargetType, typename NumberType>
    static constexpr bool integer_fits(const NumberType n) noexcept
    {
        return integer_fits_min<TargetType>(n) && integer_fits_max<TargetType>(n);
    }

    /*!
    @brief the decimal digits of the non-negative integer @a n
    */
    template<typename NumberType>
    static std::string integer_to_string(NumberType n, std::false_type /*is_signed*/)
    {
        std::string result;
        do
        {
            result.push_back(static_cast<char>('0' + (n % 10)));
            n = static_cast<NumberType>(n / 10);
        }
        while (n != 0);
        std::reverse(result.begin(), result.end());
        return result;
    }

    /*!
    @brief the decimal digits of the integer @a n, with a leading '-' if it
           is negative
    */
    template<typename NumberType>
    static std::string integer_to_string(NumberType n, std::true_type /*is_signed*/)
    {
        // the remainder of a negative n is not positive; each digit is
        // negated on its own, because negating the minimum of NumberType
        // as a whole would overflow
        const bool negative = n < 0;
        std::string result;
        do
        {
            const auto remainder = n % 10;
            result.push_back(static_cast<char>('0' + (remainder < 0 ? -remainder : remainder)));
            n = static_cast<NumberType>(n / 10);
        }
        while (n != 0);
        if (negative)
        {
            result.push_back('-');
        }
        std::reverse(result.begin(), result.end());
        return result;
    }

    /*!
    @brief throws because the integer @a j is too large for @a format
    @throw out_of_range.407 always
    */
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE
    static void throw_integer_out_of_range(const BasicJsonType& j, const input_format_t format, const char* range)
    {
        // neither std::to_string(), which has no overload for integer types
        // wider than 64 bits, nor dump(), which would also instantiate the
        // serializer for objects and fail for key types it cannot write
        using integer_limits = std::numeric_limits<typename BasicJsonType::number_integer_t>;
        using unsigned_limits = std::numeric_limits<typename BasicJsonType::number_unsigned_t>;
        const std::string number = j.is_number_unsigned()
                                   ? integer_to_string(j.m_data.m_value.number_unsigned, std::integral_constant<bool, unsigned_limits::is_signed>())
                                   : integer_to_string(j.m_data.m_value.number_integer, std::integral_constant<bool, integer_limits::is_signed>());
        static_cast<void>(number); // unused when JSON_NOEXCEPTION is defined
        static_cast<void>(format);
        static_cast<void>(range);
        JSON_THROW(out_of_range::create(exception_id::integer_too_large, concat("integer number ", number, " cannot be represented by ", input_format_name(format), " as it does not fit ", range), &j));
    }

    // The exceptions below are thrown from functions of their own, out of line:
    // the code that builds a message (concat, std::to_string) would otherwise
    // make the frame of the function that checks, which most calls never throw.

    /// @throw out_of_range.412 always
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE
    static void throw_msgpack_length_too_large(const std::size_t length, const BasicJsonType& j)
    {
        static_cast<void>(length); // unused when JSON_NOEXCEPTION is defined
        static_cast<void>(j);
        JSON_THROW(out_of_range::create(exception_id::length_too_large, concat("MessagePack length ", std::to_string(length), " exceeds maximum of ", std::to_string((std::numeric_limits<std::uint32_t>::max)())), &j));
    }

    /// @throw out_of_range.412 always
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE
    static void throw_bson_length_too_large(const std::size_t size)
    {
        static_cast<void>(size); // unused when JSON_NOEXCEPTION is defined
        JSON_THROW(out_of_range::create(exception_id::length_too_large, concat("BSON length ", std::to_string(size), " exceeds maximum of ", std::to_string((std::numeric_limits<std::int32_t>::max)())), nullptr));
    }

    /// @throw out_of_range.415 always
    template<typename SubtypeType>
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE
    static void throw_subtype_out_of_range(const SubtypeType subtype, const char* what, const BasicJsonType& j)
    {
        static_cast<void>(subtype); // unused when JSON_NOEXCEPTION is defined
        static_cast<void>(what);
        static_cast<void>(j);
        JSON_THROW(out_of_range::create(exception_id::subtype_out_of_range, concat("subtype ", std::to_string(subtype), " is too large for ", what, " (max 255)"), &j));
    }

    /// @throw other_error.407 always
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE
    static void throw_size_marker_required(const BasicJsonType& j)
    {
        static_cast<void>(j); // unused when JSON_NOEXCEPTION is defined
        JSON_THROW(other_error::create(exception_id::size_marker_required, "use_type requires use_size = true", &j));
    }

    /// @brief write @a size bytes starting at @a data to the output adapter
    JSON_HEDLEY_ALWAYS_INLINE
    void write_bytes(const void* data, const std::size_t size)
    {
        oa.write_characters(static_cast<const CharType*>(data), size);
    }

    /// @brief write the MessagePack prefix of an array or object with @a N
    ///        elements: the fix marker @a fix_marker | n, or @a marker_16 or
    ///        @a marker_32 followed by the length
    JSON_HEDLEY_ALWAYS_INLINE
    void write_msgpack_container_prefix(const std::size_t N, const BasicJsonType& j,
                                        const std::uint8_t fix_marker, const std::uint8_t marker_16, const std::uint8_t marker_32)
    {
        const auto n = to_msgpack_length(N, j);
        if (n <= 15)
        {
            // fixarray, fixmap
            oa.write_character(to_char_type(static_cast<std::uint8_t>(fix_marker | n)));
        }
        else if (n <= (std::numeric_limits<std::uint16_t>::max)())
        {
            // array 16, map 16
            oa.write_character(to_char_type(marker_16));
            write_number(static_cast<std::uint16_t>(n));
        }
        else
        {
            // array 32, map 32
            oa.write_character(to_char_type(marker_32));
            write_number(static_cast<std::uint32_t>(n));
        }
    }

    JSON_HEDLEY_ALWAYS_INLINE
    void write_msgpack_array_prefix(const std::size_t N, const BasicJsonType& j)
    {
        write_msgpack_container_prefix(N, j, 0x90, 0xDC, 0xDD);
    }

    JSON_HEDLEY_ALWAYS_INLINE
    void write_msgpack_object_prefix(const std::size_t N, const BasicJsonType& j)
    {
        write_msgpack_container_prefix(N, j, 0x80, 0xDE, 0xDF);
    }

    /// @brief a CBOR, MessagePack, BON8, or (as the base of @ref ubjson_frame)
    ///        UBJSON array or object whose elements @ref write_container_iterative,
    ///        @ref write_bon8_iterative, or @ref write_ubjson_iterative is still
    ///        writing
    struct binary_container_frame
    {
        explicit binary_container_frame(const BasicJsonType* value_) noexcept
            : value(value_)
        {
            if (value->is_object())
            {
                object_it = value->m_data.m_value.object->cbegin();
            }
            else
            {
                array_it = value->m_data.m_value.array->cbegin();
            }
        }

        // declared for GCC's -Weffc++, which asks for them in a class with
        // pointer members and a non-trivial destructor; the exception
        // specifications are left implicit, as GCC 4.8 rejects explicit ones
        // that differ from them
        binary_container_frame(const binary_container_frame&) = default;
        binary_container_frame(binary_container_frame&&) = default;
        binary_container_frame& operator=(const binary_container_frame&) = default;
        binary_container_frame& operator=(binary_container_frame&&) = default;
        ~binary_container_frame() = default;

        /// the array or object being written
        const BasicJsonType* value;
        /// value's elements still to write; which of the two is live follows
        /// from the type of value. They are kept side by side rather than in
        /// a union, which would need its special members written out by
        /// hand, see detail/iterators/internal_iterator.hpp
        typename BasicJsonType::object_t::const_iterator object_it{};
        typename BasicJsonType::array_t::const_iterator array_it{};
    };

    /// @brief the CBOR specifics of @ref write_container_iterative
    struct cbor_walk
    {
        static void array_head(binary_writer& w, const BasicJsonType& j)
        {
            w.write_cbor_head(0x80, j.m_data.m_value.array->size());
        }

        static void object_head(binary_writer& w, const BasicJsonType& j)
        {
            w.write_cbor_head(0xA0, j.m_data.m_value.object->size());
        }

        static void scalar(binary_writer& w, const BasicJsonType& j)
        {
            w.write_cbor(j);
        }

        static void string(binary_writer& w, const string_t& key, const BasicJsonType& context)
        {
            w.write_cbor_string(key, context);
        }

        template<typename KeyType>
        static void key(binary_writer& w, const KeyType& k, const BasicJsonType& object)
        {
            w.write_cbor_key(k, object);
        }
    };

    /// @brief the MessagePack specifics of @ref write_container_iterative
    struct msgpack_walk
    {
        static void array_head(binary_writer& w, const BasicJsonType& j)
        {
            w.write_msgpack_array_prefix(j.m_data.m_value.array->size(), j);
        }

        static void object_head(binary_writer& w, const BasicJsonType& j)
        {
            w.write_msgpack_object_prefix(j.m_data.m_value.object->size(), j);
        }

        static void scalar(binary_writer& w, const BasicJsonType& j)
        {
            w.write_msgpack(j);
        }

        static void string(binary_writer& w, const string_t& key, const BasicJsonType& context)
        {
            w.write_msgpack_string(key, context);
        }

        template<typename KeyType>
        static void key(binary_writer& w, const KeyType& k, const BasicJsonType& object)
        {
            w.write_msgpack_key(k, object);
        }
    };

    /*!
    @brief write @a j with @a Walk::scalar, or write its header and push a
           frame for @ref write_container_iterative to continue with its
           elements

    A scalar, and an empty array or object, are written out in full: there is
    nothing below them for @ref write_container_iterative to come back to, so
    nothing is pushed for them.
    */
    template<typename Walk>
    JSON_HEDLEY_ALWAYS_INLINE
    void write_container_value_or_push(const BasicJsonType& j, std::vector<binary_container_frame>& stack)
    {
        if (j.is_array())
        {
            Walk::array_head(*this, j);
            if (!j.m_data.m_value.array->empty())
            {
                stack.emplace_back(&j);
            }
            return;
        }

        if (j.is_object())
        {
            Walk::object_head(*this, j);
            if (!j.m_data.m_value.object->empty())
            {
                stack.emplace_back(&j);
            }
            return;
        }

        Walk::scalar(*this, j);
    }

    /*!
    @brief write out @a root and everything below it without the call stack

    Emits the same bytes as the recursive writer, keeping the containers it has
    entered on an explicit stack instead of descending into them. Only reached
    for values nested deeper than @ref recursion_depth_limit, which is why it
    is not written for speed. Shared by CBOR and MessagePack, which differ only
    in the @a Walk policy (@ref cbor_walk, @ref msgpack_walk); BON8 has its own
    walker, as it tracks an open string run and closes a container with a
    marker.
    */
    template<typename Walk>
    void write_container_iterative(const BasicJsonType& root)
    {
        // only a container with elements is ever pushed; see write_container_value_or_push
        std::vector<binary_container_frame> stack;
        write_container_value_or_push<Walk>(root, stack);

        while (!stack.empty())
        {
            const binary_container_frame current = stack.back();

            if (current.value->is_array())
            {
                const auto& array = *current.value->m_data.m_value.array;
                if (current.array_it == array.cend())
                {
                    stack.pop_back();
                    continue;
                }

                // read the child before pushing: entering it can move every frame
                const BasicJsonType* child = &(*current.array_it);
                ++stack.back().array_it;
                write_container_value_or_push<Walk>(*child, stack);
            }
            else
            {
                const auto& object = *current.value->m_data.m_value.object;
                if (current.object_it == object.cend())
                {
                    stack.pop_back();
                    continue;
                }

                // the key is written directly (not via a temporary basic_json),
                // with the object as diagnostics context, as in the recursive writer
                Walk::key(*this, current.object_it->first, *current.value);
                const BasicJsonType* child = &(current.object_it->second);
                ++stack.back().object_it;
                write_container_value_or_push<Walk>(*child, stack);
            }
        }
    }

    void write_cbor_iterative(const BasicJsonType& root)
    {
        write_container_iterative<cbor_walk>(root);
    }

    void write_msgpack_iterative(const BasicJsonType& root)
    {
        write_container_iterative<msgpack_walk>(root);
    }

    /*!
    @brief write the start of an array (@a IsArray) or object: its opening
           marker, the optimized type, and the count

    @return true when a closing ']' or '}' still has to be written after the
            elements
    */
    template<bool IsArray>
    bool write_ubjson_start_container(const BasicJsonType& j, const bool use_count, const bool use_type,
                                      const bool add_prefix, const bool use_bjdata, bool& prefix_required)
    {
        prefix_required = true;
        if (add_prefix)
        {
            oa.write_character(to_char_type(IsArray ? '[' : '{'));
        }

        const std::size_t size = IsArray ? j.m_data.m_value.array->size() : j.m_data.m_value.object->size();

        if (use_type && size != 0)
        {
            if (!use_count)
            {
                throw_size_marker_required(j);
            }
            const CharType first_prefix = ubjson_prefix(j.front(), use_bjdata);
            // the first element of an array has been compared with itself
            const bool same_prefix = std::all_of(IsArray ? j.begin() + 1 : j.begin(), j.end(),
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
            const bool excessive_valueless = IsArray
                                             && valueless_type
                                             && size > detail::max_valueless_container_size;

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
            write_ubjson_count(size, use_bjdata);
        }

        return !use_count;
    }

    /*!
    @brief whether @a j is a BJData ND-array annotation object
           (https://github.com/NeuroJSON/jdata)

    Used by both the recursive object case of @ref write_ubjson and
    @ref write_ubjson_value_or_push, which must agree on what counts as an
    ND-array: @a j is only actually written as one once @ref
    write_bjdata_ndarray has also accepted its contents.

    @pre @a j.is_object()
    */
    static bool is_bjdata_ndarray(const BasicJsonType& j)
    {
        const auto& object = *j.m_data.m_value.object;
        return object.size() == 3
               && object.find("_ArrayType_") != object.end()
               && object.find("_ArraySize_") != object.end()
               && object.find("_ArrayData_") != object.end();
    }

    /// @brief an object or array @ref write_ubjson_iterative is still writing
    ///        the elements of
    struct ubjson_frame : binary_container_frame
    {
        ubjson_frame(const BasicJsonType* value_, const bool prefix_required_) noexcept
            : binary_container_frame(value_)
            , prefix_required(prefix_required_)
        {}

        // declared for GCC's -Weffc++, which asks for them in a class with
        // pointer members and a non-trivial destructor; the exception
        // specifications are left implicit, as GCC 4.8 rejects explicit ones
        // that differ from them
        ubjson_frame(const ubjson_frame&) = default;
        ubjson_frame(ubjson_frame&&) = default;
        ubjson_frame& operator=(const ubjson_frame&) = default;
        ubjson_frame& operator=(ubjson_frame&&) = default;
        ~ubjson_frame() = default;

        /// whether value's elements each carry their own type marker; an
        /// optimized ($type) container writes it once for all of them instead
        bool prefix_required;
    };

    /*!
    @brief write @a j with @ref write_ubjson, or write its header and push a
           frame for @ref write_ubjson_iterative to continue with its elements

    @param[in] add_prefix  whether @a j's own type marker is written now (the
               elements of an optimized container, and everything below the
               top level, never repeat it)

    @sa @ref write_container_value_or_push
    */
    void write_ubjson_value_or_push(const BasicJsonType& j, const bool add_prefix, const bool use_count,
                                    const bool use_type, const bool use_bjdata, const bjdata_version_t bjdata_version,
                                    std::vector<ubjson_frame>& stack)
    {
        if (!j.is_array() && !j.is_object())
        {
            write_ubjson(j, use_count, use_type, add_prefix, use_bjdata, bjdata_version);
            return;
        }

        if (use_bjdata && j.is_object() && is_bjdata_ndarray(j)
                && !write_bjdata_ndarray(*j.m_data.m_value.object, use_count, use_type, bjdata_version))
        {
            // fully written as an ND-array: nothing below it to come back to
            return;
        }

        const bool is_array = j.is_array();
        bool prefix_required = true;
        if (is_array)
        {
            write_ubjson_start_container<true>(j, use_count, use_type, add_prefix, use_bjdata, prefix_required);
        }
        else
        {
            write_ubjson_start_container<false>(j, use_count, use_type, add_prefix, use_bjdata, prefix_required);
        }

        const bool empty = is_array ? j.m_data.m_value.array->empty() : j.m_data.m_value.object->empty();
        if (!empty)
        {
            stack.emplace_back(&j, prefix_required);
            return;
        }

        // write_ubjson_start_container returns !use_count, i.e. whether a
        // closer still has to be written; use_count is constant for the whole
        // document, so that is recomputed here instead of being carried along
        if (!use_count)
        {
            oa.write_character(to_char_type(is_array ? ']' : '}'));
        }
    }

    /*!
    @brief write out @a root and everything below it without the call stack

    @sa @ref write_cbor_iterative
    */
    void write_ubjson_iterative(const BasicJsonType& root, const bool use_count, const bool use_type,
                                const bool add_prefix, const bool use_bjdata, const bjdata_version_t bjdata_version)
    {
        std::vector<ubjson_frame> stack;
        write_ubjson_value_or_push(root, add_prefix, use_count, use_type, use_bjdata, bjdata_version, stack);

        while (!stack.empty())
        {
            const ubjson_frame current = stack.back();
            const BasicJsonType& j = *current.value;

            if (j.is_array())
            {
                const auto& array = *j.m_data.m_value.array;
                if (current.array_it == array.cend())
                {
                    if (!use_count)
                    {
                        oa.write_character(to_char_type(']'));
                    }
                    stack.pop_back();
                    continue;
                }

                const BasicJsonType* child = &(*current.array_it);
                const bool child_prefix = current.prefix_required;
                ++stack.back().array_it;
                write_ubjson_value_or_push(*child, child_prefix, use_count, use_type, use_bjdata, bjdata_version, stack);
            }
            else
            {
                const auto& object = *j.m_data.m_value.object;
                if (current.object_it == object.cend())
                {
                    if (!use_count)
                    {
                        oa.write_character(to_char_type('}'));
                    }
                    stack.pop_back();
                    continue;
                }

                // a converted key must outlive the reference returned by sanitize_utf8_for_write
                const object_key_string_t key_string = current.object_it->first;
                write_ubjson_text(key_string, j, false, use_bjdata);
                const BasicJsonType* child = &(current.object_it->second);
                const bool child_prefix = current.prefix_required;
                ++stack.back().object_it;
                write_ubjson_value_or_push(*child, child_prefix, use_count, use_type, use_bjdata, bjdata_version, stack);
            }
        }
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
        const std::size_t it = find_nul(name);
        if (JSON_HEDLEY_UNLIKELY(it != BasicJsonType::string_t::npos))
        {
            throw_bson_key_with_null(it, j);
        }

        if (JSON_HEDLEY_LIKELY(error_handler == error_handler_t::keep))
        {
            return /*id*/ 1ul + name.size() + /*zero-terminator*/1u;
        }

        return calc_bson_checked_entry_header_size(name, j);
    }

    /// @brief throw out_of_range.409 for a name with U+0000 at byte @a index;
    ///        out of line, so that the message does not burden the check
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE
    static void throw_bson_key_with_null(const std::size_t index, const BasicJsonType& j)
    {
        static_cast<void>(index); // only used when exceptions are enabled
        static_cast<void>(j);
        JSON_THROW(out_of_range::create(exception_id::bson_key_with_null, concat("BSON key cannot contain code point U+0000 (at byte ", std::to_string(index), ")"), &j));
    }

    /// @brief the size of a BSON document entry header for a name that the
    ///        error handler checks or sanitizes; out of line, as the string_t
    ///        for the sanitized copy would otherwise burden every call of
    ///        @ref calc_bson_entry_header_size
    JSON_HEDLEY_NEVER_INLINE
    std::size_t calc_bson_checked_entry_header_size(const string_t& name, const BasicJsonType& j)
    {
        string_t storage;
        const string_t& sanitized = sanitize_utf8_for_write(name, j, storage);

        return /*id*/ 1ul + sanitized.size() + /*zero-terminator*/1u;
    }

    /*!
    @brief the position of the first U+0000 in @a name, or string_t::npos

    The same as `name.find(0)`, without the calls into the standard library for
    names of a few characters: it looks at eight characters at a time.
    */
    static std::size_t find_nul(const string_t& name) noexcept
    {
        return find_nul(name, std::integral_constant<bool, sizeof(typename string_t::value_type) == 1>());
    }

    static std::size_t find_nul(const string_t& name, std::true_type /*is_byte*/) noexcept
    {
        constexpr std::uint64_t ones = 0x0101010101010101ull;
        constexpr std::uint64_t high = 0x8080808080808080ull;
        const std::size_t size = name.size();
        const char* const data = reinterpret_cast<const char*>(name.data());
        std::size_t pos = 0;
        for (; pos + 8 <= size; pos += 8)
        {
            std::uint64_t word = 0;
            std::memcpy(&word, data + pos, sizeof(word));
            if (((word - ones) & ~word & high) != 0)
            {
                break;
            }
        }
        for (; pos < size; ++pos)
        {
            if (data[pos] == '\0')
            {
                return pos;
            }
        }
        return BasicJsonType::string_t::npos;
    }

    static std::size_t find_nul(const string_t& name, std::false_type /*is_byte*/) noexcept
    {
        return name.find(static_cast<typename string_t::value_type>(0));
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
            throw_bson_length_too_large(size);
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

        if (JSON_HEDLEY_LIKELY(error_handler == error_handler_t::keep || error_handler == error_handler_t::strict))
        {
            write_bytes(name.data(), name.size());
        }
        else
        {
            string_t storage;
            const string_t& written = sanitize_utf8_for_bson_write(name, storage);
            write_bytes(written.data(), written.size());
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
            if (JSON_HEDLEY_LIKELY(error_handler == error_handler_t::keep))
            {
                return sizeof(std::int32_t) + value.size() + 1ul;
            }
            return calc_bson_checked_string_size(value, j);
        }
        return sizeof(std::int32_t) + value.size() + 1ul;
    }

    /// @brief the size of a BSON string that the error handler checks or
    ///        sanitizes; out of line, like @ref calc_bson_checked_entry_header_size
    JSON_HEDLEY_NEVER_INLINE
    std::size_t calc_bson_checked_string_size(const string_t& value, const BasicJsonType& j)
    {
        string_t storage;
        const string_t& sanitized = sanitize_utf8_for_write(value, j, storage);
        return sizeof(std::int32_t) + sanitized.size() + 1ul;
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

        string_t storage;
        const string_t& written = sanitize_utf8_for_bson_write(value, storage);

        write_number<std::int32_t>(to_bson_length(written.size() + 1ul), true);
        write_bytes(written.data(), written.size());
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
            throw_subtype_out_of_range(value.subtype(), "the BSON binary subtype", j);
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

        write_bytes(value.data(), value.size());
    }

    /*!
    @return The size of the value of the BSON document entry for @a j, which
            is neither an object nor an array
    @throw out_of_range.415 if @a j is binary with a subtype that does not fit
           into a byte, before anything is written
    @throw out_of_range.407 if @a j is an integer that does not fit the 64 bits
           of a BSON integer, before anything is written
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
                if (JSON_HEDLEY_UNLIKELY(!integer_fits<std::int64_t>(j.m_data.m_value.number_integer)))
                {
                    throw_integer_out_of_range(j, input_format_t::bson, "int64");
                }
                return calc_bson_integer_size(static_cast<std::int64_t>(j.m_data.m_value.number_integer));

            case value_t::number_unsigned:
                if (JSON_HEDLEY_UNLIKELY(!integer_fits_max<std::uint64_t>(j.m_data.m_value.number_unsigned)))
                {
                    throw_integer_out_of_range(j, input_format_t::bson, "uint64");
                }
                return calc_bson_unsigned_size(conditional_static_cast<std::uint64_t>(j.m_data.m_value.number_unsigned));

            case value_t::string:
                return calc_bson_string_size(*j.m_data.m_value.string, j);

            case value_t::null:
                return 0ul;

            case value_t::discarded:
                throw_on_discarded(j, input_format_t::bson);

            // LCOV_EXCL_START
            case value_t::object:
            case value_t::array:
            default:
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert)
                return 0ul;
                // LCOV_EXCL_STOP
        }
    }

    /// the longest name for which write_bson_scalar() writes an entry through a
    /// single reservation: the type, name, terminating null byte, and the length
    /// of a string or binary value (4 bytes) or the largest fixed-size value (8
    /// bytes, a double or a 64-bit integer) must fit max_reserve_size
    static constexpr std::size_t bson_scalar_max_name_size = max_reserve_size - 2 - 8 - 1;

    /*!
    @brief store @a n at @a out in little-endian byte order
    */
    template<typename NumberType>
    void store_little_endian(CharType* out, const NumberType n) const noexcept
    {
        std::memcpy(out, &n, sizeof(NumberType));
        if (!is_little_endian)
        {
            std::reverse(out, out + sizeof(NumberType));
        }
    }

    /*!
    @brief encode the type and the value of the BSON document entry for @a j
           if it has a fixed size
    @param[in] out  where the type byte goes
    @param[in] value_out  where the value goes: the characters after the name
                          and its terminating null byte
    @return the end of the entry, or nullptr (and nothing is written to
            @a out) if @a j is not a boolean, number, or null; at most 9
            characters are written to @a out and @a value_out

    The entry is encoded as @ref write_bson_value does.
    */
    CharType* encode_bson_fixed_entry(CharType* out, CharType* value_out, const BasicJsonType& j) const noexcept
    {
        switch (j.type())
        {
            case value_t::boolean:
                out[0] = to_char_type(0x08);
                *value_out++ = j.m_data.m_value.boolean ? to_char_type(0x01) : to_char_type(0x00);
                return value_out;

            case value_t::number_float:
                out[0] = to_char_type(0x01);
                store_little_endian<double>(value_out, static_cast<double>(j.m_data.m_value.number_float));
                return value_out + sizeof(double);

            case value_t::number_integer:
            {
                const auto value = static_cast<std::int64_t>(j.m_data.m_value.number_integer);
                if ((std::numeric_limits<std::int32_t>::min)() <= value && value <= (std::numeric_limits<std::int32_t>::max)())
                {
                    out[0] = to_char_type(0x10); // int32
                    store_little_endian<std::int32_t>(value_out, static_cast<std::int32_t>(value));
                    return value_out + sizeof(std::int32_t);
                }
                out[0] = to_char_type(0x12); // int64
                store_little_endian<std::int64_t>(value_out, value);
                return value_out + sizeof(std::int64_t);
            }

            case value_t::number_unsigned:
            {
                const auto value = conditional_static_cast<std::uint64_t>(j.m_data.m_value.number_unsigned);
                if (value <= static_cast<std::uint64_t>((std::numeric_limits<std::int32_t>::max)()))
                {
                    out[0] = to_char_type(0x10); // int32
                    store_little_endian<std::int32_t>(value_out, static_cast<std::int32_t>(value));
                    return value_out + sizeof(std::int32_t);
                }
                if (value <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
                {
                    out[0] = to_char_type(0x12); // int64
                    store_little_endian<std::int64_t>(value_out, static_cast<std::int64_t>(value));
                    return value_out + sizeof(std::int64_t);
                }
                out[0] = to_char_type(0x11); // uint64
                store_little_endian<std::uint64_t>(value_out, value);
                return value_out + sizeof(std::uint64_t);
            }

            case value_t::null:
                out[0] = to_char_type(0x0A);
                return value_out;

            case value_t::string:
            case value_t::binary:
            case value_t::object:
            case value_t::array:
            case value_t::discarded:
            default:
                return nullptr;
        }
    }

    /*!
    @brief Writes the BSON document entry with key @a name for @a j, which is
           neither an object nor an array, with the key and a fixed-size value
           (or the header of a string or binary value) in one reservation
    @return whether the entry was written; false for a discarded value, a
            string or binary value whose length does not fit the length
            field, in which case nothing was written
    @pre    @a name is at most bson_scalar_max_name_size characters long and is
            not changed by the error handler
    */
    bool write_bson_scalar(const string_t& name, const BasicJsonType& j)
    {
        const std::size_t name_size = name.size();
        // a short string is written whole: its type, the name and its null
        // byte, the length, the characters, and their null byte
        const bool whole_string = j.is_string() && j.m_data.m_value.string->size() <= max_reserve_size - name_size - 7;
        CharType* const out = oa.reserve(whole_string ? name_size + j.m_data.m_value.string->size() + 7 : name_size + 2 + 8);
        // the name and its terminating null byte follow the type byte
        CharType* p = out + 1;
        copy_characters(p, reinterpret_cast<const CharType*>(name.data()), name_size);
        p += name_size;
        *p++ = to_char_type(0x00);

        if (const CharType* const end = encode_bson_fixed_entry(out, p, j))
        {
            oa.commit(static_cast<std::size_t>(end - out));
            return true;
        }

        if (whole_string)
        {
            const string_t& value = *j.m_data.m_value.string;
            out[0] = to_char_type(0x02);
            store_little_endian<std::int32_t>(p, static_cast<std::int32_t>(value.size() + 1ul));
            p += sizeof(std::int32_t);
            copy_characters(p, reinterpret_cast<const CharType*>(value.data()), value.size());
            p += value.size();
            // the terminating null byte is written explicitly rather than
            // taken from the buffer, so that string_t::data() need not be
            // null-terminated
            *p++ = to_char_type(0x00);
            oa.commit(static_cast<std::size_t>(p - out));
            return true;
        }

        if (j.is_string())
        {
            const string_t& value = *j.m_data.m_value.string;
            if (JSON_HEDLEY_UNLIKELY(!value_in_range_of<std::int32_t>(value.size() + 1ul)))
            {
                return false;
            }
            out[0] = to_char_type(0x02);
            store_little_endian<std::int32_t>(p, static_cast<std::int32_t>(value.size() + 1ul));
            p += sizeof(std::int32_t);
            oa.commit(static_cast<std::size_t>(p - out));
            // the terminating null byte is written explicitly rather than
            // taken from the buffer, so that string_t::data() need not be
            // null-terminated
            write_bytes(value.data(), value.size());
            oa.write_character(to_char_type(0x00));
            return true;
        }

        if (j.is_binary())
        {
            const binary_t& value = *j.m_data.m_value.binary;
            if (JSON_HEDLEY_UNLIKELY(!value_in_range_of<std::int32_t>(value.size())))
            {
                return false;
            }
            out[0] = to_char_type(0x05);
            store_little_endian<std::int32_t>(p, static_cast<std::int32_t>(value.size()));
            p += sizeof(std::int32_t);
            *p++ = value.has_subtype() ? to_char_type(static_cast<std::uint8_t>(value.subtype())) : to_char_type(0x00);
            oa.commit(static_cast<std::size_t>(p - out));
            write_bytes(value.data(), value.size());
            return true;
        }

        return false;
    }

    /*!
    @brief Writes the BSON document entry with key @a name for @a j, which is
           neither an object nor an array
    */
    void write_bson_value(const string_t& name, const BasicJsonType& j)
    {
        // The strings are written as they are, as they are neither checked nor
        // sanitized again here by these two error handlers. The name has to leave
        // room for the larger payloads (see write_bson_scalar).
        if (name.size() <= bson_scalar_max_name_size
                && (error_handler == error_handler_t::keep || error_handler == error_handler_t::strict)
                && write_bson_scalar(name, j))
        {
            return;
        }

        switch (j.type())
        {
            case value_t::binary:
                return write_bson_binary(name, *j.m_data.m_value.binary);

            case value_t::boolean:
                return write_bson_boolean(name, j.m_data.m_value.boolean);

            case value_t::number_float:
                return write_bson_double(name, j.m_data.m_value.number_float);

            // calc_bson_value_size() checked that integers fit 64 bits
            case value_t::number_integer:
                return write_bson_integer(name, static_cast<std::int64_t>(j.m_data.m_value.number_integer));

            case value_t::number_unsigned:
                return write_bson_unsigned(name, conditional_static_cast<std::uint64_t>(j.m_data.m_value.number_unsigned));

            case value_t::string:
                return write_bson_string(name, *j.m_data.m_value.string);

            case value_t::null:
                return write_bson_null(name);

            case value_t::discarded:
                throw_on_discarded(j, input_format_t::bson);

            // LCOV_EXCL_START
            case value_t::object:
            case value_t::array:
            default:
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert)
                return;
                // LCOV_EXCL_STOP
        }
    }

    /*!
    @brief Writes the head of a BSON element with key @a name whose value is
           the object or array @a j: its type, key, and @a size

    Called while the key is in scope: an object key is a key_type, which
    may only convert to a temporary string_t, so it cannot be kept by
    pointer until after the loop over the entries.
    */
    void write_bson_nested_head(const string_t& name, const BasicJsonType& j,
                                const std::size_t size)
    {
        write_bson_entry_header(name, j.is_object() ? 0x03 : 0x04);
        write_number<std::int32_t>(to_bson_length(size), true);
    }

    /// space for the name of an array element, the decimal index, in the frame
    static constexpr std::size_t bson_index_name_space = 24;

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

        /// @ref calc_bson_sizes only: make @ref index the next one and count the
        /// digits of its name
        void count_index() noexcept
        {
            if (++index == index_boundary)
            {
                ++index_name_size;
                index_boundary *= 10;
            }
        }

        /// @ref write_bson_document only: make @ref index the next one and
        /// update its decimal name
        void next_index() noexcept
        {
            ++index;
            std::size_t i = index_name_size;
            while (i > 0 && index_name[i - 1] == '9')
            {
                index_name[--i] = '0';
            }
            if (i > 0)
            {
                ++index_name[i - 1];
            }
            else
            {
                // all digits were 9: 10, 100, ...
                index_name[0] = '1';
                index_name[index_name_size++] = '0';
            }
        }

        /// the object or array
        const BasicJsonType* value;
        /// objects: the next member
        typename BasicJsonType::object_t::const_iterator member{};
        /// arrays: the index of the next element
        std::size_t index = 0;
        /// arrays: the name BSON gives that element, its decimal index (at most
        /// 2^64 - 1, which has 20 digits), in space for copying a few characters
        /// more; only maintained by @ref write_bson_document
        std::array<char, bson_index_name_space> index_name{{'0'}};
        /// arrays: the number of digits of the index
        std::size_t index_name_size = 1;
        /// arrays: the first index with one more digit; only maintained by
        /// @ref calc_bson_sizes
        std::uint64_t index_boundary = 10;
        /// @ref calc_bson_sizes only: where its size goes in the table
        std::size_t size_slot;
        /// @ref calc_bson_sizes only: the size of its entries seen so far
        std::size_t entries_size = 0;
    };

    /// whether the BSON entry of @a j has a fixed size, which is the case for
    /// a boolean, a number, and null
    static bool is_bson_fixed_size(const BasicJsonType& j) noexcept
    {
        return j.is_number() || j.is_boolean() || j.is_null();
    }

    /*!
    @brief Writes the entries of the array in @a frame that have a fixed size
           (booleans, numbers, and null), from its next element on, until it
           reaches another element or the end of the array

    The index of the element and its name are advanced in @a frame.

    The entries are encoded straight into space reserved from the sink for as
    many of them as fit, with the index, its digits, and the write pointer
    kept in local variables: stores of characters may alias the frame, and
    would force them to be loaded from it again for every element.
    */
    void write_bson_array_fixed_entries(bson_frame& frame)
    {
        const auto& array = *frame.value->m_data.m_value.array;
        const std::size_t count = array.size();
        std::size_t index = frame.index;
        std::size_t name_size = frame.index_name_size;
        std::array<char, bson_index_name_space> name = frame.index_name;

        // an entry is at most the type, 20 digits, the null byte, and 8 bytes
        constexpr std::size_t max_entry = 1 + 20 + 1 + 8;
        while (index < count)
        {
            CharType* const start = oa.reserve(max_reserve_size);
            CharType* out = start;
            const CharType* const limit = start + (max_reserve_size - max_entry);
            while (out <= limit && index < count)
            {
                CharType* p = out + 1;
                std::memcpy(p, name.data(), name.size());
                p += name_size;
                *p++ = to_char_type(0x00);
                CharType* const end = encode_bson_fixed_entry(out, p, array[index]);
                if (end == nullptr)
                {
                    break;
                }
                out = end;

                ++index;
                std::size_t i = name_size;
                while (i > 0 && name[i - 1] == '9')
                {
                    name[--i] = '0';
                }
                if (i > 0)
                {
                    ++name[i - 1];
                }
                else
                {
                    // all digits were 9: 10, 100, ...
                    name[0] = '1';
                    name[name_size++] = '0';
                }
            }
            oa.commit(static_cast<std::size_t>(out - start));
            if (out <= limit && index < count)
            {
                // stopped at an element that has no fixed size
                break;
            }
        }

        frame.index = index;
        frame.index_name_size = name_size;
        frame.index_name = name;
    }

    /*!
    @brief Calculates the size of the BSON array @a j if all its elements are
           booleans, numbers, or null
    @param[out] size  the size of the array, including its own size field
    @return false (and nothing is known about @a size) if an element is not,
            or is an integer that does not fit 64 bits (which the generic
            path rejects), which is not looked at further
    */
    bool calc_bson_fixed_array_size(const BasicJsonType& j, std::size_t& size) const noexcept
    {
        std::size_t total = sizeof(std::int32_t) + 1ul;
        std::size_t index_name_size = 1;
        std::uint64_t index_boundary = 10;
        std::uint64_t index = 0;
        for (const auto& el : *j.m_data.m_value.array)
        {
            // the type, the decimal index, and the terminating null byte
            total += 2ul + index_name_size;
            if (++index == index_boundary)
            {
                ++index_name_size;
                index_boundary *= 10;
            }
            switch (el.type())
            {
                case value_t::boolean:
                    total += 1ul;
                    break;
                case value_t::number_float:
                    total += 8ul;
                    break;
                case value_t::number_integer:
                    // an integer beyond 64 bits is left to the generic path, which throws
                    if (JSON_HEDLEY_UNLIKELY(!integer_fits<std::int64_t>(el.m_data.m_value.number_integer)))
                    {
                        return false;
                    }
                    total += calc_bson_integer_size(static_cast<std::int64_t>(el.m_data.m_value.number_integer));
                    break;
                case value_t::number_unsigned:
                    if (JSON_HEDLEY_UNLIKELY(!integer_fits_max<std::uint64_t>(el.m_data.m_value.number_unsigned)))
                    {
                        return false;
                    }
                    total += calc_bson_unsigned_size(conditional_static_cast<std::uint64_t>(el.m_data.m_value.number_unsigned));
                    break;
                case value_t::null:
                    break;
                case value_t::string:
                case value_t::binary:
                case value_t::object:
                case value_t::array:
                case value_t::discarded:
                default:
                    return false;
            }
        }
        size = total;
        return true;
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
                    // the type, the decimal index (which is valid UTF-8 and
                    // has no U+0000), and the terminating null byte
                    current.entries_size += 2ul + current.index_name_size;
                    current.count_index();
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
                // an array of booleans, numbers and null: sized without a frame
                std::size_t fixed_size = 0;
                if (nested->is_array() && calc_bson_fixed_array_size(*nested, fixed_size))
                {
                    nested_sizes.push_back(fixed_size);
                    current.entries_size += fixed_size;
                    continue;
                }

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

        while (true)
        {
            // write entries until the current object or array is done, or an
            // entry is an object or array itself
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
                        write_bson_nested_head(el.first, el.second, nested_sizes[next_size++]);
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
                    if (is_bson_fixed_size(array[current.index]))
                    {
                        write_bson_array_fixed_entries(current);
                        if (current.index == array.size())
                        {
                            break;
                        }
                    }

                    // a string, binary value, object or array
                    const BasicJsonType& el = array[current.index];
                    const string_t index_name(current.index_name.data(), current.index_name_size);
                    current.next_index();
                    if (el.is_structured())
                    {
                        write_bson_nested_head(index_name, el, nested_sizes[next_size++]);
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
                if (nested->is_array())
                {
                    // an array of booleans, numbers and null is written without a frame on the stack
                    bson_frame leaf(nested);
                    write_bson_array_fixed_entries(leaf);
                    if (leaf.index == nested->m_data.m_value.array->size())
                    {
                        oa.write_character(to_char_type(0x00));
                        continue;
                    }
                    parents.push_back(std::move(current));
                    current = std::move(leaf);
                    continue;
                }
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

    /*!
    @brief size class of an unsigned integer from its bit length

    1, 2, 3, or 4 if @a x fits 1, 2, 4, or 8 bytes. Looked up from the number
    of leading zero bits instead of found by branches: the sizes of a stream
    of numbers are hard to predict, and a mispredicted branch costs more than
    writing the number. (A table, as comparisons are vectorized by clang into
    slower code.)
    */
    static unsigned integer_size_class(const std::uint64_t x) noexcept
    {
        static constexpr std::array<std::uint8_t, 64> size_class_by_leading_zeros =
        {
            {
                4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                2, 2, 2, 2, 2, 2, 2, 2,
                1, 1, 1, 1, 1, 1, 1, 1
            }
        };
        // x | 1 keeps count_leading_zeros() away from 0
        return size_class_by_leading_zeros[static_cast<std::size_t>(count_leading_zeros(x | 1u))];
    }

    /*!
    @brief encode @a first_byte and the low-order bytes of @a value that
           @a size_class calls for (none, or 1, 2, 4, or 8) in network order
           to @a out
    @return the number of characters of the encoding; up to
            @ref integer_encoding_space characters at @a out are overwritten

    The bytes are written as one byte and one 8-byte word whose bytes after
    the value are scratch that the caller drops, so that writing them does not
    depend on the size class. For class 0 the word is all scratch; it is
    shifted by 60 bits rather than 64, which would be undefined.
    */
    std::size_t encode_first_byte_and_tail(CharType* out, const std::uint8_t first_byte, const unsigned size_class, const std::uint64_t value) const noexcept
    {
        out[0] = to_char_type(first_byte);
        const unsigned unused_bits = 64u - ((8u << size_class) >> 1u);
        const std::uint64_t tail = is_little_endian ? byteswap(value) >> unused_bits : value << unused_bits;
        std::memcpy(out + 1, &tail, sizeof(tail));
        return ((std::size_t{1} << size_class) >> 1u) + 1;
    }

    /// characters encode_first_byte_and_tail() may overwrite: the first byte
    /// and one 8-byte word
    static constexpr std::size_t integer_encoding_space = 9;

    /*!
    @brief the 64 bits of a number_integer or number_unsigned value, and a mask
           that is all ones if it is negative, else zero

    Selected through masks rather than branches, as the type and the sign of
    the values in an array of mixed signs alternate unpredictably (non-negative
    integers are number_unsigned after parsing). Up to 64 bits, the sign is bit
    63 of the result (a narrower integer is sign-extended); computing it with
    masks keeps GCC from branching on the type. A wider integer has to be
    compared.
    */
    static std::uint64_t integer_bits(const BasicJsonType& j, std::uint64_t& sign_mask) noexcept
    {
        const bool is_signed = j.m_data.m_type == value_t::number_integer;
        const std::uint64_t raw = is_signed
                                  ? static_cast<std::uint64_t>(j.m_data.m_value.number_integer)
                                  : static_cast<std::uint64_t>(j.m_data.m_value.number_unsigned);
        sign_mask = sizeof(typename BasicJsonType::number_integer_t) <= sizeof(std::uint64_t)
                    ? (std::uint64_t{0} - static_cast<std::uint64_t>(is_signed)) & (std::uint64_t{0} - (raw >> 63u))
                    : std::uint64_t{0} - static_cast<std::uint64_t>(is_signed && j.m_data.m_value.number_integer < 0);
        return raw;
    }

    /*!
    @brief encode the head of a CBOR integer to @a out without branching on its
           size
    @return the number of characters of the head

    Same output as @ref write_cbor_head. The lengths of strings and containers
    are mostly predictable, so their heads keep the branches; the sizes of a
    run of integers are not, so an integer's head is assembled without them.
    */
    std::size_t encode_cbor_integer_head(CharType* out, const std::uint8_t major_type, const std::uint64_t argument) const noexcept
    {
        // an argument of at most 23 is in size class 1 (one byte) and is moved
        // to class 0, the first byte, by subtracting 1
        const auto is_immediate = static_cast<unsigned>(argument <= 0x17u);
        const unsigned size_class = integer_size_class(argument) - is_immediate;

        // the first byte: the argument itself if it is immediate, else
        // 0x17 + size_class, selected through a mask
        const std::uint64_t immediate_mask = std::uint64_t{0} - is_immediate;
        const auto first_byte = static_cast<std::uint8_t>(major_type + ((argument & immediate_mask) | ((0x17u + size_class) & ~immediate_mask)));
        return encode_first_byte_and_tail(out, first_byte, size_class, argument);
    }

    /// write the head of an array or object: one byte for a size of up to 23, else as
    /// @ref write_cbor_head
    void write_cbor_container_head(const std::uint8_t major_type, const std::uint64_t size)
    {
        if (JSON_HEDLEY_LIKELY(size <= 0x17))
        {
            oa.write_character(to_char_type(static_cast<std::uint8_t>(major_type + size)));
            return;
        }
        write_cbor_head(major_type, size);
    }

    /*!
    @brief write an object value (head and members) as CBOR

    A member whose value is null, a boolean, an integer, or a string is written
    without a call of @ref write_cbor. Kept out of line, like @ref write_cbor_array.
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_cbor_object(const BasicJsonType& j, const std::size_t depth)
    {
        // step 1: write control byte and the object size
        write_cbor_container_head(0xA0, j.m_data.m_value.object->size());

        for (const auto& el : *j.m_data.m_value.object)
        {
            // el.first is written directly (not via a temporary
            // basic_json), with the object as diagnostics context
            write_cbor_key(el.first, j);

            const BasicJsonType& value = el.second;
            switch (value.type())
            {
                case value_t::null:
                    oa.write_character(to_char_type(0xF6));
                    break;

                case value_t::boolean:
                    oa.write_character(value.m_data.m_value.boolean ? to_char_type(0xF5) : to_char_type(0xF4));
                    break;

                case value_t::number_integer:
                case value_t::number_unsigned:
                    write_cbor_integer(value, std::integral_constant<bool, integers_fit_64_bits()>());
                    break;

                case value_t::string:
                    write_cbor_string(*value.m_data.m_value.string, value);
                    break;

                case value_t::object:
                case value_t::array:
                case value_t::binary:
                case value_t::number_float:
                case value_t::discarded:
                default:
                    write_cbor(value, depth + 1);
                    break;
            }
        }
    }

    /*!
    @brief write an array value (head and elements) as CBOR

    Integer elements, the most common scalar, are written without a call to
    @ref write_cbor. The loop is kept out of line: inlined into write_cbor, its
    registers would be saved and restored on every call of write_cbor, which
    is one call per value nested in an object.
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_cbor_array(const BasicJsonType& j, const std::size_t depth)
    {
        write_cbor_container_head(0x80, j.m_data.m_value.array->size());
        if (!j.m_data.m_value.array->empty())
        {
            write_cbor_array_elements(j, depth, std::integral_constant<bool, integers_fit_64_bits()>());
        }
    }

    JSON_HEDLEY_NEVER_INLINE
    void write_cbor_array_elements(const BasicJsonType& j, const std::size_t depth, std::true_type /*fits_64_bits*/)
    {
        write_array_elements(j, [this](CharType * out, const BasicJsonType & el)
        {
            return encode_cbor_integer(out, el);
        }, [this](CharType * out, const number_float_t n)
        {
            return encode_cbor_float(out, n);
        }, [this, depth](const BasicJsonType & el)
        {
            write_cbor(el, depth + 1);
        });
    }

    void write_cbor_array_elements(const BasicJsonType& j, const std::size_t depth, std::false_type /*fits_64_bits*/)
    {
        for (const auto& el : *j.m_data.m_value.array)
        {
            write_cbor(el, depth + 1);
        }
    }

    /*!
    @brief write the elements of the array @a j, runs of integers with
           @a encode_integer, runs of floats with @a encode_float, and all
           other values with @a write_value

    Runs of numbers are encoded straight into space reserved from the sink
    for a whole run: the write pointer stays a local, where it would otherwise
    be reloaded from the sink for every value, as a store of a character may
    alias it.
    */
    template<typename EncodeInteger, typename EncodeFloat, typename WriteValue>
    void write_array_elements(const BasicJsonType& j, EncodeInteger encode_integer, EncodeFloat encode_float, WriteValue write_value)
    {
        constexpr std::size_t max_run = max_reserve_size / integer_encoding_space;
        auto it = j.m_data.m_value.array->begin();
        const auto end = j.m_data.m_value.array->end();
        while (it != end)
        {
            if (!it->is_number())
            {
                write_value(*it);
                ++it;
            }
            else if (!it->is_number_float())
            {
                CharType* const start = oa.reserve(max_run * integer_encoding_space);
                CharType* out = start;
                for (std::size_t n = 0; n < max_run && it != end && it->is_number_integer(); ++n, ++it)
                {
                    out += encode_integer(out, *it);
                }
                oa.commit(static_cast<std::size_t>(out - start));
            }
            else
            {
                it = write_float_elements(it, end, encode_float);
            }
        }
    }

    /*!
    @brief write the run of floats that starts at @a it with @a encode_float
    @return the first element after the run

    Out of line, so that the loop of integers in @ref write_array_elements is
    not changed by it.
    */
    template<typename Iterator, typename EncodeFloat>
    JSON_HEDLEY_NEVER_INLINE
    Iterator write_float_elements(Iterator it, const Iterator end, EncodeFloat encode_float) // NOLINT(performance-unnecessary-value-param): iterators are passed by value
    {
        constexpr std::size_t max_run = max_reserve_size / integer_encoding_space;
        CharType* const start = oa.reserve(max_run * integer_encoding_space);
        CharType* out = start;
        for (std::size_t n = 0; n < max_run && it != end && it->is_number_float(); ++n, ++it)
        {
            out += encode_float(out, it->m_data.m_value.number_float);
        }
        oa.commit(static_cast<std::size_t>(out - start));
        return it;
    }

    /*!
    @brief write a number_integer or number_unsigned value as a CBOR integer

    A negative integer n has major type 1 and the argument -1 - n, which is ~n.
    Kept out of line, like the other per-value paths, so that write_cbor stays
    small (runs of integers in an array are encoded inline instead).
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_cbor_integer(const BasicJsonType& j, std::true_type /*fits_64_bits*/)
    {
        oa.commit(encode_cbor_integer(oa.reserve(integer_encoding_space), j));
    }

    /// write a number_integer or number_unsigned value of a number type wider
    /// than 64 bits as a CBOR integer, with range checks on the whole value
    void write_cbor_integer(const BasicJsonType& j, std::false_type /*fits_64_bits*/)
    {
        if (j.m_data.m_type == value_t::number_unsigned)
        {
            if (JSON_HEDLEY_UNLIKELY(!integer_fits_max<std::uint64_t>(j.m_data.m_value.number_unsigned)))
            {
                throw_integer_out_of_range(j, input_format_t::cbor, "uint64");
            }
            write_cbor_head(0x00, conditional_static_cast<std::uint64_t>(j.m_data.m_value.number_unsigned));
            return;
        }

        if (j.m_data.m_value.number_integer >= 0)
        {
            if (JSON_HEDLEY_UNLIKELY(!integer_fits_max<std::uint64_t>(j.m_data.m_value.number_integer)))
            {
                throw_integer_out_of_range(j, input_format_t::cbor, "[-2^64, 2^64-1]");
            }
            // CBOR does not differentiate between positive signed
            // integers and unsigned integers
            write_cbor_head(0x00, static_cast<std::uint64_t>(j.m_data.m_value.number_integer));
        }
        else
        {
            // a negative integer n is encoded as -1 - n
            if (JSON_HEDLEY_UNLIKELY(!integer_fits_max<std::uint64_t>(-1 - j.m_data.m_value.number_integer)))
            {
                throw_integer_out_of_range(j, input_format_t::cbor, "[-2^64, 2^64-1]");
            }
            write_cbor_head(0x20, static_cast<std::uint64_t>(-1 - j.m_data.m_value.number_integer));
        }
    }

    /// encode a number_integer or number_unsigned value to @a out (see
    /// @ref write_cbor_integer) and return the number of characters
    std::size_t encode_cbor_integer(CharType* out, const BasicJsonType& j) const noexcept
    {
        std::uint64_t sign_mask = 0;
        const std::uint64_t raw = integer_bits(j, sign_mask);
        // ~raw is -1 - n in the 64 bits that are written
        return encode_cbor_integer_head(out, static_cast<std::uint8_t>(sign_mask & 0x20u), raw ^ sign_mask);
    }

    /*!
    @brief whether the CBOR and MessagePack integers of BasicJsonType are
           written by @ref encode_cbor_integer and @ref encode_msgpack_integer

    These pick the format from the low 64 bits; a wider number type is written
    with range checks on the whole value instead.
    */
    static constexpr bool integers_fit_64_bits() noexcept
    {
        return sizeof(typename BasicJsonType::number_integer_t) <= sizeof(std::uint64_t)
               && sizeof(typename BasicJsonType::number_unsigned_t) <= sizeof(std::uint64_t);
    }

    /*!
    @brief write a number_integer or number_unsigned value as a MessagePack
           integer without branching on its sign or size

    Same output as @ref write_msgpack: a non-negative integer as positive fixint
    (< 128) or uint 8/16/32/64, a negative one as negative fixint (>= -32) or
    int 8/16/32/64. Kept out of line (see @ref write_cbor_integer).
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_msgpack_integer(const BasicJsonType& j, std::true_type /*fits_64_bits*/)
    {
        oa.commit(encode_msgpack_integer(oa.reserve(integer_encoding_space), j));
    }

    /// encode a number_integer or number_unsigned value to @a out (see
    /// @ref write_msgpack_integer) and return the number of characters
    std::size_t encode_msgpack_integer(CharType* out, const BasicJsonType& j) const noexcept
    {
        std::uint64_t sign_mask = 0;
        const std::uint64_t raw = integer_bits(j, sign_mask);

        // A negative n fits int 8/16/32 exactly if 2 * (-1 - n) + 1 fits
        // uint 8/16/32, so x gives the size class of either sign.
        const std::uint64_t is_negative = sign_mask & 1u;
        const std::uint64_t x = ((raw ^ sign_mask) << is_negative) | is_negative;

        // A fixint is at most 127, or at least -32 (x at most 63). It is in
        // size class 1 and is moved to class 0, the first byte, by subtracting 1.
        const auto is_fixint = static_cast<unsigned>(x <= (127u ^ (sign_mask & 64u)));
        const unsigned size_class = integer_size_class(x) - is_fixint;

        // the first byte: the low byte of the integer for a fixint, else the
        // marker 0xCC..0xCF (uint) or 0xD0..0xD3 (int), selected through a mask
        const std::uint64_t fixint_mask = std::uint64_t{0} - is_fixint;
        const std::uint64_t marker = 0xCBu + size_class + (sign_mask & 4u);
        const auto first_byte = static_cast<std::uint8_t>((raw & fixint_mask) | (marker & ~fixint_mask));
        return encode_first_byte_and_tail(out, first_byte, size_class, raw);
    }

    /// write a number_integer or number_unsigned value of a number type wider
    /// than 64 bits as a MessagePack integer, with range checks on the whole value
    void write_msgpack_integer(const BasicJsonType& j, std::false_type /*fits_64_bits*/)
    {
        if (j.m_data.m_type == value_t::number_unsigned)
        {
            if (JSON_HEDLEY_UNLIKELY(!integer_fits_max<std::uint64_t>(j.m_data.m_value.number_unsigned)))
            {
                throw_integer_out_of_range(j, input_format_t::msgpack, "uint64");
            }
            write_msgpack_unsigned(static_cast<std::uint64_t>(j.m_data.m_value.number_unsigned));
            return;
        }

        if (j.m_data.m_value.number_integer >= 0)
        {
            if (JSON_HEDLEY_UNLIKELY(!integer_fits_max<std::uint64_t>(j.m_data.m_value.number_integer)))
            {
                throw_integer_out_of_range(j, input_format_t::msgpack, "[-2^63, 2^64-1]");
            }
            // MessagePack does not differentiate between positive
            // signed integers and unsigned integers.
            write_msgpack_unsigned(static_cast<std::uint64_t>(j.m_data.m_value.number_integer));
        }
        else
        {
            if (JSON_HEDLEY_UNLIKELY(!integer_fits_min<std::int64_t>(j.m_data.m_value.number_integer)))
            {
                throw_integer_out_of_range(j, input_format_t::msgpack, "[-2^63, 2^64-1]");
            }
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
    }

    /// write a float as MessagePack, into space reserved from the sink
    JSON_HEDLEY_NEVER_INLINE
    void write_msgpack_float(const number_float_t n)
    {
        oa.commit(encode_compact_float(oa.reserve(integer_encoding_space), n, to_char_type(0xCA), to_char_type(0xCB)));
    }

    /*!
    @brief write an object value (head and members) as MessagePack

    See @ref write_cbor_object.
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_msgpack_object(const BasicJsonType& j, const std::size_t depth)
    {
        write_msgpack_object_prefix(j.m_data.m_value.object->size(), j);

        for (const auto& el : *j.m_data.m_value.object)
        {
            // as in write_cbor, el.first is written directly with the
            // object as diagnostics context
            write_msgpack_key(el.first, j);

            const BasicJsonType& value = el.second;
            switch (value.type())
            {
                case value_t::null:
                    oa.write_character(to_char_type(0xC0));
                    break;

                case value_t::boolean:
                    oa.write_character(value.m_data.m_value.boolean ? to_char_type(0xC3) : to_char_type(0xC2));
                    break;

                case value_t::number_integer:
                case value_t::number_unsigned:
                    write_msgpack_integer(value, std::integral_constant<bool, integers_fit_64_bits()>());
                    break;

                case value_t::number_float:
                    write_msgpack_float(value.m_data.m_value.number_float);
                    break;

                case value_t::string:
                    write_msgpack_string(*value.m_data.m_value.string, value);
                    break;

                case value_t::object:
                case value_t::array:
                case value_t::binary:
                case value_t::discarded:
                default:
                    write_msgpack(value, depth + 1);
                    break;
            }
        }
    }

    /*!
    @brief write an array value (head and elements) as MessagePack

    See @ref write_cbor_array.
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_msgpack_array(const BasicJsonType& j, const std::size_t depth)
    {
        write_msgpack_array_prefix(j.m_data.m_value.array->size(), j);
        if (!j.m_data.m_value.array->empty())
        {
            write_msgpack_array_elements(j, depth, std::integral_constant<bool, integers_fit_64_bits()>());
        }
    }

    JSON_HEDLEY_NEVER_INLINE
    void write_msgpack_array_elements(const BasicJsonType& j, const std::size_t depth, std::true_type /*fits_64_bits*/)
    {
        write_array_elements(j, [this](CharType * out, const BasicJsonType & el)
        {
            return encode_msgpack_integer(out, el);
        }, [this](CharType * out, const number_float_t n)
        {
            return encode_compact_float(out, n, to_char_type(0xCA), to_char_type(0xCB));
        }, [this, depth](const BasicJsonType & el)
        {
            write_msgpack(el, depth + 1);
        });
    }

    void write_msgpack_array_elements(const BasicJsonType& j, const std::size_t depth, std::false_type /*fits_64_bits*/)
    {
        for (const auto& el : *j.m_data.m_value.array)
        {
            write_msgpack(el, depth + 1);
        }
    }

    /*!
    @brief write an object key as a CBOR or MessagePack string (@a Walk)

    A key convertible to string_t is written directly. Other key types (only
    an explicit conversion, or only a to_json overload) go through a temporary
    basic_json, as in version 3.12.0; the temporary is then the diagnostics
    context for strict UTF-8 checks.
    */
    template<typename Walk, typename Key = typename BasicJsonType::object_t::key_type,
             enable_if_t<std::is_convertible<Key, string_t>::value, int> = 0>
    void write_object_key(const typename BasicJsonType::object_t::key_type& key, const BasicJsonType& context)
    {
        Walk::string(*this, key, context);
    }

    template<typename Walk, typename Key = typename BasicJsonType::object_t::key_type,
             enable_if_t<negation<std::is_convertible<Key, string_t>>::value, int> = 0>
    void write_object_key(const typename BasicJsonType::object_t::key_type& key, const BasicJsonType& /*context*/)
    {
        Walk::scalar(*this, BasicJsonType(key));
    }

    /// @brief write an object key as a CBOR text string
    void write_cbor_key(const typename BasicJsonType::object_t::key_type& key, const BasicJsonType& context)
    {
        write_object_key<cbor_walk>(key, context);
    }

    /// @brief write an object key as a MessagePack str
    void write_msgpack_key(const typename BasicJsonType::object_t::key_type& key, const BasicJsonType& context)
    {
        write_object_key<msgpack_walk>(key, context);
    }

    /// the longest string that is written, with its head of one or two
    /// characters, in a single reservation from the sink
    static constexpr std::size_t max_text_in_reservation = max_reserve_size - 2;

    /// copy the characters of a string to space in the sink; a short one
    /// without a call of memcpy()
    static void copy_characters(CharType* dst, const CharType* src, const std::size_t length) noexcept
    {
        if (length <= 32)
        {
            copy_short(dst, src, length, std::integral_constant<bool, sizeof(CharType) == 1>());
        }
        else
        {
            std::memcpy(dst, src, length * sizeof(CharType));
        }
    }

    /*!
    @brief write a CBOR text string

    @a value is checked or sanitized according to @ref error_handler, with
    @a context (the string value itself, or the object a key belongs to) used
    as diagnostics context; this avoids converting object keys to a temporary
    basic_json just to write them

    @note When object_t::key_type is not string_t, @a value is a temporary
          string_t converted from the key, which lives only until the end of
          the caller's statement. The reference returned by
          @ref sanitize_utf8_for_write may refer to it, so it must not escape
          this function.
    */
    void write_cbor_string(const string_t& value, const BasicJsonType& context)
    {
        if (JSON_HEDLEY_LIKELY(error_handler == error_handler_t::keep))
        {
            // the string is written as it is: head and characters in one reservation
            if (JSON_HEDLEY_LIKELY(value.size() <= max_text_in_reservation))
            {
                CharType* const out = oa.reserve(value.size() + 2);
                CharType* p = out;
                if (value.size() <= 0x17)
                {
                    *p++ = to_char_type(static_cast<std::uint8_t>(0x60 + value.size()));
                }
                else
                {
                    *p++ = to_char_type(0x78);
                    *p++ = to_char_type(static_cast<std::uint8_t>(value.size()));
                }
                copy_characters(p, reinterpret_cast<const CharType*>(value.data()), value.size());
                oa.commit(static_cast<std::size_t>(p - out) + value.size());
                return;
            }
        }

        write_cbor_checked_string(value, context);
    }

    /// @brief write a CBOR text string checked or sanitized by the error handler;
    ///        out of line, as the string_t for the sanitized copy would make
    ///        every call of @ref write_cbor_string set up a frame for it
    JSON_HEDLEY_NEVER_INLINE
    void write_cbor_checked_string(const string_t& value, const BasicJsonType& context)
    {
        string_t storage;
        const string_t& sanitized = sanitize_utf8_for_write(value, context, storage);

        // step 1: write control byte and the string length
        write_cbor_head(0x60, sanitized.size());

        // step 2: write the string
        write_bytes(sanitized.data(), sanitized.size());
    }

    /////////////
    // MsgPack //
    /////////////

    /*!
    @brief write a MessagePack str

    @a value is checked or sanitized according to @ref error_handler, with
    @a context used as diagnostics context, as in @ref write_cbor_string

    @note As in @ref write_cbor_string, @a value may be a temporary string_t
          converted from a key, so the reference returned by
          @ref sanitize_utf8_for_write must not escape this function.
    */
    void write_msgpack_string(const string_t& value, const BasicJsonType& context)
    {
        if (JSON_HEDLEY_LIKELY(error_handler == error_handler_t::keep))
        {
            // the string is written as it is: head and characters in one reservation
            if (JSON_HEDLEY_LIKELY(value.size() <= max_text_in_reservation))
            {
                CharType* const out = oa.reserve(value.size() + 2);
                CharType* p = out;
                if (value.size() <= 31)
                {
                    // fixstr
                    *p++ = to_char_type(static_cast<std::uint8_t>(0xA0 | value.size()));
                }
                else
                {
                    // str 8
                    *p++ = to_char_type(0xD9);
                    *p++ = to_char_type(static_cast<std::uint8_t>(value.size()));
                }
                copy_characters(p, reinterpret_cast<const CharType*>(value.data()), value.size());
                oa.commit(static_cast<std::size_t>(p - out) + value.size());
                return;
            }
        }

        write_msgpack_checked_string(value, context);
    }

    /// @brief write a MessagePack str checked or sanitized by the error handler;
    ///        out of line, like @ref write_cbor_checked_string
    JSON_HEDLEY_NEVER_INLINE
    void write_msgpack_checked_string(const string_t& value, const BasicJsonType& context)
    {
        string_t storage;
        const string_t& sanitized = sanitize_utf8_for_write(value, context, storage);

        // step 1: write control byte and the string length
        const auto N = to_msgpack_length(sanitized.size(), context);
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
        write_bytes(sanitized.data(), sanitized.size());
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
    @brief markers and size classes of UBJSON/BJData integers, by the bit length
           of the magnitude

    A non-negative integer has the magnitude n, a negative one ~n = -1 - n; the
    bit length of the magnitude is 1 to 64. The first 130 characters of the
    table are the markers: 65 for a non-negative integer, then 65 for a negative
    one (index + 65). The marker is the first of `i`, `U`, `I`, `u` (BJData),
    `l`, `m` (BJData), `L`, `M` (BJData) whose range contains the integer; `H`
    (a high-precision number) is for a non-negative integer of 64 bits in
    UBJSON. The following 130 characters are the size classes at index + 130:
    the digit 0, 1, 2, or 3 for 1, 2, 4, or 8 bytes. Looked up, like
    @ref integer_size_class, instead of found by branches or comparisons.

    @sa ubjson_integer_prefix for the integers of types of more than 64 bits
    */
    static const char* ubjson_integer_table(const bool use_bjdata) noexcept
    {
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): initialized from string literals
        static constexpr char ubjson_table[] =
            // the markers for n >= 0, then n < 0
            "i" "iiiiiii" "U" "IIIIIII" "llllllllllllllll" "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL" "H"
            "i" "iiiiiii" "IIIIIIII" "llllllllllllllll" "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL" "L"
            // the size classes
            "000000000" "1111111" "2222222222222222" "333333333333333333333333333333333"
            "00000000" "11111111" "2222222222222222" "333333333333333333333333333333333";
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): initialized from string literals
        static constexpr char bjdata_table[] =
            "i" "iiiiiii" "U" "IIIIIII" "u" "lllllllllllllll" "m" "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL" "M"
            "i" "iiiiiii" "IIIIIIII" "llllllllllllllll" "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL" "L"
            "000000000" "11111111" "2222222222222222" "33333333333333333333333333333333"
            "00000000" "11111111" "2222222222222222" "333333333333333333333333333333333";
        static_assert(sizeof(ubjson_table) == 261 && sizeof(bjdata_table) == 261, "two tables of 130 markers and 130 size classes");
        return use_bjdata ? bjdata_table : ubjson_table;
    }

    /// the index in ubjson_integer_table() of the integer with the 64 bits
    /// @a raw and the sign mask @a sign_mask (all ones if it is negative)
    static std::size_t ubjson_integer_index(const std::uint64_t raw, const std::uint64_t sign_mask) noexcept
    {
        const std::size_t sign_offset = sign_mask != 0 ? std::size_t{65} :
                                        std::size_t{0};
        return static_cast<std::size_t>(64 - count_leading_zeros((raw ^ sign_mask) | 1u)) + sign_offset;
    }

    /*!
    @brief encode a UBJSON/BJData integer without branching on its size
    @param[in] out  where the encoding goes; at most 9 characters are written
    @param[in] raw  the 64 bits of the integer (two's complement)
    @param[in] sign_mask  all ones if the integer is negative, else zero
    @param[in] table  ubjson_integer_table(use_bjdata)
    @return the end of the encoding, or nullptr if the integer is a high-precision
            number (a non-negative one of 64 bits in UBJSON), which is not written
    */
    CharType* encode_ubjson_integer(CharType* out, const std::uint64_t raw, const std::uint64_t sign_mask,
                                    const bool add_prefix, const bool use_bjdata, const char* table) const noexcept
    {
        const std::size_t index = ubjson_integer_index(raw, sign_mask);
        const char marker = table[index];
        if (JSON_HEDLEY_UNLIKELY(marker == 'H'))
        {
            return nullptr;
        }
        const unsigned size_class = static_cast<unsigned>(table[index + 130]) & 3u;

        // the marker (or its place, if not written) and one 8-byte word, whose
        // bytes after the integer are scratch that the caller drops
        out[0] = to_char_type(static_cast<std::uint8_t>(marker));
        out += add_prefix ? 1 : 0;
        const unsigned unused_bits = 64u - (8u << size_class);
        // UBJSON in network order, BJData in little-endian
        std::uint64_t tail = 0;
        if (use_bjdata)
        {
            tail = is_little_endian ? raw : byteswap(raw);
        }
        else
        {
            tail = is_little_endian ? byteswap(raw) >> unused_bits : raw << unused_bits;
        }
        std::memcpy(out, &tail, sizeof(tail));
        return out + (std::size_t{1} << size_class);
    }

    /// @brief whether the integers of BasicJsonType are written by
    ///        @ref encode_ubjson_integer
    static constexpr bool ubjson_integers_fit_64_bits() noexcept
    {
        return integers_fit_64_bits();
    }

    /// space for the largest encoding of encode_ubjson_integer(): the marker and 8 bytes
    static constexpr std::size_t ubjson_integer_encoding_space = 9;

    /*!
    @brief write the bytes of a binary value as an array of UBJSON uint8 values

    Every byte is written with its marker, in blocks that fit the space reserved
    from the sink. Kept out of line, so that write_ubjson does not carry the
    registers of its loop.
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_ubjson_binary_bytes(const binary_t& binary, const bool bjdata_draft3)
    {
        const CharType marker = to_char_type(bjdata_draft3 ? 'B' : 'U');
        const auto* const data = binary.data();
        const std::size_t size = binary.size();
        for (std::size_t i = 0; i < size;)
        {
            const std::size_t block = (std::min)(size - i, max_reserve_size / 2);
            CharType* const out = oa.reserve(2 * block);
            for (std::size_t k = 0; k < block; ++k)
            {
                out[2 * k] = marker;
                // the cast is needed for binary types whose value type
                // is not an integer (e.g., std::byte)
                out[(2 * k) + 1] = to_char_type(static_cast<std::uint8_t>(data[i + k]));
            }
            i += block;
            oa.commit(2 * block);
        }
    }

    /*!
    @brief write the members of the object @a j of a UBJSON/BJData container

    A member whose value is null, a boolean, an integer, a float, or a string is
    written without a call of @ref write_ubjson. Kept out of line, like
    @ref write_cbor_object.
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_ubjson_members(const BasicJsonType& j, const bool use_count, const bool use_type,
                              const bool prefix_required, const bool use_bjdata, const bjdata_version_t bjdata_version,
                              const std::size_t depth)
    {
        for (const auto& el : *j.m_data.m_value.object)
        {
            // a converted key must outlive the reference returned by sanitize_utf8_for_write
            const object_key_string_t key_string = el.first;
            write_ubjson_text(key_string, j, false, use_bjdata);

            const BasicJsonType& value = el.second;
            switch (value.type())
            {
                case value_t::null:
                    if (prefix_required)
                    {
                        oa.write_character(to_char_type('Z'));
                    }
                    break;

                case value_t::boolean:
                    if (prefix_required)
                    {
                        oa.write_character(value.m_data.m_value.boolean ? to_char_type('T') : to_char_type('F'));
                    }
                    break;

                case value_t::number_integer:
                    write_number_with_ubjson_prefix(value.m_data.m_value.number_integer, prefix_required, use_bjdata);
                    break;

                case value_t::number_unsigned:
                    write_number_with_ubjson_prefix(value.m_data.m_value.number_unsigned, prefix_required, use_bjdata);
                    break;

                case value_t::number_float:
                    write_number_with_ubjson_prefix(value.m_data.m_value.number_float, prefix_required, use_bjdata);
                    break;

                case value_t::string:
                    write_ubjson_text(*value.m_data.m_value.string, value, prefix_required, use_bjdata);
                    break;

                case value_t::object:
                case value_t::array:
                case value_t::binary:
                case value_t::discarded:
                default:
                    write_ubjson(value, use_count, use_type, prefix_required, use_bjdata, bjdata_version, depth + 1);
                    break;
            }
        }
    }

    /// write the count marker `#` and the number of elements of a container as
    /// an integer; a count of up to 127, which is `i` and a byte, in one reservation
    void write_ubjson_count(const std::size_t count, const bool use_bjdata)
    {
        if (JSON_HEDLEY_LIKELY(count <= 127))
        {
            CharType* const out = oa.reserve(3);
            out[0] = to_char_type('#');
            out[1] = to_char_type('i');
            out[2] = to_char_type(static_cast<std::uint8_t>(count));
            oa.commit(3);
            return;
        }
        oa.write_character(to_char_type('#'));
        write_number_with_ubjson_prefix(count, true, use_bjdata);
    }

    /*!
    @brief write a UBJSON/BJData string or object key: the optional string
           marker `S`, the length as an integer with its marker, and the characters

    With the default error handler (keep) and a string of up to 253 characters,
    which has a length of the marker `i` or `U` and a single byte, everything is
    written into space reserved from the sink in one go.

    @param[in] value  the string; checked or sanitized according to
                      @ref error_handler, with @a context as diagnostics context
    @param[in] add_marker  whether `S` is written first (not for an object key)
    */
    void write_ubjson_text(const string_t& value, const BasicJsonType& context, const bool add_marker, const bool use_bjdata)
    {
        const std::size_t size = value.size();
        if (JSON_HEDLEY_LIKELY(error_handler == error_handler_t::keep) && JSON_HEDLEY_LIKELY(size <= max_text_in_reservation - 1))
        {
            CharType* const out = oa.reserve(size + 3);
            CharType* p = out;
            if (add_marker)
            {
                *p++ = to_char_type('S');
            }
            *p++ = to_char_type(size <= 127 ? 'i' : 'U');
            *p++ = to_char_type(static_cast<std::uint8_t>(size));
            copy_characters(p, reinterpret_cast<const CharType*>(value.data()), size);
            oa.commit(static_cast<std::size_t>(p - out) + size);
            return;
        }

        write_ubjson_checked_text(value, context, add_marker, use_bjdata);
    }

    /// @brief write a UBJSON/BJData string checked or sanitized by the error
    ///        handler; out of line, like @ref write_cbor_checked_string
    JSON_HEDLEY_NEVER_INLINE
    void write_ubjson_checked_text(const string_t& value, const BasicJsonType& context, const bool add_marker, const bool use_bjdata)
    {
        string_t storage;
        const string_t& sanitized = sanitize_utf8_for_write(value, context, storage);
        if (add_marker)
        {
            oa.write_character(to_char_type('S'));
        }
        write_number_with_ubjson_prefix(sanitized.size(), true, use_bjdata);
        write_bytes(sanitized.data(), sanitized.size());
    }

    /*!
    @brief encode a UBJSON/BJData float, with its marker if @a add_prefix
    @param[in] out  where the encoding goes; at most 9 characters are written
    @return the end of the encoding
    */
    CharType* encode_ubjson_float(CharType* out, const number_float_t n, const bool add_prefix, const bool use_bjdata) const noexcept
    {
        if (add_prefix)
        {
            *out++ = get_ubjson_float_prefix<number_float_t>();
        }
        return store_number(out, n, use_bjdata);
    }

    /// whether @a array starts with a number that @ref write_ubjson_array_elements
    /// can encode (all but an integer that UBJSON writes as a high-precision
    /// number); an array that does not is written by write_ubjson one element at a time
    template<typename ArrayType>
    static bool starts_with_ubjson_number(const ArrayType& array, const bool use_bjdata, std::true_type /*fits_64_bits*/) noexcept
    {
        if (array.empty() || !array.front().is_number())
        {
            return false;
        }
        const BasicJsonType& first = array.front();
        return use_bjdata || first.m_data.m_type != value_t::number_unsigned
               || (static_cast<std::uint64_t>(first.m_data.m_value.number_unsigned) >> 63u) == 0;
    }

    template<typename ArrayType>
    static bool starts_with_ubjson_number(const ArrayType& /*array*/, const bool /*use_bjdata*/, std::false_type /*fits_64_bits*/) noexcept
    {
        return false;
    }

    /*!
    @brief write the elements of an array of a UBJSON/BJData container that
           starts with a number, with runs of numbers encoded without a call of
           @ref write_ubjson for each

    Same output as calling write_ubjson for each element. The numbers of a
    run are encoded straight into space reserved from the sink, as in
    @ref write_array_elements; all other values, and an integer that UBJSON
    writes as a high-precision number, are written with write_ubjson. Kept out
    of line, like @ref write_cbor_array.
    */
    template<typename ArrayType>
    JSON_HEDLEY_NEVER_INLINE
    void write_ubjson_array_elements(const ArrayType& array, const bool use_count, const bool use_type,
                                     const bool prefix_required, const bool use_bjdata, const bjdata_version_t bjdata_version,
                                     const std::size_t depth)
    {
        constexpr std::size_t max_run = max_reserve_size / ubjson_integer_encoding_space;
        const char* const table = ubjson_integer_table(use_bjdata);
        auto it = array.begin();
        const auto end = array.end();
        while (it != end)
        {
            if (!it->is_number())
            {
                write_ubjson(*it, use_count, use_type, prefix_required, use_bjdata, bjdata_version, depth + 1);
                ++it;
                continue;
            }

            CharType* const start = oa.reserve(max_run * ubjson_integer_encoding_space);
            CharType* out = start;
            bool unencodable = false;
            for (std::size_t n = 0; n < max_run && it != end && it->is_number(); ++n)
            {
                CharType* next = nullptr;
                if (it->is_number_float())
                {
                    next = encode_ubjson_float(out, it->m_data.m_value.number_float, prefix_required, use_bjdata);
                }
                else
                {
                    std::uint64_t sign_mask = 0;
                    const std::uint64_t raw = integer_bits(*it, sign_mask);
                    next = encode_ubjson_integer(out, raw, sign_mask, prefix_required, use_bjdata, table);
                }
                if (JSON_HEDLEY_UNLIKELY(next == nullptr))
                {
                    unencodable = true;
                    break;
                }
                out = next;
                ++it;
            }
            oa.commit(static_cast<std::size_t>(out - start));

            if (unencodable)
            {
                write_ubjson(*it, use_count, use_type, prefix_required, use_bjdata, bjdata_version, depth + 1);
                ++it;
            }
        }
    }

    /*!
    @brief store @a n at @a out in the byte order of the output
    @param[in] output_little_endian  whether the output is little-endian
    @return the end of the number
    */
    template<typename NumberType>
    CharType* store_number(CharType* out, const NumberType n, const bool output_little_endian) const noexcept
    {
        std::array<CharType, sizeof(NumberType)> vec{};
        std::memcpy(vec.data(), &n, sizeof(NumberType));
        if (is_little_endian != output_little_endian)
        {
            reverse_bytes(vec);
        }
        std::memcpy(out, vec.data(), sizeof(NumberType));
        return out + sizeof(NumberType);
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
        if (use_bjdata && std::is_unsigned<NumberType>::value && integer_fits_max<std::uint64_t>(n))
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
                JSON_ASSERT(prefix == 'H');
                write_ubjson_high_precision(n, use_bjdata);
                break;
            }
        }
    }

    /// @brief write an integer as a high-precision number: its decimal digits as
    ///        a string; out of line, as the string would otherwise burden
    ///        @ref write_ubjson_integer_payload for every integer
    template<typename NumberType>
    JSON_HEDLEY_NEVER_INLINE
    void write_ubjson_high_precision(const NumberType n, const bool use_bjdata)
    {
        write_ubjson_high_precision(n, use_bjdata, std::integral_constant < bool, std::is_unsigned<NumberType>::value && sizeof(NumberType) <= sizeof(std::uint64_t) > ());
    }

    /// an unsigned integer of at most 64 bits: its decimal digits are written directly
    template<typename NumberType>
    void write_ubjson_high_precision(const NumberType n, const bool use_bjdata, std::true_type /*is_unsigned_64_bits*/)
    {
        std::array<char, 20> digits; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::size_t first = digits.size();
        auto value = static_cast<std::uint64_t>(n);
        do
        {
            digits[--first] = static_cast<char>('0' + (value % 10));
            value /= 10;
        }
        while (value != 0);
        const std::size_t length = digits.size() - first;
        write_number_with_ubjson_prefix(length, true, use_bjdata);
        CharType* const out = oa.reserve(digits.size());
        for (std::size_t i = 0; i < length; ++i)
        {
            out[i] = to_char_type(static_cast<std::uint8_t>(digits[first + i]));
        }
        oa.commit(length);
    }

    /// any other integer: its decimal digits from basic_json::dump()
    template<typename NumberType>
    void write_ubjson_high_precision(const NumberType n, const bool use_bjdata, std::false_type /*is_unsigned_64_bits*/)
    {
        const auto number = BasicJsonType(n).dump();
        write_number_with_ubjson_prefix(number.size(), true, use_bjdata);
        for (std::size_t i = 0; i < number.size(); ++i)
        {
            oa.write_character(to_char_type(static_cast<std::uint8_t>(number[i])));
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
            wrapping, regardless of which of the two kinds it is stored as;
            false for a value that does not even fit the 64-bit type it is
            read as (possible for number types wider than 64 bits)
    */
    template<typename TargetType>
    static bool bjdata_ndarray_value_in_range(const BasicJsonType& el)
    {
        return el.is_number_unsigned()
               ? integer_fits_max<std::uint64_t>(el.m_data.m_value.number_unsigned) && value_in_range_of<TargetType>(static_cast<std::uint64_t>(el.m_data.m_value.number_unsigned))
               : integer_fits<std::int64_t>(el.m_data.m_value.number_integer) && value_in_range_of<TargetType>(static_cast<std::int64_t>(el.m_data.m_value.number_integer));
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
    @return whether @a el's value survives narrowing to float and back without any change
            (so the ND-array round-trips exactly), or is infinite or NaN; always true when
            @a dry_run is false
    */
    bool write_bjdata_ndarray_float_element(const BasicJsonType& el, const bool dry_run)
    {
        const auto dval = static_cast<double>(el.m_data.m_value.number_float);
        if (dry_run)
        {
#ifdef __GNUC__
            JSON_HEDLEY_DIAGNOSTIC_PUSH
            JSON_HEDLEY_PRAGMA(GCC diagnostic ignored "-Wfloat-equal")
#endif
            // a value that would be rounded (rather than exactly represented) by the
            // narrowing to float is treated like an out-of-range integer element; this
            // is the same criterion write_compact_float() uses for CBOR/MessagePack
            const bool in_range = std::isnan(dval) ||
                                  (dval >= static_cast<double>(std::numeric_limits<float>::lowest()) &&
                                   dval <= static_cast<double>((std::numeric_limits<float>::max)()) &&
                                   static_cast<double>(static_cast<float>(dval)) == dval) ||
                                  std::isinf(dval);
#ifdef __GNUC__
            JSON_HEDLEY_DIAGNOSTIC_POP
#endif
            return in_range;
        }
        write_number(static_cast<float>(dval), true);
        return true;
    }

    /*!
    @brief write the elements of an ND-array as the number kind @a dtype names
           (see @ref write_bjdata_ndarray), after they have been found to be
           in range by a dry run of @ref write_bjdata_ndarray_elements

    The elements are encoded in blocks into space reserved from the sink.
    */
    void write_bjdata_ndarray_values(const BasicJsonType& array_data, const CharType dtype)
    {
        switch (dtype)
        {
            case 'U':
            case 'C':
            case 'B':
                write_bjdata_ndarray_block<std::uint8_t>(array_data);
                break;
            case 'i':
                write_bjdata_ndarray_block<std::int8_t>(array_data);
                break;
            case 'u':
                write_bjdata_ndarray_block<std::uint16_t>(array_data);
                break;
            case 'I':
                write_bjdata_ndarray_block<std::int16_t>(array_data);
                break;
            case 'm':
                write_bjdata_ndarray_block<std::uint32_t>(array_data);
                break;
            case 'l':
                write_bjdata_ndarray_block<std::int32_t>(array_data);
                break;
            case 'M':
                write_bjdata_ndarray_block<std::uint64_t>(array_data);
                break;
            case 'L':
                write_bjdata_ndarray_block<std::int64_t>(array_data);
                break;
            case 'd':
                write_bjdata_ndarray_block<float>(array_data);
                break;
            case 'D':
            default:
                // 'D' (double) already spans the full range of number_float_t
                write_bjdata_ndarray_block<double>(array_data);
                break;
        }
    }

    /// the value of an ND-array element that is an integer, as the integer type that @a T is converted from
    template<typename T>
    static T bjdata_ndarray_integer(const BasicJsonType& el, std::true_type /*is_integral*/) noexcept
    {
        using storage_type = typename std::conditional<std::is_unsigned<T>::value, std::uint64_t, std::int64_t>::type;
        return static_cast<T>(el.is_number_unsigned()
                              ? static_cast<storage_type>(el.m_data.m_value.number_unsigned)
                              : static_cast<storage_type>(el.m_data.m_value.number_integer));
    }

    /// the value of an ND-array element that is a float
    template<typename T>
    static T bjdata_ndarray_integer(const BasicJsonType& el, std::false_type /*is_integral*/) noexcept
    {
        return static_cast<T>(static_cast<double>(el.m_data.m_value.number_float));
    }

    /// write the elements of an ND-array as @a T, little-endian, in blocks
    template<typename T>
    void write_bjdata_ndarray_block(const BasicJsonType& array_data)
    {
        constexpr std::size_t per_block = max_reserve_size / sizeof(T);
        auto it = array_data.m_data.m_value.array->begin();
        const auto end = array_data.m_data.m_value.array->end();
        while (it != end)
        {
            CharType* const start = oa.reserve(per_block * sizeof(T));
            CharType* out = start;
            for (std::size_t n = 0; n < per_block && it != end; ++n, ++it)
            {
                out = store_number(out, bjdata_ndarray_integer<T>(*it, std::is_integral<T>()), true);
            }
            oa.commit(static_cast<std::size_t>(out - start));
        }
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
        if (!dry_run)
        {
            write_bjdata_ndarray_values(array_data, dtype);
            return true;
        }

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
            // is not a non-negative integer in the range of std::uint64_t is
            // rejected: a non-integer entry would pun unrelated bytes as the
            // dimension, and a negative or wider one would wrap into a
            // nonsensical length
            if (!el.is_number_integer() || !bjdata_ndarray_value_in_range<std::uint64_t>(el))
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
    @param[in] depth            nesting level of @a j, counted from the
                                top-level value passed to @ref basic_json::to_bon8
    @throw type_error.316 if a string value or an object key is not valid
           UTF-8
    @throw out_of_range.407 if an unsigned integer does not fit int64
    @throw type_error.321 if @a j or a value nested in it is discarded

    Values nested deeper than @ref recursion_depth_limit are written by
    @ref write_bon8_iterative without the call stack.

    @sa @ref write_cbor
    @sa https://github.com/nlohmann/json/issues/5392
    */
    void write_bon8_value(const BasicJsonType& j, bool& string_open, const std::size_t depth = 0)
    {
        if (JSON_HEDLEY_UNLIKELY(depth >= recursion_depth_limit()) && (j.is_array() || j.is_object()))
        {
            write_bon8_iterative(j, string_open);
            return;
        }

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
                if (JSON_HEDLEY_UNLIKELY(!integer_fits_max<std::int64_t>(j.m_data.m_value.number_unsigned)))
                {
                    throw_integer_out_of_range(j, input_format_t::bon8, "int64");
                }
                write_bon8_integer(static_cast<std::int64_t>(j.m_data.m_value.number_unsigned));
                string_open = false;
                break;
            }

            case value_t::number_integer:
            {
                if (JSON_HEDLEY_UNLIKELY(!integer_fits<std::int64_t>(j.m_data.m_value.number_integer)))
                {
                    throw_integer_out_of_range(j, input_format_t::bon8, "int64");
                }
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

                if (N != 0 && j.m_data.m_value.array->front().is_number())
                {
                    write_bon8_array_elements(*j.m_data.m_value.array, string_open, depth);
                }
                else
                {
                    for (const auto& el : *j.m_data.m_value.array)
                    {
                        write_bon8_value(el, string_open, depth + 1);
                    }
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

                write_bon8_members(j, string_open, depth);

                if (N > 4)
                {
                    write_bon8_marker(0xFE, string_open);
                }
                break;
            }

            case value_t::binary:
            {
                write_bon8_binary(*j.m_data.m_value.binary, string_open);
                break;
            }

            case value_t::discarded:
            default:
                throw_on_discarded(j, input_format_t::bon8);
        }
    }

    /*!
    @brief write @a j with @ref write_bon8_value, or write its marker and push
           a frame for @ref write_bon8_iterative to continue with its elements

    A scalar, and an empty array or object, are written out in full and not
    pushed.

    @sa @ref write_container_value_or_push
    */
    void write_bon8_value_or_push(const BasicJsonType& j, bool& string_open, std::vector<binary_container_frame>& stack)
    {
        if (j.is_array() || j.is_object())
        {
            // arrays use the markers 0x80..0x85, objects 0x86..0x8B; the last
            // one stands for more than four elements, closed later with 0xFE
            const auto N = j.size();
            const std::size_t base = j.is_array() ? 0x80 : 0x86;
            write_bon8_marker(static_cast<std::uint8_t>(base + (N <= 4 ? N : 5)), string_open);
            if (N != 0)
            {
                stack.emplace_back(&j);
            }
            return;
        }

        write_bon8_value(j, string_open);
    }

    /*!
    @brief write out @a root and everything below it without the call stack

    A container with more than four elements is closed with 0xFE once its
    last element is written, as in @ref write_bon8_value.

    @sa @ref write_cbor_iterative
    */
    void write_bon8_iterative(const BasicJsonType& root, bool& string_open)
    {
        // only a container with elements is ever pushed; see write_bon8_value_or_push
        std::vector<binary_container_frame> stack;
        write_bon8_value_or_push(root, string_open, stack);

        while (!stack.empty())
        {
            const binary_container_frame current = stack.back();
            const bool is_array = current.value->is_array();
            const bool at_end = is_array
                                ? current.array_it == current.value->m_data.m_value.array->cend()
                                : current.object_it == current.value->m_data.m_value.object->cend();

            if (at_end)
            {
                if (current.value->size() > 4)
                {
                    write_bon8_marker(0xFE, string_open);
                }
                stack.pop_back();
                continue;
            }

            // read the child before pushing: entering it can move every frame
            const BasicJsonType* child = nullptr;
            if (is_array)
            {
                child = &(*current.array_it);
                ++stack.back().array_it;
            }
            else
            {
                write_bon8_string(current.object_it->first, string_open, *current.value);
                child = &(current.object_it->second);
                ++stack.back().object_it;
            }
            write_bon8_value_or_push(*child, string_open, stack);
        }
    }

    /*!
    @brief encode an integer as @ref write_bon8_integer writes it
    @param[in] out  where the encoding goes; at most 9 characters are written
    @return the end of the encoding
    */
    CharType* encode_bon8_integer(CharType* out, std::int64_t value) const noexcept
    {
        if (value < (std::numeric_limits<std::int32_t>::min)() || value > (std::numeric_limits<std::int32_t>::max)())
        {
            *out++ = to_char_type(0x8D);
            return store_number(out, value, false);
        }
        if (value < -33818506 || value > 67637031)
        {
            *out++ = to_char_type(0x8C);
            return store_number(out, static_cast<std::int32_t>(value), false);
        }
        if (value <= -264075)
        {
            value = -(value + 264075);
            return put_bon8_bytes(out, 0xF0 + ((value >> 22) & 0x07), 0xC0 + ((value >> 16) & 0x3F), value >> 8, value);
        }
        if (value <= -1931)
        {
            value = -(value + 1931);
            return put_bon8_bytes(out, 0xE0 + ((value >> 14) & 0x0F), 0xC0 + ((value >> 8) & 0x3F), value);
        }
        if (value <= -11)
        {
            value = -(value + 11);
            return put_bon8_bytes(out, 0xC2 + ((value >> 6) & 0x1F), 0xC0 + (value & 0x3F));
        }
        if (value <= -1)
        {
            return put_bon8_bytes(out, 0xB8 - (value + 1));
        }
        if (value <= 39)
        {
            return put_bon8_bytes(out, 0x90 + value);
        }
        if (value <= 3879)
        {
            value -= 40;
            return put_bon8_bytes(out, 0xC2 + ((value >> 7) & 0x1F), value & 0x7F);
        }
        if (value <= 528167)
        {
            value -= 3880;
            return put_bon8_bytes(out, 0xE0 + ((value >> 15) & 0x0F), (value >> 8) & 0x7F, value);
        }
        value -= 528168;
        return put_bon8_bytes(out, 0xF0 + ((value >> 23) & 0x07), (value >> 16) & 0x7F, value >> 8, value);
    }

    /// store the low byte of each argument at @a out; return the end
    template<typename... Bytes>
    CharType* put_bon8_bytes(CharType* out, const Bytes... bytes) const noexcept
    {
        const std::array<CharType, sizeof...(Bytes)> buffer{{to_char_type(static_cast<std::uint8_t>(bytes & 0xFF))...}};
        std::memcpy(out, buffer.data(), buffer.size());
        return out + buffer.size();
    }

    /*!
    @brief encode a float as @ref write_bon8_float writes it
    @param[in] out  where the encoding goes; at most 9 characters are written
    @return the end of the encoding
    */
    CharType* encode_bon8_float(CharType* out, const number_float_t n) const noexcept
    {
#ifdef __GNUC__
        JSON_HEDLEY_DIAGNOSTIC_PUSH
        JSON_HEDLEY_PRAGMA(GCC diagnostic ignored "-Wfloat-equal")
#endif
        if (n == static_cast<number_float_t>(-1))
        {
            *out++ = to_char_type(0xFB);
            return out;
        }
        if (n == static_cast<number_float_t>(0) && !std::signbit(n))
        {
            *out++ = to_char_type(0xFC);
            return out;
        }
        if (n == static_cast<number_float_t>(1))
        {
            *out++ = to_char_type(0xFD);
            return out;
        }
        if (std::isnan(n))
        {
            return put_bon8_bytes(out, 0x8E, 0x7F, 0x80, 0x00, 0x01);
        }
        return out + encode_compact_float(out, n, to_char_type(0x8E), to_char_type(0x8F));
#ifdef __GNUC__
        JSON_HEDLEY_DIAGNOSTIC_POP
#endif
    }

    /*!
    @brief write the elements of an array that starts with a number, with runs
           of numbers encoded without a call of @ref write_bon8_value for each

    Same output as calling write_bon8_value for each element. The numbers of a
    run are encoded into space reserved from the sink, as in
    @ref write_array_elements; an integer that BON8 cannot write (an unsigned
    one above the int64 range, or one of a number type wider than 64 bits) throws
    from write_bon8_value, like any other value that is not a number. Kept out
    of line, like @ref write_cbor_array.
    */
    template<typename ArrayType>
    JSON_HEDLEY_NEVER_INLINE
    void write_bon8_array_elements(const ArrayType& array, bool& string_open, const std::size_t depth)
    {
        constexpr std::size_t max_run = max_reserve_size / 9;
        auto it = array.begin();
        const auto end = array.end();
        while (it != end)
        {
            if (!it->is_number())
            {
                write_bon8_value(*it, string_open, depth + 1);
                ++it;
                continue;
            }

            CharType* const start = oa.reserve(max_run * 9);
            CharType* out = start;
            bool unencodable = false;
            for (std::size_t n = 0; n < max_run && it != end && it->is_number(); ++n)
            {
                if (it->is_number_float())
                {
                    out = encode_bon8_float(out, it->m_data.m_value.number_float);
                }
                else if (JSON_HEDLEY_UNLIKELY((it->m_data.m_type == value_t::number_unsigned
                                               && !integer_fits_max<std::int64_t>(it->m_data.m_value.number_unsigned))
                                              || (it->m_data.m_type == value_t::number_integer
                                                  && !integer_fits<std::int64_t>(it->m_data.m_value.number_integer))))
                {
                    unencodable = true;
                    break;
                }
                else
                {
                    out = encode_bon8_integer(out, it->m_data.m_type == value_t::number_integer
                                              ? static_cast<std::int64_t>(it->m_data.m_value.number_integer)
                                              : static_cast<std::int64_t>(it->m_data.m_value.number_unsigned));
                }
                ++it;
            }
            oa.commit(static_cast<std::size_t>(out - start));
            if (out != start)
            {
                // a number follows a string without terminating it
                string_open = false;
            }

            if (unencodable)
            {
                write_bon8_value(*it, string_open, depth + 1);
                ++it;
            }
        }
    }

    /*!
    @brief write the members of the object @a j as BON8

    A member whose value is null, a boolean, a number, or a string is written
    without a call of @ref write_bon8_value. Kept out of line, like
    @ref write_cbor_object.
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_bon8_members(const BasicJsonType& j, bool& string_open, const std::size_t depth)
    {
        for (const auto& el : *j.m_data.m_value.object)
        {
            write_bon8_string(el.first, string_open, j);

            const BasicJsonType& value = el.second;
            switch (value.type())
            {
                case value_t::null:
                    write_bon8_marker(0xFA, string_open);
                    break;

                case value_t::boolean:
                    write_bon8_marker(value.m_data.m_value.boolean ? 0xF9 : 0xF8, string_open);
                    break;

                case value_t::string:
                    write_bon8_string(*value.m_data.m_value.string, string_open, value);
                    break;

                case value_t::number_integer:
                    if (JSON_HEDLEY_LIKELY(integer_fits<std::int64_t>(value.m_data.m_value.number_integer)))
                    {
                        write_bon8_integer(static_cast<std::int64_t>(value.m_data.m_value.number_integer));
                        string_open = false;
                        break;
                    }
                    // beyond 64 bits (number types wider than that): throws
                    write_bon8_value(value, string_open, depth + 1);
                    break;

                case value_t::number_float:
                    write_bon8_float(value.m_data.m_value.number_float);
                    string_open = false;
                    break;

                case value_t::number_unsigned:
                    if (JSON_HEDLEY_LIKELY(integer_fits_max<std::int64_t>(value.m_data.m_value.number_unsigned)))
                    {
                        write_bon8_integer(static_cast<std::int64_t>(value.m_data.m_value.number_unsigned));
                        string_open = false;
                        break;
                    }
                    // too large for BON8: throws
                    write_bon8_value(value, string_open, depth + 1);
                    break;

                case value_t::object:
                case value_t::array:
                case value_t::binary:
                case value_t::discarded:
                default:
                    write_bon8_value(value, string_open, depth + 1);
                    break;
            }
        }
    }

    /*!
    @brief write a binary value as BON8

    BON8 has no binary type: the bytes are written as an array of integers,
    like UBJSON and BJData do. Kept out of line, so that write_bon8_value does
    not carry the registers of its loop.
    */
    JSON_HEDLEY_NEVER_INLINE
    void write_bon8_binary(const binary_t& binary, bool& string_open)
    {
        const auto N = binary.size();
        write_bon8_marker(static_cast<std::uint8_t>(N <= 4 ? 0x80 + N : 0x85), string_open);

        // a byte is an integer of 0 to 255: one byte up to 39, two bytes above
        const auto* const data = binary.data();
        for (std::size_t i = 0; i < N;)
        {
            const std::size_t block = (std::min)(N - i, max_reserve_size / 2);
            CharType* const start = oa.reserve(2 * block);
            CharType* out = start;
            for (std::size_t k = 0; k < block; ++k, ++i)
            {
                // the cast is needed for binary types whose value type
                // is not an integer (e.g., std::byte)
                const auto value = static_cast<unsigned>(static_cast<std::uint8_t>(data[i]));
                // both bytes are stored, the second only counts for a value above 39:
                // 0xC2 + ((value - 40) >> 7), (value - 40) & 0x7F
                const unsigned wide = value - 40u;
                const bool is_wide = value > 39u;
                out[0] = to_char_type(static_cast<std::uint8_t>(is_wide ? 0xC2u + (wide >> 7u) : 0x90u + value));
                out[1] = to_char_type(static_cast<std::uint8_t>(wide & 0x7Fu));
                out += is_wide ? 2 : 1;
            }
            oa.commit(static_cast<std::size_t>(out - start));
        }

        if (N > 4)
        {
            write_bon8_marker(0xFE, string_open);
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
            write_bytes(s.data(), s.size());
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
        const auto* data = reinterpret_cast<const unsigned char*>(s.data());
        const std::size_t valid = valid_utf8_prefix(data, s.size());
        if (JSON_HEDLEY_UNLIKELY(valid != s.size()))
        {
            throw_invalid_utf8(data, valid, context);
        }
    }

    /// @brief throw type_error.316 for the invalid byte at @a index of @a data;
    ///        out of line, so that the message does not burden check_utf8()
    JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE
    static void throw_invalid_utf8(const unsigned char* data, const std::size_t index, const BasicJsonType& context)
    {
        static_cast<void>(data); // only used when exceptions are enabled
        static_cast<void>(index);
        static_cast<void>(context);
        JSON_THROW(type_error::create(exception_id::invalid_utf8, concat("invalid UTF-8 byte at index ", std::to_string(index), ": 0x", detail::hex_byte(data[index])), &context));
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

    @a s must be an lvalue that outlives the returned reference. An object key
    whose `key_type` is not @ref string_t must therefore first be converted
    into a named string_t (see @ref object_key_string_t); the deleted overload
    below enforces this at compile time.

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
    @brief the write-pass counterpart of @ref sanitize_utf8_for_write for BSON

    The size pass (@ref calc_bson_entry_header_size, @ref
    calc_bson_string_size) has already validated @a s, and thrown for @ref
    error_handler_t::strict if it was ill-formed. Here, @ref
    error_handler_t::strict therefore behaves like @ref error_handler_t::keep,
    and @ref error_handler_t::replace / @ref error_handler_t::ignore produce
    exactly the bytes the size pass measured. Hence no context is needed.

    @param[in] s        the string (value or object key) to write
    @param[out] storage  backing storage for a sanitized copy

    @return a reference to @a s, or to @a storage once it holds a sanitized copy
    */
    const string_t& sanitize_utf8_for_bson_write(const string_t& s, string_t& storage) const
    {
        if (error_handler == error_handler_t::keep || error_handler == error_handler_t::strict || is_valid_utf8(s))
        {
            return s; // NOLINT(bugprone-return-const-ref-from-parameter): callers pass lvalues that outlive the call
        }
        storage = sanitize_utf8(s, error_handler);
        return storage;
    }

    /// deleted: anything but a string_t would bind a temporary that dies before the returned reference is used
    template < typename T, enable_if_t < !std::is_same<T, string_t>::value, int > = 0 >
    const string_t& sanitize_utf8_for_write(const T& /*s*/, const BasicJsonType& /*context*/, string_t& /*storage*/) const = delete; // NOLINT(hicpp-use-equals-delete,modernize-use-equals-delete): a private helper's guard, not part of the interface

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

    /*!
    @brief reverse the bytes of a buffer by byte-swapping it as UIntType

    Loading the buffer into an unsigned integer of the same width and swapping
    that is what lets the compiler emit a single bswap/rev/movbe; reversing the
    buffer element by element does not reliably get there (clang keeps a scalar
    shuffle). (The two memcpy calls, rather than bit_cast, keep GCC from
    inlining differently in C++20, which made writing slower.)
    */
    template<typename UIntType, std::size_t N>
    static void byte_swap_buffer(std::array<CharType, N>& a) noexcept
    {
        static_assert(sizeof(UIntType) == N, "swap width must match the buffer size");
        UIntType v{};
        std::memcpy(&v, a.data(), sizeof(v));
        v = byteswap(v);
        std::memcpy(a.data(), &v, sizeof(v));
    }

    // reverse the bytes of a fixed-size buffer; a single byteswap() for the
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

    /// whether @a n is written as a float32 by @ref write_compact_float
    static bool fits_float32(const number_float_t n) noexcept
    {
        static_assert(std::is_same<number_float_t, float>::value || std::is_same<number_float_t, double>::value,
                      "number_float_t must be float or double for the CBOR/MessagePack/BON8 writer");
#ifdef __GNUC__
        JSON_HEDLEY_DIAGNOSTIC_PUSH
        JSON_HEDLEY_PRAGMA(GCC diagnostic ignored "-Wfloat-equal")
#endif
#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 7)
        JSON_HEDLEY_PRAGMA(GCC diagnostic ignored "-Wduplicated-branches")
#endif
        return !std::isfinite(n) || ((static_cast<double>(n) >= static_cast<double>(std::numeric_limits<float>::lowest()) &&
                                      static_cast<double>(n) <= static_cast<double>((std::numeric_limits<float>::max)()) &&
                                      static_cast<double>(static_cast<float>(n)) == static_cast<double>(n)));
#ifdef __GNUC__
        JSON_HEDLEY_DIAGNOSTIC_POP
#endif
    }

    /*!
    @brief encode @a n to @a out as @ref write_compact_float writes it
    @return the number of characters, 5 or 9
    */
    std::size_t encode_compact_float(CharType* out, const number_float_t n, const CharType float32_marker, const CharType float64_marker) const noexcept
    {
        if (fits_float32(n))
        {
            *out = float32_marker;
            store_number(out + 1, static_cast<float>(n), false);
            return 1 + sizeof(float);
        }
        *out = float64_marker;
        store_number(out + 1, n, false);
        return 1 + sizeof(number_float_t);
    }

    /*!
    @brief encode a float as @ref write_cbor writes it
    @return the number of characters, 3, 5 or 9
    */
    std::size_t encode_cbor_float(CharType* out, const number_float_t n) const noexcept
    {
        if (JSON_HEDLEY_UNLIKELY(!std::isfinite(n)))
        {
            // NaN is 0xf97e00, Infinity is 0xf97c00, -Infinity is 0xf9fc00
            out[0] = to_char_type(0xF9);
            if (std::isnan(n))
            {
                out[1] = to_char_type(0x7E);
            }
            else
            {
                out[1] = n > 0 ? to_char_type(0x7C) : to_char_type(0xFC);
            }
            out[2] = to_char_type(0x00);
            return 3;
        }
        return encode_compact_float(out, n, to_char_type(0xFA), to_char_type(0xFB));
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
        if (fits_float32(n))
        {
            oa.write_character(float32_marker);
            write_number(static_cast<float>(n));
        }
        else
        {
            oa.write_character(float64_marker);
            write_number(n);
        }
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
        return bit_cast<CharType>(x);
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
