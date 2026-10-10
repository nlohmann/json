//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cmath> // ldexp
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t, uintmax_t
#include <cstdio> // snprintf
#include <cstring> // memcpy
#include <iterator> // back_inserter
#include <limits> // numeric_limits
#include <string> // char_traits, string
#include <utility> // make_pair, move
#include <vector> // vector
#ifdef __cpp_lib_byteswap
    #include <bit>  //byteswap
#endif

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/input/input_adapters.hpp>
#include <nlohmann/detail/input/json_sax.hpp>
#include <nlohmann/detail/input/lexer.hpp>
#include <nlohmann/detail/input/string_scan.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/is_sax.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>
#include <nlohmann/detail/output/error_handler.hpp>
#include <nlohmann/detail/string_concat.hpp>
#include <nlohmann/detail/string_utils.hpp>
#include <nlohmann/detail/value_t.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// how to treat CBOR tags
enum class cbor_tag_handler_t
{
    error,   ///< throw a parse_error exception in case of a tag
    ignore,  ///< ignore tags
    store    ///< store tagged byte strings (for bytes 0xd8..0xdb) as binary values with the tag as subtype; other tagged values are read as if the tag were ignored
};

/*!
@brief determine system byte order

@return true if and only if system's byte order is little endian

@note from https://stackoverflow.com/a/1001328/266378
*/
inline bool little_endianness(int num = 1) noexcept
{
    return *reinterpret_cast<char*>(&num) == 1;
}

/*!
@brief largest element count accepted for a UBJSON container of a valueless type

An element of type 'Z' (null), 'T' (true) or 'F' (false) is encoded by its
type marker alone, so an optimized container of one of those types has no
payload at all and its declared count is the only thing that decides how much
is allocated: `[$Z#L` followed by a large count turns some ten bytes of input
into that many values (see #2793, which reports 35 GB and 150 seconds). Every
other type costs at least one byte per element and is bounded by the end of
the input.

This is a sanity bound rather than a security boundary, and it is far above
any container met in practice. @ref binary_writer falls back to the
unoptimized encoding for longer containers, so that a value serialized by
this library can always be read back.

@sa https://github.com/nlohmann/json/issues/2793
*/
JSON_INLINE_VARIABLE constexpr std::size_t max_valueless_container_size = 1 << 20;

///////////////////
// binary reader //
///////////////////

/*!
@brief deserialization of BJData, BON8, BSON, CBOR, MessagePack, and UBJSON values
*/
template<typename BasicJsonType, typename InputAdapterType, typename SAX = json_sax_dom_parser<BasicJsonType, InputAdapterType>>
class binary_reader
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;
    using json_sax_t = SAX;
    using char_type = typename InputAdapterType::char_type;
    using char_int_type = typename char_traits<char_type>::int_type;

    /// whether the input is a contiguous block of bytes that can be inspected
    /// and consumed in bulk (as in the lexer); used by @ref get_bon8_string_bulk
    static constexpr bool bulk_scan =
        input_adapter_supports_bulk_scan<InputAdapterType>(is_detected<detect_supports_bulk_scan, InputAdapterType> {});

  public:
    /*!
    @brief create a binary reader

    @param[in] adapter  input adapter to read from
    @param[in] format   the binary format to parse
    @param[in] error_handler_  how to treat text strings and object keys that
               are not well-formed UTF-8; none of the supported formats
               requires a decoder to reject those, so the default is to
               @ref error_handler_t::keep them unchanged, as every binary
               reader did before this parameter existed
    */
    explicit binary_reader(InputAdapterType&& adapter, const input_format_t format = input_format_t::json,
                           const error_handler_t error_handler_ = error_handler_t::keep) noexcept
        : ia(std::move(adapter)), input_format(format), error_handler(error_handler_)
    {
        (void)detail::is_sax_static_asserts<SAX, BasicJsonType> {};
    }

    // make class move-only
    binary_reader(const binary_reader&) = delete;
    binary_reader(binary_reader&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    binary_reader& operator=(const binary_reader&) = delete;
    binary_reader& operator=(binary_reader&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    ~binary_reader() = default;

    /*!
    @brief parse in the format the constructor was given

    @param[in] sax_    a SAX event processor
    @param[in] strict  whether to expect the input to be consumed completed
    @param[in] tag_handler  how to treat CBOR tags

    @return whether parsing was successful
    */
    JSON_HEDLEY_NON_NULL(2)
    bool sax_parse(json_sax_t* sax_,
                   const bool strict = true,
                   const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error)
    {
        sax = sax_;
        container_stack.clear();
        bon8_pushback_size = 0;
        bool result = false;

        switch (input_format)
        {
            case input_format_t::bson:
                result = parse_bson_internal();
                break;

            case input_format_t::cbor:
                result = parse_cbor_internal(tag_handler);
                break;

            case input_format_t::msgpack:
                result = parse_msgpack_internal();
                break;

            case input_format_t::ubjson:
            case input_format_t::bjdata:
                result = parse_ubjson_internal();
                break;

            case input_format_t::bon8:
                result = parse_bon8_internal();
                break;

            case input_format_t::json: // LCOV_EXCL_LINE
            default:            // LCOV_EXCL_LINE
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
        }

        // strict mode: next byte must be EOF
        if (result && strict)
        {
            if (input_format == input_format_t::ubjson || input_format == input_format_t::bjdata)
            {
                get_ignore_noop();
            }
            else if (input_format == input_format_t::bon8)
            {
                // a string that ends a container hands back the byte after it
                get_bon8();
            }
            else
            {
                get();
            }

            if (JSON_HEDLEY_UNLIKELY(current != char_traits<char_type>::eof()))
            {
                return sax->parse_error(chars_read, get_token_string(), parse_error::create(110, chars_read,
                                        exception_message(concat("expected end of input; last byte: 0x", get_token_string()), "value"), nullptr));
            }
        }

        return result;
    }

  private:
    ////////////////////////
    // nested containers  //
    ////////////////////////

    /*!
    @brief a container that has been opened and not closed yet

    The binary readers do not call themselves once per nesting level. Like
    @ref parser::sax_parse_internal, which does the same for JSON text, they
    keep the containers they are inside of on a heap-allocated stack, so that
    the native call stack does not grow with the nesting depth of the input
    and a deeply nested value is bounded by memory rather than by the stack
    (see #5104).

    The members are ordered by decreasing alignment, which is the ordering that
    keeps a struct from growing as members are added to it.
    */
    struct container_frame
    {
        container_frame(const std::size_t remaining_, const bool is_object_,
                        const char_int_type type_marker_ = 0) noexcept
            : remaining(remaining_), type_marker(type_marker_), is_object(is_object_) {}

        /// number of elements that have not been read yet, or npos when the
        /// container is not sized and ends at a marker instead
        std::size_t remaining;
        /// BSON: value of chars_read before this document's size prefix, which
        /// check_bson_document_size() needs once the document has been read
        std::size_t start_position = 0;
        /// UBJSON/BJData: the type marker of an optimized container, so that
        /// its elements are read without one of their own; 0 otherwise
        char_int_type type_marker;
        /// BSON: the size this document declares, in bytes
        std::int32_t declared_size = 0;
        /// whether to close this container with end_object() or end_array()
        bool is_object;
    };

    /*!
    @brief open a nested array or object

    Emits the SAX start event and records the container. This is the only
    place the binary readers start a container, so a check that rejects one
    can be made here and is then guaranteed to run before the start event.

    @param[in] is_object  whether an object (true) or an array (false) begins
    @param[in] len        number of elements the container declares

    @return whether the SAX parser accepted the start event
    */
    bool enter_container(const bool is_object, const std::size_t len,
                         const char_int_type type_marker = 0)
    {
        if (JSON_HEDLEY_UNLIKELY(is_object ? !sax->start_object(len) : !sax->start_array(len)))
        {
            return false;
        }

        container_stack.emplace_back(len, is_object, type_marker);
        return true;
    }

    /// @copydoc enter_container
    bool enter_array(const std::size_t len, const char_int_type type_marker = 0)
    {
        return enter_container(/*is_object*/false, len, type_marker);
    }

    /// @copydoc enter_container
    bool enter_object(const std::size_t len, const char_int_type type_marker = 0)
    {
        return enter_container(/*is_object*/true, len, type_marker);
    }

    /*!
    @brief close the innermost open array or object

    Pops the container opened by the matching @ref enter_container call and
    emits the SAX end event. Every format-specific driver otherwise repeated
    the same pop-then-dispatch sequence at its own close site.

    @return whether the SAX parser accepted the end event
    */
    bool leave_container()
    {
        const bool is_object = container_stack.back().is_object;
        container_stack.pop_back();
        return is_object ? sax->end_object() : sax->end_array();
    }

    //////////
    // BSON //
    //////////

    /*!
    @brief Validate a BSON document's declared size against the bytes read.

    A BSON document starts with an int32 that counts its own total length in
    bytes, including that prefix and the trailing 0x00. The reader is driven
    by the terminator rather than the declared length, so without this check a
    nested document could declare a length that disagrees with where its
    terminator actually falls and quietly hand the bytes in between to the
    enclosing document. A well-formed document is at least 5 bytes (the prefix
    plus the terminator); the equality also rejects those impossible sizes,
    since at least 5 bytes are always consumed.

    @param[in] document_start  value of chars_read before the size prefix
    @param[in] document_size   the declared document size
    @return whether the declared size matches the number of bytes read
    */
    bool check_bson_document_size(const std::size_t document_start, const std::int32_t document_size)
    {
        if (JSON_HEDLEY_UNLIKELY(document_size < 0 || static_cast<std::size_t>(document_size) != chars_read - document_start))
        {
            return sax->parse_error(chars_read, get_token_string(), parse_error::create(112, chars_read,
                                    exception_message(concat("document size ", std::to_string(document_size), " does not match the number of bytes read (", std::to_string(chars_read - document_start), ")"), "document"), nullptr));
        }
        return true;
    }

    /*!
    @brief Reads in a BSON-object and passes it to the SAX-parser.
    @return whether a valid BSON-value was passed to the SAX parser
    */
    bool open_bson_document(const bool is_object)
    {
        // recorded before the size prefix is read, because
        // check_bson_document_size() measures the document from here
        const std::size_t document_start = chars_read;
        std::int32_t document_size{};
        if (!get_number<std::int32_t, true>(document_size))
        {
            return false;
        }

        if (JSON_HEDLEY_UNLIKELY(!enter_container(is_object, detail::unknown_size())))
        {
            return false;
        }

        container_frame& frame = container_stack.back();
        frame.start_position = document_start;
        frame.declared_size = document_size;
        return true;
    }

    /*!
    @brief read a BSON document and everything nested inside it

    Reads elements until the document that was begun here is complete,
    resuming the enclosing document each time an embedded one ends, so that
    the nesting depth of the input costs heap rather than native stack
    (see #5104).

    @return whether reading the document succeeded
    */
    bool parse_bson_internal()
    {
        if (JSON_HEDLEY_UNLIKELY(!open_bson_document(/*is_object*/true)))
        {
            return false;
        }

        // the key currently being read; hoisted out of the loop so that its
        // capacity is reused across elements and across nesting levels
        string_t key;

        while (true)
        {
            const auto element_type = get();

            if (element_type == 0) // end of the innermost document
            {
                // a copy, not a reference: it must stay valid across the
                // pop_back() inside leave_container() below, which destroys
                // the container_stack element it would otherwise alias
                const container_frame top = container_stack.back();

                if (JSON_HEDLEY_UNLIKELY(!check_bson_document_size(top.start_position, top.declared_size)))
                {
                    return false;
                }

                if (JSON_HEDLEY_UNLIKELY(!leave_container()))
                {
                    return false;
                }
                // the document begun here is complete once it is not inside one
                if (container_stack.empty())
                {
                    return true;
                }
                continue;
            }

            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("element list")))
            {
                return false;
            }

            const std::size_t element_type_parse_position = chars_read;
            key.clear();
            if (JSON_HEDLEY_UNLIKELY(!get_bson_cstr(key)))
            {
                return false;
            }

            // an array's elements are named "0", "1", ... in the wire format,
            // and those names are not passed on
            if (container_stack.back().is_object && !sax->key(key))
            {
                return false;
            }

            if (JSON_HEDLEY_UNLIKELY(!parse_bson_element_internal(element_type, element_type_parse_position)))
            {
                return false;
            }
        }
    }

    /*!
    @brief Parses a C-style string from the BSON input.
    @param[in,out] result  A reference to the string variable where the read
                            string is to be stored.
    @return `true` if the \\x00-byte indicating the end of the string was
             encountered before the EOF; false` indicates an unexpected EOF.
    */
    bool get_bson_cstr(string_t& result)
    {
        if (get_bson_cstr_bulk(result, std::integral_constant<bool, bulk_scan> {}))
        {
            return check_string_utf8(result, "key");
        }

        auto out = std::back_inserter(result);
        while (true)
        {
            get();
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("cstring")))
            {
                return false;
            }
            if (current == 0x00)
            {
                return check_string_utf8(result, "key");
            }
            *out++ = static_cast<typename string_t::value_type>(current);
        }
    }

    /*!
    @brief read a C-style string from contiguous input in one step

    @param[in,out] result  the string to append to
    @return whether the string was read; if the input has no \\x00-byte, nothing
            is read, and @ref get_bson_cstr reports the end of the input
    */
    bool get_bson_cstr_bulk(string_t& result, std::true_type /*bulk*/)
    {
        const std::size_t remaining = ia.bulk_remaining();
        if (remaining == 0)
        {
            return false;
        }
        const auto* const data = reinterpret_cast<const unsigned char*>(ia.bulk_data());
        // a plain loop rather than std::memchr: most keys are short (array
        // indices are keys, too), and the call would cost more than it saves
        std::size_t length = 0;
        while (length < remaining && data[length] != 0x00)
        {
            ++length;
        }
        if (length == remaining)
        {
            return false;
        }
        result.append(reinterpret_cast<const typename string_t::value_type*>(data), length);
        // consume the string and its \x00-byte, as the byte-wise path does
        ia.bulk_skip(length + 1);
        chars_read += length + 1;
        current = 0x00;
        return true;
    }

    /// input that is not contiguous: C-style strings are read byte by byte
    bool get_bson_cstr_bulk(string_t& /*result*/, std::false_type /*bulk*/) const noexcept
    {
        return false;
    }

    /*!
    @brief Parses a zero-terminated string of length @a len from the BSON
           input.
    @param[in] len  The length (including the zero-byte at the end) of the
                    string to be read.
    @param[in,out] result  A reference to the string variable where the read
                            string is to be stored.
    @tparam NumberType The type of the length @a len
    @pre len >= 1
    @return `true` if the string was successfully parsed
    */
    template<typename NumberType>
    bool get_bson_string(const NumberType len, string_t& result)
    {
        if (JSON_HEDLEY_UNLIKELY(len < 1))
        {
            auto last_token = get_token_string();
            return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message(concat("string length must be at least 1, is ", std::to_string(len)), "string"), nullptr));
        }

        if (JSON_HEDLEY_UNLIKELY(!get_string(len - static_cast<NumberType>(1), result)))
        {
            return false;
        }

        if (JSON_HEDLEY_UNLIKELY(get() != 0x00))
        {
            auto last_token = get_token_string();
            return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message("BSON string is not null-terminated",
                                            "string"), nullptr));
        }

        return check_string_utf8(result, "string");
    }

    /*!
    @brief Parses a byte array input of length @a len from the BSON input.
    @param[in] len  The length of the byte array to be read.
    @param[in,out] result  A reference to the binary variable where the read
                            array is to be stored.
    @tparam NumberType The type of the length @a len
    @pre len >= 0
    @return `true` if the byte array was successfully parsed
    */
    template<typename NumberType>
    bool get_bson_binary(const NumberType len, binary_t& result)
    {
        if (JSON_HEDLEY_UNLIKELY(len < 0))
        {
            auto last_token = get_token_string();
            return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message(concat("byte array length cannot be negative, is ", std::to_string(len)), "binary"), nullptr));
        }

        // All BSON binary values have a subtype
        std::uint8_t subtype{};
        if (JSON_HEDLEY_UNLIKELY(!get_number<std::uint8_t>(subtype)))
        {
            return false;
        }
        result.set_subtype(subtype);

        return get_binary(len, result);
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
    bool parse_bson_element_internal(const char_int_type element_type,
                                     const std::size_t element_type_parse_position)
    {
        switch (element_type)
        {
            case 0x01: // double
            {
                double number{};
                return get_number<double, true>(number) && emit_float(number);
            }

            case 0x02: // string
            {
                std::int32_t len{};
                string_t value;
                return get_number<std::int32_t, true>(len) && get_bson_string(len, value) && sax->string(value);
            }

            case 0x03: // object
            {
                return open_bson_document(/*is_object*/true);
            }

            case 0x04: // array
            {
                return open_bson_document(/*is_object*/false);
            }

            case 0x05: // binary
            {
                std::int32_t len{};
                binary_t value;
                return get_number<std::int32_t, true>(len) && get_bson_binary(len, value) && sax->binary(value);
            }

            case 0x08: // boolean
            {
                std::uint8_t value{};
                return get_number<std::uint8_t>(value) && sax->boolean(value != 0);
            }

            case 0x0A: // null
            {
                return sax->null();
            }

            case 0x10: // int32
            {
                std::int32_t value{};
                return get_number<std::int32_t, true>(value) && emit_signed(value);
            }

            case 0x12: // int64
            {
                std::int64_t value{};
                return get_number<std::int64_t, true>(value) && emit_signed(value);
            }

            case 0x11: // uint64
            {
                std::uint64_t value{};
                return get_number<std::uint64_t, true>(value) && emit_unsigned(value);
            }

            default: // anything else is not supported (yet)
            {
                std::array<char, 3> cr{{}};
                static_cast<void>((std::snprintf)(cr.data(), cr.size(), "%.2hhX", static_cast<unsigned char>(element_type))); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
                const std::string cr_str{cr.data()};
                return sax->parse_error(element_type_parse_position, cr_str,
                                        parse_error::create(114, element_type_parse_position, concat("Unsupported BSON record type 0x", cr_str), nullptr));
            }
        }
    }

    //////////
    // CBOR //
    //////////

    template<typename NumberType>
    bool get_cbor_negative_integer()
    {
        NumberType number{};
        if (JSON_HEDLEY_UNLIKELY(!get_number(number)))
        {
            return false;
        }

        // the value is -1 - number, which fits into number_integer_t
        // whenever number does; the outer cast undoes the integral promotion
        // for number_integer_t types narrower than int
        if (JSON_HEDLEY_LIKELY(value_in_range_of<number_integer_t>(number)))
        {
            return sax->number_integer(conditional_static_cast<number_integer_t>(static_cast<number_integer_t>(-1) - static_cast<number_integer_t>(number)));
        }

        // like the lexer does for JSON text, store a value too small for
        // number_integer_t as number_float_t; compute it as long double so
        // that emit_float sees a finite value and can detect an overflow of
        // number_float_t
        return emit_float(static_cast<long double>(-1) - static_cast<long double>(number));
    }

    /*!
    @param[in] get_char  whether a new character should be retrieved from the
                         input (true) or whether the last read character should
                         be considered instead (false)
    @param[in] tag_handler how CBOR tags should be treated
    @param[out] tag_pending whether a tag was parsed and its value follows
    @param[out] item_read whether the tagged value's initial byte is already in current

    @return whether a valid CBOR value was passed to the SAX parser
    */
    bool parse_cbor_value(const bool get_char,
                          const cbor_tag_handler_t tag_handler,
                          bool& tag_pending,
                          bool& item_read)
    {
        tag_pending = false;
        item_read = false;

        switch (get_char ? get() : current)
        {
            // EOF
            case char_traits<char_type>::eof():
                return unexpect_eof("value");

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
                std::uint8_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 0x19: // Unsigned integer (two-byte uint16_t follows)
            {
                std::uint16_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 0x1A: // Unsigned integer (four-byte uint32_t follows)
            {
                std::uint32_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 0x1B: // Unsigned integer (eight-byte uint64_t follows)
            {
                std::uint64_t number{};
                return get_number(number) && emit_unsigned(number);
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
                return get_cbor_negative_integer<std::uint8_t>();

            case 0x39: // Negative integer -1-n (two-byte uint16_t follows)
                return get_cbor_negative_integer<std::uint16_t>();

            case 0x3A: // Negative integer -1-n (four-byte uint32_t follows)
                return get_cbor_negative_integer<std::uint32_t>();

            case 0x3B: // Negative integer -1-n (eight-byte uint64_t follows)
                return get_cbor_negative_integer<std::uint64_t>();

            // Binary data (0x00..0x17 bytes follow)
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
            case 0x58: // Binary data (one-byte uint8_t for n follows)
            case 0x59: // Binary data (two-byte uint16_t for n follow)
            case 0x5A: // Binary data (four-byte uint32_t for n follow)
            case 0x5B: // Binary data (eight-byte uint64_t for n follow)
            case 0x5F: // Binary data (indefinite length)
            {
                binary_t b;
                return get_cbor_binary(b) && sax->binary(b);
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
                return get_cbor_string(s) && sax->string(s);
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
                return enter_array(conditional_static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x1Fu));

            case 0x98: // array (one-byte uint8_t for n follows)
            case 0x99: // array (two-byte uint16_t for n follow)
            case 0x9A: // array (four-byte uint32_t for n follow)
            case 0x9B: // array (eight-byte uint64_t for n follow)
            {
                std::uint64_t len{};
                std::size_t size{};
                return get_cbor_argument(len) && get_cbor_container_size(len, size, "array") && enter_array(size);
            }

            case 0x9F: // array (indefinite length)
                return enter_array(detail::unknown_size());

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
                return enter_object(conditional_static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x1Fu));

            case 0xB8: // map (one-byte uint8_t for n follows)
            case 0xB9: // map (two-byte uint16_t for n follow)
            case 0xBA: // map (four-byte uint32_t for n follow)
            case 0xBB: // map (eight-byte uint64_t for n follow)
            {
                std::uint64_t len{};
                std::size_t size{};
                return get_cbor_argument(len) && get_cbor_container_size(len, size, "map") && enter_object(size);
            }

            case 0xBF: // map (indefinite length)
                return enter_object(detail::unknown_size());

            case 0xC0: // tagged item (tag value 0-23, in the head itself)
            case 0xC1:
            case 0xC2:
            case 0xC3:
            case 0xC4:
            case 0xC5:
            case 0xC6:
            case 0xC7:
            case 0xC8:
            case 0xC9:
            case 0xCA:
            case 0xCB:
            case 0xCC:
            case 0xCD:
            case 0xCE:
            case 0xCF:
            case 0xD0:
            case 0xD1:
            case 0xD2:
            case 0xD3:
            case 0xD4:
            case 0xD5:
            case 0xD6:
            case 0xD7:
            {
                if (tag_handler == cbor_tag_handler_t::error)
                {
                    auto last_token = get_token_string();
                    return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                            exception_message(concat("invalid byte: 0x", last_token), "value"), nullptr));
                }

                // ignore and store: the tag value is already in the head, so
                // there is nothing left to read here; the tagged value that
                // follows is read by the loop in parse_cbor_internal() rather
                // than by recursing here
                tag_pending = true;
                return true;
            }

            case 0xD8: // tagged item (1 byte follows)
            case 0xD9: // tagged item (2 bytes follow)
            case 0xDA: // tagged item (4 bytes follow)
            case 0xDB: // tagged item (8 bytes follow)
            {
                switch (tag_handler)
                {
                    case cbor_tag_handler_t::error:
                    {
                        auto last_token = get_token_string();
                        return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                                exception_message(concat("invalid byte: 0x", last_token), "value"), nullptr));
                    }

                    case cbor_tag_handler_t::ignore:
                    {
                        // ignore the tag's binary subtype argument
                        std::uint64_t subtype_to_ignore{};
                        if (!get_cbor_argument(subtype_to_ignore))
                        {
                            return false;
                        }
                        // the tagged value follows; it is read by the loop in
                        // parse_cbor_internal() rather than by recursing here
                        tag_pending = true;
                        return true;
                    }

                    case cbor_tag_handler_t::store:
                    {
                        // use binary subtype and store in a binary container
                        std::uint64_t subtype{};
                        if (!get_cbor_argument(subtype))
                        {
                            return false;
                        }
                        binary_t b;
                        b.set_subtype(detail::conditional_static_cast<typename binary_t::subtype_type>(subtype));

                        get();
                        // a byte string (the heads accepted by get_cbor_binary) keeps the tag as subtype
                        if ((current >= 0x40 && current <= 0x5B) || current == 0x5F)
                        {
                            return get_cbor_binary(b) && sax->binary(b);
                        }

                        // not a byte string: the tagged value, whose first byte
                        // was just read, is read by the caller like for ignore
                        tag_pending = true;
                        item_read = true;
                        return true;
                    }

                    default:                 // LCOV_EXCL_LINE
                        JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
                        return false;        // LCOV_EXCL_LINE
                }
            }

            case 0xF4: // false
                return sax->boolean(false);

            case 0xF5: // true
                return sax->boolean(true);

            case 0xF6: // null
                return sax->null();

            case 0xF9: // Half-Precision Float (two-byte IEEE 754)
                return get_half_float(false);

            case 0xFA: // Single-Precision Float (four-byte IEEE 754)
            {
                float number{};
                return get_number(number) && emit_float(number);
            }

            case 0xFB: // Double-Precision Float (eight-byte IEEE 754)
            {
                double number{};
                return get_number(number) && emit_float(number);
            }

            default: // anything else (0xFF is handled inside the other types)
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                        exception_message(concat("invalid byte: 0x", last_token), "value"), nullptr));
            }
        }
    }

    /*!
    @brief reports a nested indefinite-length CBOR string or byte array
    @param[in] type_name  name of the rejected string type
    @param[in] context  parsing context for the error message
    @return whether the SAX consumer accepts the parse error
    */
    bool cbor_indefinite_string_error(const char* type_name, const char* context)
    {
        auto last_token = get_token_string();
        return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                exception_message(concat("indefinite-length ", type_name,
                                        " is not allowed inside indefinite-length ", type_name, "; last byte: 0x", last_token), context), nullptr));
    }

    /*!
    @brief reads a definite-length CBOR string

    Reads everything @ref get_cbor_string accepts except the indefinite-length
    form, which that function handles itself. The bytes are appended to @a
    result, so consecutive chunks of an indefinite-length string can be read
    into the same string.

    @param[out] result  string the bytes are appended to
    @param[in] inside_indefinite  whether the bytes belong to an indefinite-length string

    @return whether string creation completed

    @pre @a current is not EOF
    */
    bool get_cbor_string_chunk(string_t& result, const bool inside_indefinite)
    {
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
                return get_string(static_cast<unsigned int>(current) & 0x1Fu, result);
            }

            case 0x78: // UTF-8 string (one-byte uint8_t for n follows)
            {
                std::uint8_t len{};
                return get_number(len) && get_string(len, result);
            }

            case 0x79: // UTF-8 string (two-byte uint16_t for n follow)
            {
                std::uint16_t len{};
                return get_number(len) && get_string(len, result);
            }

            case 0x7A: // UTF-8 string (four-byte uint32_t for n follow)
            {
                std::uint32_t len{};
                return get_number(len) && get_string(len, result);
            }

            case 0x7B: // UTF-8 string (eight-byte uint64_t for n follow)
            {
                std::uint64_t len{};
                return get_number(len) && get_string(len, result);
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                        exception_message(concat("expected length specification (0x60-0x7B)", inside_indefinite ? "" : " or indefinite string type (0x7F)", "; last byte: 0x", last_token), "string"), nullptr));
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
    bool get_cbor_string(string_t& result, const char* context = "string")
    {
        // read chunks iteratively, but reject a second indefinite-length
        // level as required by RFC 8949, Section 3.2.3
        bool indefinite = false;

        while (true)
        {
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("string")))
            {
                return false;
            }

            if (current == 0x7F) // UTF-8 string (indefinite length)
            {
                if (JSON_HEDLEY_UNLIKELY(indefinite))
                {
                    return cbor_indefinite_string_error("string", "string");
                }
                indefinite = true;
                get();
                continue;
            }

            // a break marker closes the indefinite-length string; outside
            // of one it falls through to the error below
            if (indefinite && current == 0xFF)
            {
                return check_string_utf8(result, context);
            }

            if (JSON_HEDLEY_UNLIKELY(!get_cbor_string_chunk(result, indefinite)))
            {
                return false;
            }

            if (!indefinite)
            {
                return check_string_utf8(result, context);
            }

            get();
        }
    }

    /*!
    @brief reads a CBOR object key

    RFC 8949 allows any data item as a map key, but only strings have a
    counterpart in JSON. A key of any other type is rejected with a message
    naming that type, rather than the one @ref get_cbor_string gives for a
    malformed string.

    @param[out] result  created key

    @return whether key creation completed
    */
    bool get_cbor_object_key(string_t& result)
    {
        // EOF and major type 3 (text string) are left to get_cbor_string
        if (current == char_traits<char_type>::eof() || (static_cast<unsigned int>(current) & 0xE0u) == 0x60u)
        {
            return get_cbor_string(result, "key");
        }

        const char* found = nullptr;
        switch (static_cast<unsigned int>(current) >> 5u)
        {
            case 0:
                found = "an unsigned integer";
                break;
            case 1:
                found = "a negative integer";
                break;
            case 2:
                found = "a byte string";
                break;
            case 4:
                found = "an array";
                break;
            case 5:
                found = "a map";
                break;
            case 6:
                found = "a tag";
                break;
            default: // major type 7
                switch (current)
                {
                    case 0xF4:
                    case 0xF5:
                        found = "a boolean";
                        break;
                    case 0xF6:
                        found = "null";
                        break;
                    case 0xF7:
                        found = "undefined";
                        break;
                    case 0xF9:
                    case 0xFA:
                    case 0xFB:
                        found = "a floating-point number";
                        break;
                    case 0xFF:
                        found = "a break stop code";
                        break;
                    default:
                        found = "a simple value";
                        break;
                }
                break;
        }

        auto last_token = get_token_string();
        return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                exception_message(concat("only string keys are supported, but found ", found, "; last byte: 0x", last_token), "object key"), nullptr));
    }

    /*!
    @brief reads a definite-length CBOR byte array

    Reads everything @ref get_cbor_binary accepts except the indefinite-length
    form, which that function handles itself. The bytes are appended to @a
    result, so consecutive chunks of an indefinite-length byte array can be
    read into the same byte array.

    @param[out] result  byte array the bytes are appended to
    @param[in] inside_indefinite  whether the bytes belong to an indefinite-length string

    @return whether byte array creation completed

    @pre @a current is not EOF
    */
    bool get_cbor_binary_chunk(binary_t& result, const bool inside_indefinite)
    {
        switch (current)
        {
            // Binary data (0x00..0x17 bytes follow)
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
            {
                return get_binary(static_cast<unsigned int>(current) & 0x1Fu, result);
            }

            case 0x58: // Binary data (one-byte uint8_t for n follows)
            {
                std::uint8_t len{};
                return get_number(len) &&
                       get_binary(len, result);
            }

            case 0x59: // Binary data (two-byte uint16_t for n follow)
            {
                std::uint16_t len{};
                return get_number(len) &&
                       get_binary(len, result);
            }

            case 0x5A: // Binary data (four-byte uint32_t for n follow)
            {
                std::uint32_t len{};
                return get_number(len) &&
                       get_binary(len, result);
            }

            case 0x5B: // Binary data (eight-byte uint64_t for n follow)
            {
                std::uint64_t len{};
                return get_number(len) &&
                       get_binary(len, result);
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                        exception_message(concat("expected length specification (0x40-0x5B)", inside_indefinite ? "" : " or indefinite binary array type (0x5F)", "; last byte: 0x", last_token), "binary"), nullptr));
            }
        }
    }

    /*!
    @brief reads a CBOR byte array

    This function first reads starting bytes to determine the expected
    byte array length and then copies this number of bytes into the byte array.
    Additionally, CBOR's byte arrays with indefinite lengths are supported.

    @param[out] result  created byte array

    @return whether byte array creation completed
    */
    bool get_cbor_binary(binary_t& result)
    {
        // read chunks iteratively, but reject a second indefinite-length
        // level as required by RFC 8949, Section 3.2.3
        bool indefinite = false;

        while (true)
        {
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("binary")))
            {
                return false;
            }

            if (current == 0x5F) // Binary data (indefinite length)
            {
                if (JSON_HEDLEY_UNLIKELY(indefinite))
                {
                    return cbor_indefinite_string_error("binary array", "binary");
                }
                indefinite = true;
                get();
                continue;
            }

            // a break marker closes the indefinite-length string; outside
            // of one it falls through to the error below
            if (indefinite && current == 0xFF)
            {
                return true;
            }

            if (JSON_HEDLEY_UNLIKELY(!get_cbor_binary_chunk(result, indefinite)))
            {
                return false;
            }

            if (!indefinite)
            {
                return true;
            }

            get();
        }
    }

    /*!
    @brief read a CBOR argument (additional information 24-27) of the width
           @ref current announces

    The lower 5 bits of @a current (0x18-0x1B) select a 1/2/4/8-byte
    big-endian unsigned integer that follows the head byte; this is shared by
    every major type that uses this encoding (unsigned/negative integers,
    strings, arrays, maps, tags). Reading always goes through @ref get_number,
    so EOF is reported the same way as before this helper existed.

    @param[out] value  the decoded argument
    @return whether reading succeeded
    */
    bool get_cbor_argument(std::uint64_t& value)
    {
        switch (current & 0x1F)
        {
            case 0x18: // 1 byte
            {
                std::uint8_t n{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(n)))
                {
                    return false;
                }
                value = n;
                return true;
            }

            case 0x19: // 2 bytes
            {
                std::uint16_t n{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(n)))
                {
                    return false;
                }
                value = n;
                return true;
            }

            case 0x1A: // 4 bytes
            {
                std::uint32_t n{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(n)))
                {
                    return false;
                }
                value = n;
                return true;
            }

            case 0x1B: // 8 bytes
            {
                std::uint64_t n{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(n)))
                {
                    return false;
                }
                value = n;
                return true;
            }

            default:                 // LCOV_EXCL_LINE
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
                return false;        // LCOV_EXCL_LINE
        }
    }

    /*!
    @brief narrow a definite CBOR array/map length to std::size_t

    A definite length is rejected if it does not fit in std::size_t or if it
    equals detail::unknown_size(), which is reserved to mark an indefinite-
    length container and would otherwise make the length read as indefinite.
    Both cases exceed any container's max_size(), so no representable input
    is affected.

    @param[in]  len      the declared length
    @param[out] result   the length narrowed to std::size_t
    @param[in]  context  "array" or "map", for the error message
    @return whether the length is usable
    */
    bool get_cbor_container_size(const std::uint64_t len, std::size_t& result, const char* context)
    {
        if (JSON_HEDLEY_UNLIKELY(!value_in_range_of<std::size_t>(len) || len == detail::unknown_size()))
        {
            return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408,
                                    exception_message(concat("excessive ", context, " size"), "size"), nullptr));
        }
        result = conditional_static_cast<std::size_t>(len);
        return true;
    }

    /*!
    @brief read a CBOR value and everything nested inside it

    Reads values until the one that was begun here is complete, resuming the
    enclosing container after each element, so that the nesting depth of the
    input costs heap rather than native stack (see #5104).

    @param[in] tag_handler how CBOR tags should be treated

    @return whether reading the value succeeded
    */
    bool parse_cbor_internal(const cbor_tag_handler_t tag_handler)
    {
        // whether the next value starts at a fresh byte or at the one already
        // read into `current`
        bool fetch = true;

        // the key currently being read; hoisted out of the loop so that its
        // capacity is reused across elements and across nesting levels
        string_t key;

        while (true)
        {
            if (!container_stack.empty())
            {
                // a copy, not a reference: it must stay valid across the
                // pop_back() below, which destroys the container_stack element
                // it would otherwise alias
                const container_frame top = container_stack.back();
                bool at_end = false;

                if (top.remaining != npos)
                {
                    // definite length: the container ends once its elements
                    // have been read
                    at_end = (top.remaining == 0);
                    if (!at_end)
                    {
                        // claim the element about to be read
                        --container_stack.back().remaining;
                        if (top.is_object)
                        {
                            get();
                        }
                    }
                    fetch = true;
                }
                else
                {
                    // indefinite length: the container ends at a break marker.
                    // Testing for it consumes a byte, which is the first byte
                    // of the next element when it is not one.
                    at_end = (get() == 0xFF);
                    fetch = top.is_object;
                }

                if (at_end)
                {
                    if (JSON_HEDLEY_UNLIKELY(!leave_container()))
                    {
                        return false;
                    }
                    // the value begun here is complete once its container is
                    if (container_stack.empty())
                    {
                        return true;
                    }
                    continue;
                }

                if (top.is_object)
                {
                    key.clear();
                    if (JSON_HEDLEY_UNLIKELY(!get_cbor_object_key(key) || !sax->key(key)))
                    {
                        return false;
                    }
                    fetch = true;
                }
            }

            // a tag is not a value of its own: read on until the tagged value
            bool tag_pending = false;
            bool item_read = false;
            do
            {
                if (JSON_HEDLEY_UNLIKELY(!parse_cbor_value(fetch, tag_handler, tag_pending, item_read)))
                {
                    return false;
                }
                fetch = !item_read;
            }
            while (tag_pending);

            // a value that opened a container left it on the stack; one that
            // did not, and that was not inside a container, was the whole value
            if (container_stack.empty())
            {
                return true;
            }
        }
    }

    /////////////
    // MsgPack //
    /////////////

    /*!
    @brief read one MessagePack value

    Reads a single value and passes it to the SAX parser. A value that begins
    a container is not read to its end: the container is opened with
    @ref enter_container and its elements are read by
    @ref parse_msgpack_internal, so that nesting does not consume native stack.

    @return whether reading the value succeeded
    */
    bool parse_msgpack_value()
    {
        switch (get())
        {
            // EOF
            case char_traits<char_type>::eof():
                return unexpect_eof("value");

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
                return enter_object(conditional_static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x0Fu));

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
                return enter_array(conditional_static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x0Fu));

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
            case 0xD9: // str 8
            case 0xDA: // str 16
            case 0xDB: // str 32
            {
                string_t s;
                return get_msgpack_string(s) && sax->string(s);
            }

            case 0xC0: // nil
                return sax->null();

            case 0xC2: // false
                return sax->boolean(false);

            case 0xC3: // true
                return sax->boolean(true);

            case 0xC4: // bin 8
            case 0xC5: // bin 16
            case 0xC6: // bin 32
            case 0xC7: // ext 8
            case 0xC8: // ext 16
            case 0xC9: // ext 32
            case 0xD4: // fixext 1
            case 0xD5: // fixext 2
            case 0xD6: // fixext 4
            case 0xD7: // fixext 8
            case 0xD8: // fixext 16
            {
                binary_t b;
                return get_msgpack_binary(b) && sax->binary(b);
            }

            case 0xCA: // float 32
            {
                float number{};
                return get_number(number) && emit_float(number);
            }

            case 0xCB: // float 64
            {
                double number{};
                return get_number(number) && emit_float(number);
            }

            case 0xCC: // uint 8
            {
                std::uint8_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 0xCD: // uint 16
            {
                std::uint16_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 0xCE: // uint 32
            {
                std::uint32_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 0xCF: // uint 64
            {
                std::uint64_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 0xD0: // int 8
            {
                std::int8_t number{};
                return get_number(number) && emit_signed(number);
            }

            case 0xD1: // int 16
            {
                std::int16_t number{};
                return get_number(number) && emit_signed(number);
            }

            case 0xD2: // int 32
            {
                std::int32_t number{};
                return get_number(number) && emit_signed(number);
            }

            case 0xD3: // int 64
            {
                std::int64_t number{};
                return get_number(number) && emit_signed(number);
            }

            case 0xDC: // array 16
            {
                std::uint16_t len{};
                return get_number(len) && enter_array(static_cast<std::size_t>(len));
            }

            case 0xDD: // array 32
            {
                std::uint32_t len{};
                return get_number(len) && enter_array(conditional_static_cast<std::size_t>(len));
            }

            case 0xDE: // map 16
            {
                std::uint16_t len{};
                return get_number(len) && enter_object(static_cast<std::size_t>(len));
            }

            case 0xDF: // map 32
            {
                std::uint32_t len{};
                return get_number(len) && enter_object(conditional_static_cast<std::size_t>(len));
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
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                        exception_message(concat("invalid byte: 0x", last_token), "value"), nullptr));
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
    bool get_msgpack_string(string_t& result, const char* context = "string")
    {
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("string")))
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
                return get_string(static_cast<unsigned int>(current) & 0x1Fu, result) && check_string_utf8(result, context);
            }

            case 0xD9: // str 8
            {
                std::uint8_t len{};
                return get_number(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 0xDA: // str 16
            {
                std::uint16_t len{};
                return get_number(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 0xDB: // str 32
            {
                std::uint32_t len{};
                return get_number(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                        exception_message(concat("expected length specification (0xA0-0xBF, 0xD9-0xDB); last byte: 0x", last_token), "string"), nullptr));
            }
        }
    }

    /*!
    @brief reads a MessagePack object key

    The MessagePack specification allows any type as a map key, but only
    strings have a counterpart in JSON. A key of any other type is rejected
    with a message naming that type, rather than the one @ref
    get_msgpack_string gives for a malformed string.

    @param[out] result  created key

    @return whether key creation completed
    */
    bool get_msgpack_object_key(string_t& result)
    {
        const char* found = nullptr;
        switch (current)
        {
            case 0xC0:
                found = "nil";
                break;
            case 0xC2:
            case 0xC3:
                found = "a boolean";
                break;
            case 0xCA:
            case 0xCB:
                found = "a float";
                break;
            case 0xC4:
            case 0xC5:
            case 0xC6:
                found = "a bin";
                break;
            case 0xC7:
            case 0xC8:
            case 0xC9:
            case 0xD4:
            case 0xD5:
            case 0xD6:
            case 0xD7:
            case 0xD8:
                found = "an ext";
                break;
            case 0xCC:
            case 0xCD:
            case 0xCE:
            case 0xCF:
            case 0xD0:
            case 0xD1:
            case 0xD2:
            case 0xD3:
                found = "an integer";
                break;
            case 0xDC:
            case 0xDD:
                found = "an array";
                break;
            case 0xDE:
            case 0xDF:
                found = "a map";
                break;
            default:
                // fixint, fixmap, and fixarray; strings, EOF, and the unused
                // byte 0xC1 are left to get_msgpack_string
                if (current == char_traits<char_type>::eof())
                {
                    return get_msgpack_string(result, "key");
                }
                if (current <= 0x7F || current >= 0xE0)
                {
                    found = "an integer";
                }
                else if (current <= 0x8F)
                {
                    found = "a map";
                }
                else if (current <= 0x9F)
                {
                    found = "an array";
                }
                else
                {
                    return get_msgpack_string(result, "key");
                }
                break;
        }

        auto last_token = get_token_string();
        return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                exception_message(concat("only string keys are supported, but found ", found, "; last byte: 0x", last_token), "object key"), nullptr));
    }

    /*!
    @brief reads a MessagePack byte array

    This function first reads starting bytes to determine the expected
    byte array length and then copies this number of bytes into a byte array.

    @param[out] result  created byte array

    @return whether byte array creation completed
    */
    bool get_msgpack_binary(binary_t& result)
    {
        // helper function to set the subtype
        auto assign_and_return_true = [&result](std::int8_t subtype)
        {
            result.set_subtype(static_cast<std::uint8_t>(subtype));
            return true;
        };

        switch (current)
        {
            case 0xC4: // bin 8
            {
                std::uint8_t len{};
                return get_number(len) &&
                       get_binary(len, result);
            }

            case 0xC5: // bin 16
            {
                std::uint16_t len{};
                return get_number(len) &&
                       get_binary(len, result);
            }

            case 0xC6: // bin 32
            {
                std::uint32_t len{};
                return get_number(len) &&
                       get_binary(len, result);
            }

            case 0xC7: // ext 8
            {
                std::uint8_t len{};
                std::int8_t subtype{};
                return get_number(len) &&
                       get_number(subtype) &&
                       get_binary(len, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xC8: // ext 16
            {
                std::uint16_t len{};
                std::int8_t subtype{};
                return get_number(len) &&
                       get_number(subtype) &&
                       get_binary(len, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xC9: // ext 32
            {
                std::uint32_t len{};
                std::int8_t subtype{};
                return get_number(len) &&
                       get_number(subtype) &&
                       get_binary(len, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD4: // fixext 1
            {
                std::int8_t subtype{};
                return get_number(subtype) &&
                       get_binary(1, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD5: // fixext 2
            {
                std::int8_t subtype{};
                return get_number(subtype) &&
                       get_binary(2, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD6: // fixext 4
            {
                std::int8_t subtype{};
                return get_number(subtype) &&
                       get_binary(4, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD7: // fixext 8
            {
                std::int8_t subtype{};
                return get_number(subtype) &&
                       get_binary(8, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD8: // fixext 16
            {
                std::int8_t subtype{};
                return get_number(subtype) &&
                       get_binary(16, result) &&
                       assign_and_return_true(subtype);
            }

            default:           // LCOV_EXCL_LINE
                return false;  // LCOV_EXCL_LINE
        }
    }

    /*!
    @brief read a MessagePack value and everything nested inside it

    Reads values until the one that was begun here is complete, resuming the
    enclosing container each time an element ends, so that the nesting depth
    of the input costs heap rather than native stack (see #5104).

    @return whether reading the value succeeded
    */
    bool parse_msgpack_internal()
    {
        // the key currently being read; hoisted out of the loop so that its
        // capacity is reused across elements and across nesting levels
        string_t key;

        while (true)
        {
            if (!container_stack.empty())
            {
                // copied out before anything can push onto the stack and
                // invalidate a reference into it
                const bool is_object = container_stack.back().is_object;

                if (container_stack.back().remaining == 0)
                {
                    if (JSON_HEDLEY_UNLIKELY(!leave_container()))
                    {
                        return false;
                    }
                    // the value begun here is complete once its container is
                    if (container_stack.empty())
                    {
                        return true;
                    }
                    continue;
                }

                // claim the element about to be read
                --container_stack.back().remaining;

                if (is_object)
                {
                    get();
                    key.clear();
                    if (JSON_HEDLEY_UNLIKELY(!get_msgpack_object_key(key) || !sax->key(key)))
                    {
                        return false;
                    }
                }
            }

            if (JSON_HEDLEY_UNLIKELY(!parse_msgpack_value()))
            {
                return false;
            }

            // a value that opened a container left it on the stack; one that
            // did not, and that was not inside a container, was the whole value
            if (container_stack.empty())
            {
                return true;
            }
        }
    }

    ////////////
    // UBJSON //
    ////////////

    /*!
    @return whether a valid UBJSON value was passed to the SAX parser
    */
    bool parse_ubjson_internal()
    {
        // the key currently being read; hoisted out of the loop so that its
        // capacity is reused across elements and across nesting levels
        string_t key;

        // the type marker of the value to read next
        char_int_type prefix = get_ignore_noop();

        while (true)
        {
            const std::size_t depth = container_stack.size();

            if (JSON_HEDLEY_UNLIKELY(!get_ubjson_value(prefix)))
            {
                return false;
            }

            // the value begun here is complete once it is not inside anything
            if (container_stack.empty())
            {
                return true;
            }

            // a value was completed rather than a container opened; a
            // container that ends at a marker needs the next byte to test
            if (container_stack.size() == depth && container_stack.back().remaining == npos)
            {
                get_ignore_noop();
            }

            // advance to the next element, closing the containers that ended.
            // top is a copy, not a reference: it must stay valid across the
            // pop_back() below, which destroys the container_stack element it
            // would otherwise alias.
            for (;;)
            {
                const container_frame top = container_stack.back();

                if (top.remaining != npos)
                {
                    if (top.remaining != 0)
                    {
                        --container_stack.back().remaining;
                        if (top.is_object)
                        {
                            key.clear();
                            if (JSON_HEDLEY_UNLIKELY(!get_ubjson_string(key, true, "key") || !sax->key(key)))
                            {
                                return false;
                            }
                        }
                        // an optimized container gives its elements no marker
                        prefix = (top.type_marker != 0) ? top.type_marker : get_ignore_noop();
                        break;
                    }
                }
                // the end marker is compared against a literal rather than
                // against a conditional expression, because char_int_type is
                // unsigned for some input adapters and MSVC then reports the
                // comparison as a signed/unsigned mismatch
                else if (top.is_object ? (current != '}') : (current != ']'))
                {
                    // a container that ends at a marker is never optimized, so
                    // every element carries its own marker; for an object the
                    // byte tested above is the first byte of the key
                    if (top.is_object)
                    {
                        key.clear();
                        if (JSON_HEDLEY_UNLIKELY(!get_ubjson_string(key, false, "key") || !sax->key(key)))
                        {
                            return false;
                        }
                        prefix = get_ignore_noop();
                    }
                    else
                    {
                        prefix = current;
                    }
                    break;
                }

                if (JSON_HEDLEY_UNLIKELY(!leave_container()))
                {
                    return false;
                }
                if (container_stack.empty())
                {
                    return true;
                }
                // the container that just ended was an element of the one
                // below it, which may need the next byte for its own test
                if (container_stack.back().remaining == npos)
                {
                    get_ignore_noop();
                }
            }
        }
    }

    /*!
    @brief reject a negative UBJSON/BJData string length

    String and key lengths are written with signed integer markers (i, I, l,
    L). A negative value is malformed; without this check get_string() would
    silently treat it as an empty string and leave the following bytes to be
    misread as the next value. This mirrors the non-negative check the
    optimized-container count path already performs in get_ubjson_size_value.

    @param[in] len  the string length read from the input
    @return whether the length is valid (non-negative)
    */
    template<typename NumberType>
    bool check_ubjson_string_length(const NumberType len)
    {
        if (JSON_HEDLEY_UNLIKELY(len < 0))
        {
            return sax->parse_error(chars_read, get_token_string(), parse_error::create(113, chars_read,
                                    exception_message("string length must not be negative", "string"), nullptr));
        }
        return true;
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
    bool get_ubjson_string(string_t& result, const bool get_char = true, const char* context = "string")
    {
        if (get_char)
        {
            // no get_ignore_noop() here: the byte read next must be a string
            // length type specification, and a no-op ('N') is not valid in
            // that position. No-ops at positions where a value may appear are
            // already consumed by the callers via get_ignore_noop().
            get();
        }

        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("value")))
        {
            return false;
        }

        switch (current)
        {
            case 'U':
            {
                std::uint8_t len{};
                return get_number(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 'i':
            {
                std::int8_t len{};
                return get_number(len) && check_ubjson_string_length(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 'I':
            {
                std::int16_t len{};
                return get_number(len) && check_ubjson_string_length(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 'l':
            {
                std::int32_t len{};
                return get_number(len) && check_ubjson_string_length(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 'L':
            {
                std::int64_t len{};
                return get_number(len) && check_ubjson_string_length(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 'u':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint16_t len{};
                return get_number(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 'm':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint32_t len{};
                return get_number(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            case 'M':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint64_t len{};
                return get_number(len) && get_string(len, result) && check_string_utf8(result, context);
            }

            default:
                break;
        }
        auto last_token = get_token_string();
        std::string message;

        if (input_format != input_format_t::bjdata)
        {
            message = "expected length type specification (U, i, I, l, L); last byte: 0x" + last_token;
        }
        else
        {
            message = "expected length type specification (U, i, u, I, m, l, M, L); last byte: 0x" + last_token;
        }
        return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(message, "string"), nullptr));
    }

    /*!
    @param[out] dim  an integer vector storing the ND array dimensions
    @return whether reading ND array size vector is successful
    */
    bool get_ubjson_ndarray_size(std::vector<size_t>& dim)
    {
        std::pair<std::size_t, char_int_type> size_and_type;
        size_t dimlen = 0;
        bool no_ndarray = true;

        if (JSON_HEDLEY_UNLIKELY(!get_ubjson_size_type(size_and_type, no_ndarray)))
        {
            return false;
        }

        if (size_and_type.first != npos)
        {
            if (size_and_type.second != 0)
            {
                if (size_and_type.second != 'N')
                {
                    for (std::size_t i = 0; i < size_and_type.first; ++i)
                    {
                        if (JSON_HEDLEY_UNLIKELY(!get_ubjson_size_value(dimlen, no_ndarray, size_and_type.second)))
                        {
                            return false;
                        }
                        dim.push_back(dimlen);
                    }
                }
            }
            else
            {
                for (std::size_t i = 0; i < size_and_type.first; ++i)
                {
                    if (JSON_HEDLEY_UNLIKELY(!get_ubjson_size_value(dimlen, no_ndarray)))
                    {
                        return false;
                    }
                    dim.push_back(dimlen);
                }
            }
        }
        else
        {
            while (current != ']')
            {
                if (JSON_HEDLEY_UNLIKELY(!get_ubjson_size_value(dimlen, no_ndarray, current)))
                {
                    return false;
                }
                dim.push_back(dimlen);
                get_ignore_noop();
            }
        }
        return true;
    }

    /*!
    @brief read a UBJSON/BJData optimized-container count of a signed marker
           type ('i', 'I', 'l', 'L') and narrow it to std::size_t

    Every signed count marker rejects a negative value the same way (error
    113); the value_in_range_of check additionally needed for 'L' is only
    ever live when @a SignedType is std::int64_t on a target where
    std::size_t is narrower (e.g. 32-bit), since 'i'/'I'/'l' can never exceed
    std::size_t there.

    @tparam SignedType  std::int8_t, std::int16_t, std::int32_t or std::int64_t
    @param[out] result  the count narrowed to std::size_t
    @return whether reading and validating succeeded
    */
    template<typename SignedType>
    bool get_ubjson_signed_count(std::size_t& result)
    {
        SignedType number{};
        if (JSON_HEDLEY_UNLIKELY(!get_number(number)))
        {
            return false;
        }
        if (JSON_HEDLEY_UNLIKELY(number < 0))
        {
            return sax->parse_error(chars_read, get_token_string(), parse_error::create(113, chars_read,
                                    exception_message("count in an optimized container must be positive", "size"), nullptr));
        }
        if (JSON_HEDLEY_UNLIKELY(!value_in_range_of<std::size_t>(number)))
        {
            return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408,
                                    exception_message("integer value overflow", "size"), nullptr));
        }
        result = static_cast<std::size_t>(number); // NOLINT(bugprone-signed-char-misuse,cert-str34-c): number is not a char
        return true;
    }

    /*!
    @param[out] result  determined size
    @param[in,out] is_ndarray  for input, `true` means already inside an ndarray vector
                               or ndarray dimension is not allowed; `false` means ndarray
                               is allowed; for output, `true` means an ndarray is found;
                               is_ndarray can only return `true` when its initial value
                               is `false`
    @param[in] prefix  type marker if already read, otherwise set to 0
    @param[in] ndarray_dtype  the element type marker of the enclosing bjdata ndarray if
                              already known (it precedes the dimension vector read here),
                              otherwise 0; used to emit the "_ArrayType_" annotation key
                              before "_ArraySize_" if a dimension vector turns out to
                              describe an ndarray

    @return whether size determination completed
    */
    bool get_ubjson_size_value(std::size_t& result, bool& is_ndarray, char_int_type prefix = 0, char_int_type ndarray_dtype = 0)
    {
        if (prefix == 0)
        {
            prefix = get_ignore_noop();
        }

        switch (prefix)
        {
            case 'U':
            {
                std::uint8_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'i':
                return get_ubjson_signed_count<std::int8_t>(result);

            case 'I':
                return get_ubjson_signed_count<std::int16_t>(result);

            case 'l':
                return get_ubjson_signed_count<std::int32_t>(result);

            case 'L':
                return get_ubjson_signed_count<std::int64_t>(result);

            case 'u':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint16_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'm':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint32_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(number)))
                {
                    return false;
                }
                result = conditional_static_cast<std::size_t>(number);
                return true;
            }

            case 'M':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint64_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(number)))
                {
                    return false;
                }
                if (!value_in_range_of<std::size_t>(number))
                {
                    return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408,
                                            exception_message("integer value overflow", "size"), nullptr));
                }
                result = detail::conditional_static_cast<std::size_t>(number);
                return true;
            }

            case '[':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                if (is_ndarray) // ndarray dimensional vector can only contain integers and cannot embed another array
                {
                    return sax->parse_error(chars_read, get_token_string(), parse_error::create(113, chars_read, exception_message("ndarray dimensional vector is not allowed", "size"), nullptr));
                }
                std::vector<size_t> dim;
                if (JSON_HEDLEY_UNLIKELY(!get_ubjson_ndarray_size(dim)))
                {
                    return false;
                }
                if (dim.size() == 1 || (dim.size() == 2 && dim.at(0) == 1)) // return normal array size if 1D row vector
                {
                    result = dim.at(dim.size() - 1);
                    return true;
                }
                if (!dim.empty())  // if ndarray, convert to an object in JData annotated array format
                {
                    for (auto i : dim) // test if any dimension in an ndarray is 0, if so, return a 1D empty container
                    {
                        if ( i == 0 )
                        {
                            result = 0;
                            return true;
                        }
                    }

                    if (JSON_HEDLEY_UNLIKELY(!sax->start_object(3)))
                    {
                        return false;
                    }

                    // the element type precedes the dimension vector (see get_ubjson_size_type)
                    // and is passed down as ndarray_dtype; emit it here so the annotation keys
                    // follow the documented _ArrayType_, _ArraySize_, _ArrayData_ order
                    if (ndarray_dtype != 0)
                    {
                        const char* type_name = bjd_type_name(ndarray_dtype);
                        if (JSON_HEDLEY_UNLIKELY(type_name == nullptr))
                        {
                            auto last_token = get_token_string();
                            return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                                    exception_message("invalid byte: 0x" + last_token, "type"), nullptr));
                        }

                        string_t type_key = "_ArrayType_";
                        string_t type = type_name; // sax->string() takes a reference
                        if (JSON_HEDLEY_UNLIKELY(!sax->key(type_key) || !sax->string(type)))
                        {
                            return false;
                        }
                    }

                    string_t key = "_ArraySize_";
                    if (JSON_HEDLEY_UNLIKELY(!sax->key(key) || !sax->start_array(dim.size())))
                    {
                        return false;
                    }
                    result = 1;
                    for (auto i : dim)
                    {
                        // Pre-multiplication overflow check: since the loop above
                        // already rejected any zero dimension, i is always > 0
                        // here, so result > SIZE_MAX/i means result*i would
                        // overflow. This check must happen before multiplication
                        // since overflow detection after the fact is unreliable,
                        // as modular arithmetic can produce any value, not just 0
                        // or SIZE_MAX.
                        if (JSON_HEDLEY_UNLIKELY(result > (std::numeric_limits<std::size_t>::max)() / i))
                        {
                            return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408, exception_message("excessive ndarray size caused overflow", "size"), nullptr));
                        }
                        result *= i;
                        // the pre-check above already rules out result becoming 0
                        // by overflow; the only value it cannot rule out is an
                        // exact match with npos, the sentinel reserved for an
                        // unknown-size container (see get_ubjson_size_type())
                        if (result == npos)
                        {
                            return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408, exception_message("excessive ndarray size caused overflow", "size"), nullptr));
                        }
                        if (JSON_HEDLEY_UNLIKELY(!emit_unsigned(i)))
                        {
                            return false;
                        }
                    }
                    is_ndarray = true;
                    return sax->end_array();
                }
                result = 0;
                return true;
            }

            default:
                break;
        }
        auto last_token = get_token_string();
        std::string message;

        if (input_format != input_format_t::bjdata)
        {
            message = "expected length type specification (U, i, I, l, L) after '#'; last byte: 0x" + last_token;
        }
        else
        {
            message = "expected length type specification (U, i, u, I, m, l, M, L) after '#'; last byte: 0x" + last_token;
        }
        return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(message, "size"), nullptr));
    }

    /*!
    @brief determine the type and size for a container

    In the optimized UBJSON format, a type and a size can be provided to allow
    for a more compact representation.

    @param[out] result  pair of the size and the type
    @param[in] inside_ndarray  whether the parser is parsing an ND array dimensional vector

    @return whether pair creation completed
    */
    bool get_ubjson_size_type(std::pair<std::size_t, char_int_type>& result, bool inside_ndarray = false)
    {
        result.first = npos; // size
        result.second = 0; // type
        // seed the flag with the caller's context: inside an ndarray dimension
        // vector another ndarray is not allowed, and get_ubjson_size_value()
        // rejects it up front instead of reading it and reporting afterwards.
        // Seeding it with `false` made every '#' of a "[#[#[..." chain descend
        // another level, which overflowed the stack (see #5104).
        bool is_ndarray = inside_ndarray;

        get_ignore_noop();

        if (current == '$')
        {
            result.second = get();  // must not ignore 'N', because 'N' maybe the type
            if (input_format == input_format_t::bjdata
                    && JSON_HEDLEY_UNLIKELY(is_bjd_excluded_optimized_type(result.second)))
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                        exception_message(concat("marker 0x", last_token, " is not a permitted optimized array type"), "type"), nullptr));
            }

            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("type")))
            {
                return false;
            }

            get_ignore_noop();
            if (JSON_HEDLEY_UNLIKELY(current != '#'))
            {
                if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("value")))
                {
                    return false;
                }
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                        exception_message(concat("expected '#' after type information; last byte: 0x", last_token), "size"), nullptr));
            }

            const bool is_error = get_ubjson_size_value(result.first, is_ndarray, 0, result.second);
            // an ndarray was read here only if the flag flipped; when it was
            // seeded true, get_ubjson_size_value() already rejected the nested
            // dimension vector
            if (input_format == input_format_t::bjdata && is_ndarray && !inside_ndarray)
            {
                result.second |= (1 << 8); // use bit 8 to indicate ndarray, all UBJSON and BJData markers should be ASCII letters
            }
            return is_error;
        }

        if (current == '#')
        {
            const bool is_error = get_ubjson_size_value(result.first, is_ndarray);
            if (input_format == input_format_t::bjdata && is_ndarray && !inside_ndarray)
            {
                return sax->parse_error(chars_read, get_token_string(), parse_error::create(112, chars_read,
                                        exception_message("ndarray requires both type and size", "size"), nullptr));
            }
            return is_error;
        }

        return true;
    }

    /*!
    @param prefix  the previously read or set type prefix
    @return whether value creation completed
    */
    bool get_ubjson_value(const char_int_type prefix)
    {
        switch (prefix)
        {
            case char_traits<char_type>::eof():  // EOF
                return unexpect_eof("value");

            case 'T':  // true
                return sax->boolean(true);
            case 'F':  // false
                return sax->boolean(false);

            case 'Z':  // null
                return sax->null();

            case 'B':  // byte
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint8_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 'U':
            {
                std::uint8_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 'i':
            {
                std::int8_t number{};
                return get_number(number) && emit_signed(number);
            }

            case 'I':
            {
                std::int16_t number{};
                return get_number(number) && emit_signed(number);
            }

            case 'l':
            {
                std::int32_t number{};
                return get_number(number) && emit_signed(number);
            }

            case 'L':
            {
                std::int64_t number{};
                return get_number(number) && emit_signed(number);
            }

            case 'u':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint16_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 'm':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint32_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 'M':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint64_t number{};
                return get_number(number) && emit_unsigned(number);
            }

            case 'h':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                return get_half_float(true);
            }

            case 'd':
            {
                float number{};
                return get_number(number) && emit_float(number);
            }

            case 'D':
            {
                double number{};
                return get_number(number) && emit_float(number);
            }

            case 'H':
            {
                return get_ubjson_high_precision_number();
            }

            case 'C':  // char
            {
                get();
                if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("char")))
                {
                    return false;
                }
                if (JSON_HEDLEY_UNLIKELY(current > 127))
                {
                    auto last_token = get_token_string();
                    return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                            exception_message(concat("byte after 'C' must be in range 0x00..0x7F; last byte: 0x", last_token), "char"), nullptr));
                }
                string_t s(1, static_cast<typename string_t::value_type>(current));
                return sax->string(s);
            }

            case 'S':  // string
            {
                string_t s;
                return get_ubjson_string(s) && sax->string(s);
            }

            case '[':  // array
                return get_ubjson_array();

            case '{':  // object
                return get_ubjson_object();

            default: // anything else
                break;
        }
        auto last_token = get_token_string();
        return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, exception_message("invalid byte: 0x" + last_token, "value"), nullptr));
    }

    /*!
    @return whether array creation completed
    */
    bool get_ubjson_array()
    {
        std::pair<std::size_t, char_int_type> size_and_type;
        if (JSON_HEDLEY_UNLIKELY(!get_ubjson_size_type(size_and_type)))
        {
            return false;
        }

        // if bit-8 of size_and_type.second is set to 1, encode bjdata ndarray as an object in JData annotated array format (https://github.com/NeuroJSON/jdata):
        // {"_ArrayType_" : "typeid", "_ArraySize_" : [n1, n2, ...], "_ArrayData_" : [v1, v2, ...]}

        if (input_format == input_format_t::bjdata && size_and_type.first != npos && (size_and_type.second & (1 << 8)) != 0)
        {
            size_and_type.second &= ~(static_cast<char_int_type>(1) << 8);  // use bit 8 to indicate ndarray, here we remove the bit to restore the type marker

            // the "_ArrayType_" and "_ArraySize_" annotation keys were already emitted by
            // get_ubjson_size_value() (the type marker is known before the dimension vector
            // that determines size_and_type.first is read, so it is emitted first there to
            // match the documented _ArrayType_, _ArraySize_, _ArrayData_ key order)
            if (size_and_type.second == 'C' || size_and_type.second == 'B')
            {
                size_and_type.second = 'U';
            }

            string_t key = "_ArrayData_";
            if (JSON_HEDLEY_UNLIKELY(!sax->key(key) || !sax->start_array(size_and_type.first) ))
            {
                return false;
            }

            for (std::size_t i = 0; i < size_and_type.first; ++i)
            {
                if (JSON_HEDLEY_UNLIKELY(!get_ubjson_value(size_and_type.second)))
                {
                    return false;
                }
            }

            return (sax->end_array() && sax->end_object());
        }

        // If BJData type marker is 'B' decode as binary
        if (input_format == input_format_t::bjdata && size_and_type.first != npos && size_and_type.second == 'B')
        {
            binary_t result;
            return get_binary(size_and_type.first, result) && sax->binary(result);
        }

        if (size_and_type.first != npos)
        {
            // reading an element of a valueless type consumes no input, so the
            // declared count alone decides how much is allocated; the check is
            // made before the start event so that no container is opened that
            // is then abandoned. See @ref max_valueless_container_size.
            if (JSON_HEDLEY_UNLIKELY((size_and_type.second == 'Z' || size_and_type.second == 'T' || size_and_type.second == 'F')
                                     && size_and_type.first > max_valueless_container_size))
            {
                return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408,
                                        exception_message("excessive array size", "size"), nullptr));
            }

            if (JSON_HEDLEY_UNLIKELY(!enter_array(size_and_type.first, size_and_type.second)))
            {
                return false;
            }

            if (size_and_type.second == 'N')
            {
                // a no-op is not a value, so a container of them holds none;
                // the declared size has already been passed to the SAX parser
                container_stack.back().remaining = 0;
            }

            return true;
        }

        return enter_array(detail::unknown_size());
    }

    /*!
    @return whether object creation completed
    */
    bool get_ubjson_object()
    {
        std::pair<std::size_t, char_int_type> size_and_type;
        if (JSON_HEDLEY_UNLIKELY(!get_ubjson_size_type(size_and_type)))
        {
            return false;
        }

        // do not accept ND-array size in objects in BJData
        if (input_format == input_format_t::bjdata && size_and_type.first != npos && (size_and_type.second & (1 << 8)) != 0)
        {
            auto last_token = get_token_string();
            return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message("BJData object does not support ND-array size in optimized format", "object"), nullptr));
        }

        if (size_and_type.first != npos)
        {
            return enter_object(size_and_type.first, size_and_type.second);
        }

        return enter_object(detail::unknown_size());
    }

    // Note, UBJSON has no binary type of its own; BJData, which shares this
    // reader, decodes optimized 'B' arrays as binary in get_ubjson_array().

    bool get_ubjson_high_precision_number()
    {
        // get the size of the following number string
        std::size_t size{};
        bool no_ndarray = true;
        auto res = get_ubjson_size_value(size, no_ndarray);
        if (JSON_HEDLEY_UNLIKELY(!res))
        {
            return res;
        }

        // get number string
        std::vector<char> number_vector;
        for (std::size_t i = 0; i < size; ++i)
        {
            get();
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("number")))
            {
                return false;
            }
            // the lexer would stop at a NUL and accept the digits before it
            if (JSON_HEDLEY_UNLIKELY(current == '\0'))
            {
                return sax->parse_error(chars_read, "00", parse_error::create(115, chars_read,
                                        exception_message("invalid number text; last byte: 0x00", "high-precision number"), nullptr));
            }
            number_vector.push_back(static_cast<char>(current));
        }

        // parse number string
        using ia_type = decltype(detail::input_adapter(number_vector));
        auto number_lexer = detail::lexer<BasicJsonType, ia_type>(detail::input_adapter(number_vector), false);
        const auto result_number = number_lexer.scan();
        const auto number_string = number_lexer.get_token_string();
        const auto result_remainder = number_lexer.scan();

        using token_type = typename detail::lexer_base<BasicJsonType>::token_type;

        if (JSON_HEDLEY_UNLIKELY(result_remainder != token_type::end_of_input))
        {
            return sax->parse_error(chars_read, number_string, parse_error::create(115, chars_read,
                                    exception_message(concat("invalid number text: ", number_lexer.get_token_string()), "high-precision number"), nullptr));
        }

        switch (result_number)
        {
            case token_type::value_integer:
                return sax->number_integer(number_lexer.get_number_integer());
            case token_type::value_unsigned:
                return sax->number_unsigned(number_lexer.get_number_unsigned());
            case token_type::value_float:
            {
                const auto parsed_float = number_lexer.get_number_float();
                if (JSON_HEDLEY_UNLIKELY(!std::isfinite(parsed_float)))
                {
                    return sax->parse_error(
                               chars_read,
                               number_string,
                               out_of_range::create(406, concat("number overflow parsing '", number_string, '\''), nullptr));
                }
                // number_string is a std::string, while the SAX interface takes a
                // string_t; convert explicitly, as the two are only implicitly
                // convertible for some string types
                return sax->number_float(parsed_float, string_t(number_string.data(), number_string.size()));
            }
            case token_type::uninitialized:
            case token_type::literal_true:
            case token_type::literal_false:
            case token_type::literal_null:
            case token_type::value_string:
            case token_type::begin_array:
            case token_type::begin_object:
            case token_type::end_array:
            case token_type::end_object:
            case token_type::name_separator:
            case token_type::value_separator:
            case token_type::parse_error:
            case token_type::end_of_input:
            case token_type::literal_or_value:
            default:
                return sax->parse_error(chars_read, number_string, parse_error::create(115, chars_read,
                                        exception_message(concat("invalid number text: ", number_lexer.get_token_string()), "high-precision number"), nullptr));
        }
    }

    //////////
    // BON8 //
    //////////

    /*!
    @brief get the next byte of a BON8 value

    A BON8 string has no length prefix and no mandatory terminator: it ends at
    the first byte that cannot continue it, which is already the first byte (or,
    for an integer that begins with a UTF-8 lead byte, the first two bytes) of
    whatever follows. The string reader hands those bytes back with
    @ref unget_bon8, and every BON8 read goes through this function so that
    they are seen again.

    @return character read from the input
    */
    char_int_type get_bon8()
    {
        if (bon8_pushback_size != 0)
        {
            ++chars_read;
            return current = bon8_pushback[--bon8_pushback_size];
        }
        return get();
    }

    /*!
    @brief hand a byte back so that the next @ref get_bon8 returns it again

    @param[in] c  the byte to hand back; bytes handed back are returned in
                  reverse order
    */
    void unget_bon8(const char_int_type c)
    {
        // At most two bytes are ever handed back: a byte is only handed back
        // right after it was read with get_bon8(), and the only place that
        // hands back two bytes (a lead byte and the byte after it) read both
        // of them in a row, which emptied the buffer first. This is an
        // invariant of the reader rather than a property of the input, so
        // an assertion suffices (the fuzzers are built with assertions).
        JSON_ASSERT(bon8_pushback_size < bon8_pushback.size());
        bon8_pushback[bon8_pushback_size++] = c;
        --chars_read;
    }

    /*!
    @param[in] c  a byte
    @return whether @a c is a UTF-8 continuation byte (0x80..0xBF)
    */
    static constexpr bool is_bon8_continuation(const char_int_type c) noexcept
    {
        return 0x80 <= c && c <= 0xBF;
    }

    /*!
    @brief report a parse error at the last read byte

    @param[in] detail   a detailed error message
    @param[in] context  further context information
    @return false
    */
    bool bon8_error(const std::string& detail, const char* context)
    {
        auto last_token = get_token_string();
        return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                exception_message(concat(detail, ": 0x", last_token), context), nullptr));
    }

    /*!
    @brief read a BON8 value and everything nested inside it

    Reads values until the one that was begun here is complete, resuming the
    enclosing container after each element, so that the nesting depth of the
    input costs heap rather than native stack (see #5104).

    @return whether reading the value succeeded
    */
    bool parse_bon8_internal()
    {
        // the key currently being read; hoisted out of the loop so that its
        // capacity is reused across elements and across nesting levels
        string_t key;

        while (true)
        {
            if (!container_stack.empty())
            {
                // a copy, not a reference: it must stay valid across the
                // pop_back() below, which destroys the container_stack element
                // it would otherwise alias
                const container_frame top = container_stack.back();
                bool at_end = false;

                if (top.remaining != npos)
                {
                    // counted container (0x80..0x84, 0x86..0x8A): it ends once
                    // its elements have been read
                    at_end = (top.remaining == 0);
                    if (!at_end)
                    {
                        // claim the element about to be read
                        --container_stack.back().remaining;
                    }
                }
                else
                {
                    // container 0x85 or 0x8B: it ends at an end-of-container
                    // marker (0xFE); any other byte begins the next element
                    at_end = (get_bon8() == 0xFE);
                    if (!at_end)
                    {
                        unget_bon8(current);
                    }
                }

                if (at_end)
                {
                    if (JSON_HEDLEY_UNLIKELY(!leave_container()))
                    {
                        return false;
                    }
                    // the value begun here is complete once its container is
                    if (container_stack.empty())
                    {
                        return true;
                    }
                    continue;
                }

                if (top.is_object)
                {
                    key.clear();
                    if (JSON_HEDLEY_UNLIKELY(!get_bon8_key(key) || !sax->key(key)))
                    {
                        return false;
                    }
                }
            }

            if (JSON_HEDLEY_UNLIKELY(!parse_bon8_value()))
            {
                return false;
            }

            // a value that opened a container left it on the stack; one that
            // did not, and that was not inside a container, was the whole value
            if (container_stack.empty())
            {
                return true;
            }
        }
    }

    /*!
    @brief read one BON8 value

    Reads a single value and passes it to the SAX parser. A value that begins
    a container is not read to its end: the container is opened with
    @ref enter_container and its elements are read by
    @ref parse_bon8_internal, so that nesting does not consume native stack.

    @return whether reading the value succeeded
    */
    bool parse_bon8_value()
    {
        const auto byte = get_bon8();

        if (byte == char_traits<char_type>::eof())
        {
            return unexpect_eof("value");
        }

        // string: ASCII character
        if (byte <= 0x7F)
        {
            string_t s;
            unget_bon8(byte);
            return get_bon8_string(s) && sax->string(s);
        }

        // array with 0..4 elements
        if (byte <= 0x84)
        {
            return enter_array(static_cast<std::size_t>(byte - 0x80));
        }

        // array terminated by 0xFE
        if (byte == 0x85)
        {
            return enter_array(npos);
        }

        // object with 0..4 members
        if (byte <= 0x8A)
        {
            return enter_object(static_cast<std::size_t>(byte - 0x86));
        }

        switch (byte)
        {
            case 0x8B: // object terminated by 0xFE
                return enter_object(npos);

            case 0x8C: // int32
            {
                std::int32_t number{};
                return get_number(number) && emit_bon8_integer(number);
            }

            case 0x8D: // int64
            {
                std::int64_t number{};
                return get_number(number) && emit_bon8_integer(number);
            }

            case 0x8E: // binary32
            {
                float number{};
                return get_number(number) && emit_float(number);
            }

            case 0x8F: // binary64
            {
                double number{};
                return get_number(number) && emit_float(number);
            }

            case 0xF8:
                return sax->boolean(false);

            case 0xF9:
                return sax->boolean(true);

            case 0xFA:
                return sax->null();

            case 0xFB:
                return sax->number_float(static_cast<number_float_t>(-1.0), "");

            case 0xFC:
                return sax->number_float(static_cast<number_float_t>(0.0), "");

            case 0xFD:
                return sax->number_float(static_cast<number_float_t>(1.0), "");

            case 0xFF: // empty string
            {
                string_t s;
                return sax->string(s);
            }

            default:
                break;
        }

        // integer 0..39
        if (byte <= 0xB7)
        {
            return sax->number_unsigned(static_cast<number_unsigned_t>(byte - 0x90));
        }

        // integer -1..-10
        if (byte <= 0xC1)
        {
            return sax->number_integer(conditional_static_cast<number_integer_t>(-1 - static_cast<number_integer_t>(byte - 0xB8)));
        }

        // 0xC2..0xF7: a UTF-8 lead byte begins a string if a continuation
        // byte follows and an integer otherwise
        if (byte <= 0xF7)
        {
            const auto second = get_bon8();
            if (is_bon8_continuation(second))
            {
                string_t s;
                unget_bon8(second);
                unget_bon8(byte);
                return get_bon8_string(s) && sax->string(s);
            }
            return get_bon8_integer(byte, second);
        }

        // 0xFE: end of container where a value is expected
        return bon8_error("invalid byte", "value");
    }

    /*!
    @brief pass an integer to the SAX parser

    Non-negative integers are passed as unsigned, negative integers as signed
    numbers, like the other binary formats do. A value that does not fit the
    number type is passed as described for @ref emit_unsigned and
    @ref emit_signed.

    @param[in] number  the integer
    @return whether the SAX parser accepted the value
    */
    bool emit_bon8_integer(const std::int64_t number)
    {
        if (number >= 0)
        {
            return emit_unsigned(static_cast<std::uint64_t>(number));
        }
        return emit_signed(number);
    }

    /*!
    @brief read an integer encoded in 2..4 bytes

    The first byte is a UTF-8 lead byte (0xC2..0xF7) that is followed by a
    byte that is not a continuation byte: 0x00..0x7F for positive and
    0xC0..0xFF for negative integers. The lead byte's low bits and the second
    byte's low 7 (positive) or 6 (negative) bits are the most significant bits
    of the value; 3- and 4-byte integers add one or two full bytes. Each range
    starts where the shorter one ends, so no value has two encodings of the
    same length.

    @param[in] lead    the first byte (0xC2..0xF7)
    @param[in] second  the second byte
    @return whether reading the integer succeeded
    */
    bool get_bon8_integer(const char_int_type lead, const char_int_type second)
    {
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("number")))
        {
            return false;
        }

        const bool negative = second >= 0xC0;
        auto value = static_cast<std::int64_t>(negative ? (second & 0x3F) : second);
        std::int64_t offset = 0;
        int extra_bytes = 0;

        if (lead <= 0xDF)
        {
            value |= static_cast<std::int64_t>(lead - 0xC2) << (negative ? 6 : 7);
            offset = negative ? 11 : 40;
        }
        else if (lead <= 0xEF)
        {
            value |= static_cast<std::int64_t>(lead & 0x0F) << (negative ? 6 : 7);
            offset = negative ? 1931 : 3880;
            extra_bytes = 1;
        }
        else
        {
            value |= static_cast<std::int64_t>(lead & 0x07) << (negative ? 6 : 7);
            offset = negative ? 264075 : 528168;
            extra_bytes = 2;
        }

        for (int i = 0; i < extra_bytes; ++i)
        {
            if (JSON_HEDLEY_UNLIKELY(get_bon8() == char_traits<char_type>::eof()))
            {
                return unexpect_eof("number");
            }
            value = (value << 8) | static_cast<std::int64_t>(current);
        }

        return emit_bon8_integer(negative ? -(value + offset) : value + offset);
    }

    /*!
    @brief read an object key

    A key must be a string, so its first byte must be an ASCII character, a
    UTF-8 lead byte followed by a continuation byte, or 0xFF (empty string).

    @param[out] result  the key
    @return whether reading the key succeeded
    */
    bool get_bon8_key(string_t& result)
    {
        const auto byte = get_bon8();

        if (byte == char_traits<char_type>::eof())
        {
            return unexpect_eof("key");
        }

        if (byte == 0xFF)
        {
            return true;
        }

        if (byte <= 0x7F)
        {
            unget_bon8(byte);
            return get_bon8_string(result);
        }

        if (0xC2 <= byte && byte <= 0xF7)
        {
            const auto second = get_bon8();
            if (second == char_traits<char_type>::eof())
            {
                // the input ends inside a character or an integer
                return unexpect_eof("key");
            }
            unget_bon8(second);
            if (is_bon8_continuation(second))
            {
                unget_bon8(byte);
                return get_bon8_string(result);
            }
            // an integer: report its first byte rather than the one after it
            current = byte;
        }

        return bon8_error("expected a string; last byte", "key");
    }

    /*!
    @brief append the run of valid UTF-8 at the read position to a string

    For contiguous input, the ASCII characters and complete well-formed UTF-8
    sequences at the read position are appended to @a result in one step. The
    byte that stops the run (an end-of-string marker, the first byte of the
    next value, or an ill-formed byte) is left for @ref get_bon8_string, so
    that strings end and errors are reported exactly as without this step.

    @param[in,out] result  the string to append to
    */
    void get_bon8_string_bulk(string_t& result, std::true_type /*bulk*/)
    {
        // bytes handed back must be read through get_bon8() first
        if (bon8_pushback_size != 0)
        {
            return;
        }
        const std::size_t remaining = ia.bulk_remaining();
        if (remaining == 0)
        {
            return;
        }
        const auto* const data = reinterpret_cast<const unsigned char*>(ia.bulk_data());
        const std::size_t length = valid_utf8_prefix(data, remaining);
        if (length != 0)
        {
            result.append(reinterpret_cast<const typename string_t::value_type*>(data), length);
            ia.bulk_skip(length);
            chars_read += length;
        }
    }

    /// input that is not contiguous: strings are read byte by byte
    void get_bon8_string_bulk(string_t& /*result*/, std::false_type /*bulk*/) const noexcept {}

    /*!
    @brief read a string

    Reads UTF-8 characters until an end-of-string marker (0xFF), which is
    consumed, or a byte that cannot continue the string, which is handed back
    to be read as the start of the next value. The string must be valid UTF-8,
    and it must not end at the end of the input: the last string of a message
    is always terminated by 0xFF.

    @param[out] result  the string
    @return whether reading the string succeeded
    */
    bool get_bon8_string(string_t& result)
    {
        while (true)
        {
            get_bon8_string_bulk(result, std::integral_constant<bool, bulk_scan> {});

            const auto byte = get_bon8();

            if (byte == char_traits<char_type>::eof())
            {
                return unexpect_eof("string");
            }

            // end of string
            if (byte == 0xFF)
            {
                return true;
            }

            // ASCII character
            if (byte <= 0x7F)
            {
                result.push_back(static_cast<typename string_t::value_type>(byte));
                continue;
            }

            // a byte that cannot begin a character ends the string and begins
            // the next value
            if (byte < 0xC2 || byte > 0xF7)
            {
                unget_bon8(byte);
                return true;
            }

            // a lead byte ends the string if no continuation byte follows: it
            // is then the first byte of an integer
            const auto second = get_bon8();
            if (second == char_traits<char_type>::eof())
            {
                // the input ends inside a character or an integer: either
                // way, the message is incomplete
                return unexpect_eof("string");
            }
            if (!is_bon8_continuation(second))
            {
                unget_bon8(second);
                unget_bon8(byte);
                return true;
            }

            // the valid range of the second byte excludes overlong forms,
            // surrogates, and code points above U+10FFFF
            // (RFC 3629, section 4)
            int continuation_bytes = 0;
            bool valid_second = true;
            if (byte <= 0xDF)
            {
                continuation_bytes = 1;
            }
            else if (byte <= 0xEF)
            {
                continuation_bytes = 2;
                valid_second = (byte != 0xE0 || second >= 0xA0) && (byte != 0xED || second <= 0x9F);
            }
            else
            {
                continuation_bytes = 3;
                valid_second = byte <= 0xF4 && (byte != 0xF0 || second >= 0x90) && (byte != 0xF4 || second <= 0x8F);
            }

            if (JSON_HEDLEY_UNLIKELY(!valid_second))
            {
                return bon8_error("invalid UTF-8 byte", "string");
            }

            result.push_back(static_cast<typename string_t::value_type>(byte));
            result.push_back(static_cast<typename string_t::value_type>(second));

            for (int i = 1; i < continuation_bytes; ++i)
            {
                if (JSON_HEDLEY_UNLIKELY(get_bon8() == char_traits<char_type>::eof()))
                {
                    return unexpect_eof("string");
                }
                if (JSON_HEDLEY_UNLIKELY(!is_bon8_continuation(current)))
                {
                    return bon8_error("invalid UTF-8 byte", "string");
                }
                result.push_back(static_cast<typename string_t::value_type>(current));
            }
        }
    }

    ///////////////////////
    // Utility functions //
    ///////////////////////

    /*!
    @brief get next character from the input

    This function provides the interface to the used input adapter. It does
    not throw in case the input reached EOF, but returns a -'ve valued
    `char_traits<char_type>::eof()` in that case.

    @return character read from the input
    */
    char_int_type get()
    {
        ++chars_read;
        return current = ia.get_character();
    }

    /*!
    @brief get_to read into a primitive type

    This function provides the interface to the used input adapter. It does
    not throw in case the input reached EOF, but returns false instead

    @return bool, whether the read was successful
    */
    template<class T>
    bool get_to(T& dest, const char* context)
    {
        // false positive: new_chars_read is read on the next lines
        // @infer-ignore DEAD_STORE
        auto new_chars_read = ia.get_elements(&dest);
        chars_read += new_chars_read;
        if (JSON_HEDLEY_UNLIKELY(new_chars_read < sizeof(T)))
        {
            // in case of failure, advance position by 1 to report the failing location
            ++chars_read;
            sax->parse_error(chars_read, "<end of file>", parse_error::create(110, chars_read, exception_message("unexpected end of input", context), nullptr));
            return false;
        }
        return true;
    }

    /*!
    @return character read from the input after ignoring all 'N' entries
    */
    char_int_type get_ignore_noop()
    {
        do
        {
            get();
        }
        while (current == 'N');

        return current;
    }

    template<class NumberType>
    static void byte_swap(NumberType& number)
    {
        constexpr std::size_t sz = sizeof(number);
#ifdef __cpp_lib_byteswap
        if constexpr (sz == 1)
        {
            return;
        }
        else if constexpr(std::is_integral_v<NumberType>)
        {
            number = std::byteswap(number);
            return;
        }
        else
        {
#endif
            auto* ptr = reinterpret_cast<std::uint8_t*>(&number);
            for (std::size_t i = 0; i < sz / 2; ++i)
            {
                std::swap(ptr[i], ptr[sz - i - 1]);
            }
#ifdef __cpp_lib_byteswap
        }
#endif
    }

    /*!
    @brief read a number from the input

    @tparam NumberType the type of the number
    @param[out] result  number of type @a NumberType

    @return whether conversion completed

    @note This function needs to respect the system's endianness, because
          bytes in CBOR, MessagePack, UBJSON, and BON8 are stored in network
          order (big endian) and therefore need reordering on little endian
          systems. On the other hand, BSON and BJData use little endian and
          should reorder on big endian systems.
    */
    template<typename NumberType, bool InputIsLittleEndian = false>
    bool get_number(NumberType& result)
    {
        // read in the original format

        if (JSON_HEDLEY_UNLIKELY(!get_to(result, "number")))
        {
            return false;
        }
        if (is_little_endian != (InputIsLittleEndian || input_format == input_format_t::bjdata))
        {
            byte_swap(result);
        }
        return true;
    }

    /*!
    @brief pass a signed integer read from the input to the SAX parser

    Like the lexer does for JSON text, a value that does not fit into
    number_integer_t is passed as number_unsigned_t if it is non-negative and
    fits there, and as number_float_t otherwise. With the default number
    types, every integer the binary formats can encode fits, so this only
    matters for narrower custom number types.

    @tparam NumberType a signed integer type
    @param[in] number  the integer
    @return whether the SAX parser accepted the value

    @throw out_of_range.406 if @a number overflows number_float_t (see
           @ref emit_float)
    */
    template<typename NumberType>
    bool emit_signed(const NumberType number)
    {
        if (JSON_HEDLEY_LIKELY(value_in_range_of<number_integer_t>(number)))
        {
            return sax->number_integer(static_cast<number_integer_t>(number));
        }
        if (value_in_range_of<number_unsigned_t>(number))
        {
            return sax->number_unsigned(static_cast<number_unsigned_t>(number));
        }
        // std::isfinite has no integer overloads in MSVC's <cmath>
        return emit_float(static_cast<long double>(number));
    }

    /*!
    @brief pass an unsigned integer read from the input to the SAX parser

    Like the lexer does for JSON text, a value that does not fit into
    number_unsigned_t is passed as number_float_t.

    @tparam NumberType an unsigned integer type
    @param[in] number  the integer
    @return whether the SAX parser accepted the value

    @throw out_of_range.406 if @a number overflows number_float_t (see
           @ref emit_float)
    */
    template<typename NumberType>
    bool emit_unsigned(const NumberType number)
    {
        if (JSON_HEDLEY_LIKELY(value_in_range_of<number_unsigned_t>(number)))
        {
            return sax->number_unsigned(static_cast<number_unsigned_t>(number));
        }
        // std::isfinite has no integer overloads in MSVC's <cmath>
        return emit_float(static_cast<long double>(number));
    }

    /*!
    @brief pass a floating-point number read from the input to the SAX parser

    Like the lexer does for JSON text, a finite value that overflows
    number_float_t is rejected instead of silently becoming infinity. Infinity
    and NaN in the input are passed on unchanged. Integers only overflow if
    number_float_t cannot represent 2^64, e.g., a half-precision type.

    @tparam NumberType a floating-point type (emit_signed and emit_unsigned
                       convert integers to long double first)
    @param[in] number  the number
    @return whether the SAX parser accepted the value

    @throw out_of_range.406 if a finite @a number overflows number_float_t
    */
    template<typename NumberType>
    bool emit_float(const NumberType number)
    {
        const auto result = static_cast<number_float_t>(number);
        if (JSON_HEDLEY_UNLIKELY(std::isfinite(number) && !std::isfinite(result)))
        {
            return sax->parse_error(chars_read, get_token_string(),
                                    out_of_range::create(406, exception_message("number overflow", "value"), nullptr));
        }
        return sax->number_float(result, "");
    }

    /*!
    @brief read and decode an IEEE 754 half-precision (16-bit) float

    Used by CBOR (big endian) and BJData (little endian); the two formats
    only differ in the byte order of the two bytes that make up the half.
    @param[in] little_endian whether the two bytes are little endian (BJData)
                             or big endian (CBOR)

    @return whether reading and decoding succeeded
    */
    bool get_half_float(const bool little_endian)
    {
        const auto byte1_raw = get();
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("number")))
        {
            return false;
        }
        const auto byte2_raw = get();
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof("number")))
        {
            return false;
        }

        const auto byte1 = static_cast<unsigned char>(byte1_raw);
        const auto byte2 = static_cast<unsigned char>(byte2_raw);

        // Code from RFC 8949, Appendix D, Figure 3:
        // As half-precision floating-point numbers were only added
        // to IEEE 754 in 2008, today's programming platforms often
        // still only have limited support for them. It is very
        // easy to include at least decoding support for them even
        // without such support. An example of a small decoder for
        // half-precision floating-point numbers in the C language
        // is shown in Fig. 3.
        const auto half = little_endian
                          ? static_cast<unsigned int>((byte2 << 8u) + byte1)
                          : static_cast<unsigned int>((byte1 << 8u) + byte2);
        const double val = [&half]
        {
            const int exp = (half >> 10u) & 0x1Fu;
            const unsigned int mant = half & 0x3FFu;
            JSON_ASSERT(exp <= 31);
            JSON_ASSERT(mant <= 1023);
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

    /*!
    @brief create a string by reading characters from the input

    @tparam NumberType the type of the number
    @param[in] len number of characters to read
    @param[out] result string created by reading @a len bytes

    @return whether string creation completed

    @note We can not reserve @a len bytes for the result, because @a len
          may be too large. Usually, @ref unexpect_eof() detects the end of
          the input before we run out of string memory.
    */
    template<typename NumberType>
    bool get_string(const NumberType len,
                    string_t& result)
    {
        // Strings are taken as is by default: none of CBOR (RFC 8949 §3.1
        // leaves the choice to the decoder), MessagePack (whose spec
        // explicitly allows a str object to contain an invalid byte
        // sequence), UBJSON, BJData, or BSON requires a decoder to reject
        // ill-formed UTF-8. Checking (and, with @ref error_handler_t::strict,
        // rejecting, or with `replace`/`ignore`, sanitizing) is opt-in via
        // @ref error_handler, applied once the whole string (all chunks of
        // an indefinite-length CBOR string included) has been assembled, by
        // @ref check_string_utf8 at the call site.
        return get_bytes(len, "string", result);
    }

    /*!
    @brief validate a decoded text string (value or object key) against @ref error_handler

    None of the binary formats requires a decoder to reject ill-formed UTF-8
    in a text string (see @ref get_string), so by default
    (@ref error_handler_t::keep) this does nothing. A stricter
    @ref error_handler opts into the same well-formedness check @ref
    serializer::dump_escaped_impl applies when dumping a string:
    @ref error_handler_t::strict rejects ill-formed input with
    parse_error.113 (honoring `allow_exceptions` via @a sax), while
    @ref error_handler_t::replace / @ref error_handler_t::ignore sanitize
    @a result in place, using the exact same rules.

    @param[in,out] result  the already assembled string to check
    @param[in] context     further context information (for diagnostics)
    @return whether @a result is acceptable (always true for `keep`)
    */
    bool check_string_utf8(string_t& result, const char* context)
    {
        if (error_handler == error_handler_t::keep || is_valid_utf8(result))
        {
            return true;
        }

        if (error_handler == error_handler_t::strict)
        {
            auto last_token = get_token_string();
            return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                    exception_message("invalid string: ill-formed UTF-8 byte", context), nullptr));
        }

        result = sanitize_utf8(result, error_handler);
        return true;
    }

    /*!
    @brief create a byte array by reading bytes from the input

    @tparam NumberType the type of the number
    @param[in] len number of bytes to read
    @param[out] result byte array created by reading @a len bytes

    @return whether byte array creation completed

    @note We can not reserve @a len bytes for the result, because @a len
          may be too large. Usually, @ref unexpect_eof() detects the end of
          the input before we run out of memory.
    */
    template<typename NumberType>
    bool get_binary(const NumberType len,
                    binary_t& result)
    {
        return get_bytes(len, "binary", result);
    }

    /*!
    @brief read @a len bytes from the input into a string or byte container

    @tparam NumberType    the type of the length
    @tparam ContainerType the destination container (string_t or binary_t)
    @param[in] len      number of bytes to read
    @param[in] context  further context information (for diagnostics)
    @param[out] result  container the bytes are appended to

    @return whether reading completed

    @note We cannot reserve @a len bytes for the result up front, because
          @a len may be far larger than the actual input. Instead we read in
          bounded chunks, so the peak allocation is capped regardless of the
          claimed length while the per-byte loop is replaced by block copies
          (a std::memcpy for contiguous inputs). @ref unexpect_eof() still
          detects a premature end of input.
    */
    template<typename NumberType, typename ContainerType>
    bool get_bytes(NumberType len,
                   const char* context,
                   ContainerType& result)
    {
        // upper bound on the number of bytes read (and allocated) per chunk
        constexpr std::size_t chunk_size = 4096;

        while (len > 0)
        {
            // number of bytes to read this iteration: min(chunk_size, len),
            // computed without truncating chunk_size to a narrow NumberType
            const std::size_t wanted = (static_cast<std::uintmax_t>(len) < static_cast<std::uintmax_t>(chunk_size))
                                       ? static_cast<std::size_t>(len)
                                       : chunk_size;
            const std::size_t old_size = result.size();
            result.resize(old_size + wanted);
            // resize() is required to make size() exactly old_size + wanted;
            // that is the room get_elements() is allowed to write into
            JSON_ASSERT(result.size() == old_size + wanted);
            // false positive: bytes_read is read on the next lines
            // @infer-ignore DEAD_STORE
            const std::size_t bytes_read = ia.get_elements(&result[old_size], wanted);
            chars_read += bytes_read;
            if (JSON_HEDLEY_UNLIKELY(bytes_read < wanted))
            {
                // premature end of input: shrink to what was actually read and
                // report the failure at the first missing byte (same position
                // accounting as get_to() for partial number reads)
                result.resize(old_size + bytes_read);
                ++chars_read;
                current = char_traits<char_type>::eof();
                return unexpect_eof(context);
            }
            // a full chunk was read; get_elements() never returns more than requested
            JSON_ASSERT(bytes_read == wanted);
            len = static_cast<NumberType>(len - static_cast<NumberType>(wanted));
        }
        return true;
    }

    /*!
    @param[in] context  further context information (for diagnostics)
    @return whether the last read character is not EOF
    */
    JSON_HEDLEY_NON_NULL(2)
    bool unexpect_eof(const char* context) const
    {
        if (JSON_HEDLEY_UNLIKELY(current == char_traits<char_type>::eof()))
        {
            return sax->parse_error(chars_read, "<end of file>",
                                    parse_error::create(110, chars_read, exception_message("unexpected end of input", context), nullptr));
        }
        return true;
    }

    /*!
    @return a string representation of the last read byte
    */
    std::string get_token_string() const
    {
        std::array<char, 3> cr{{}};
        static_cast<void>((std::snprintf)(cr.data(), cr.size(), "%.2hhX", static_cast<unsigned char>(current))); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        return std::string{cr.data()};
    }

    /*!
    @param[in] detail   a detailed error message
    @param[in] context  further context information
    @return a message string to use in the parse_error exceptions
    */
    std::string exception_message(const std::string& detail,
                                  const std::string& context) const
    {
        std::string error_msg = "syntax error while parsing ";

        switch (input_format)
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

            case input_format_t::bjdata:
                error_msg += "BJData";
                break;

            case input_format_t::bon8:
                error_msg += "BON8";
                break;

            case input_format_t::json: // LCOV_EXCL_LINE
            default:            // LCOV_EXCL_LINE
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
        }

        return concat(error_msg, ' ', context, ": ", detail);
    }

  private:
    static JSON_INLINE_VARIABLE constexpr std::size_t npos = detail::unknown_size();

    /// input adapter
    InputAdapterType ia;

    /// the current character
    char_int_type current = char_traits<char_type>::eof();

    /// the number of characters read
    std::size_t chars_read = 0;

    /// whether we can assume little endianness
    const bool is_little_endian = little_endianness();

    /// input format
    const input_format_t input_format = input_format_t::json;

    /// how to treat text strings/object keys that are not well-formed UTF-8
    const error_handler_t error_handler = error_handler_t::keep;

    /// the SAX parser
    json_sax_t* sax = nullptr;

    /// the containers that have been opened and not closed yet; see @ref container_frame
    std::vector<container_frame> container_stack{};

    /// BON8: bytes read past the end of a string, returned again by @ref get_bon8
    std::array<char_int_type, 2> bon8_pushback{{}};
    /// BON8: number of bytes in @ref bon8_pushback
    std::size_t bon8_pushback_size = 0;

  JSON_PRIVATE_UNLESS_TESTED:
    /*!
    @brief whether @a marker is excluded from BJData's optimized ND-array types
    @return whether @a marker is one of 'F', 'H', 'N', 'S', 'T', 'Z', '[', '{'

    Mirrors binary_writer's @ref binary_writer::is_bjdata_excluded_type_marker
    "is_bjdata_excluded_type_marker()`, which encodes the same list the other
    way; keep the two in sync.
    */
    static constexpr bool is_bjd_excluded_optimized_type(const char_int_type marker) noexcept
    {
        return marker == '[' || marker == '{' || marker == 'S' || marker == 'H'
               || marker == 'T' || marker == 'F' || marker == 'N' || marker == 'Z';
    }

    /*!
    @brief look up the ND-array element type name for a BJData dtype marker
    @return the type name ("uint8", "int8", ...), or nullptr if @a marker does
            not name a known dtype

    A C++11 `constexpr` function cannot contain a `switch`, so this is a
    plain (non-constexpr) switch instead.
    */
    static const char* bjd_type_name(const char_int_type marker)
    {
        switch (marker)
        {
            case 'B':
                return "byte";
            case 'C':
                return "char";
            case 'D':
                return "double";
            case 'I':
                return "int16";
            case 'L':
                return "int64";
            case 'M':
                return "uint64";
            case 'U':
                return "uint8";
            case 'd':
                return "single";
            case 'i':
                return "int8";
            case 'l':
                return "int32";
            case 'm':
                return "uint32";
            case 'u':
                return "uint16";
            default:
                return nullptr;
        }
    }
};

#ifndef JSON_HAS_CPP_17
    template<typename BasicJsonType, typename InputAdapterType, typename SAX>
    constexpr std::size_t binary_reader<BasicJsonType, InputAdapterType, SAX>::npos;
#endif

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
