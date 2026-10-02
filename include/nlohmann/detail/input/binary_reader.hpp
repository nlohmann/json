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

@tparam AllowRecovery  whether the SAX parser may ask to recover from errors by
        returning true from parse_error() (see #3989). The functions that read
        into a JSON value use false, because their SAX parsers never do, and
        then the code that recovers is not compiled.
*/
template<typename BasicJsonType, typename InputAdapterType, typename SAX = json_sax_dom_parser<BasicJsonType, InputAdapterType>, bool AllowRecovery = false>
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
    /// the result of @ref report_repairable_error, which is always false if
    /// the code that recovers is not compiled
    using repair_t = typename std::conditional<AllowRecovery, bool, std::false_type>::type;

    /// whether the input is a contiguous block of bytes that can be inspected
    /// and consumed in bulk (as in the lexer); used by @ref get_bon8_string_bulk
    static constexpr bool bulk_scan =
        input_adapter_supports_bulk_scan<InputAdapterType>(is_detected<detect_supports_bulk_scan, InputAdapterType> {});

  public:
    /*!
    @brief create a binary reader

    @param[in] adapter  input adapter to read from
    */
    explicit binary_reader(InputAdapterType&& adapter, const input_format_t format = input_format_t::json) noexcept : ia(std::move(adapter)), input_format(format)
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

    @return whether parsing was successful: the input was read without errors,
            and no SAX event returned false
    */
    JSON_HEDLEY_NON_NULL(2)
    bool sax_parse(json_sax_t* sax_,
                   const bool strict = true,
                   const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error)
    {
        sax = sax_;
        container_stack.clear();
        bon8_pushback_size = 0;
        close_requested = false;
        error_repaired = false;
        key_pending = false;
        skip_requested = false;
        ndarray_open = 0;
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
                return report_error(chars_read, get_token_string(), parse_error::create(110, chars_read,
                                    exception_message(input_format, concat("expected end of input; last byte: 0x", get_token_string()), "value"), nullptr));
            }
        }

        if (!result)
        {
            close_open_containers(std::integral_constant<bool, AllowRecovery> {});
        }

        return result && !error_repaired;
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

    When recovering from errors, a document whose size does not match is
    accepted: its terminator was found, so everything in it has been read.

    @param[in] document_start  value of chars_read before the size prefix
    @param[in] document_size   the declared document size
    @return whether the declared size matches the number of bytes read, or
            the mismatch is repaired
    */
    bool check_bson_document_size(const std::size_t document_start, const std::int32_t document_size)
    {
        if (JSON_HEDLEY_UNLIKELY(document_size < 0 || static_cast<std::size_t>(document_size) != chars_read - document_start))
        {
            return report_repairable_error(chars_read, get_token_string(), parse_error::create(112, chars_read,
                                           exception_message(input_format_t::bson, concat("document size ", std::to_string(document_size), " does not match the number of bytes read (", std::to_string(chars_read - document_start), ")"), "document"), nullptr));
        }
        return true;
    }

    /*!
    @brief whether the rest of the innermost BSON document can be skipped

    A BSON document declares its size, so the reader can continue after it
    even if an element in it cannot be read. This requires a size that ends
    the document after the current position.
    */
    bool can_skip_to_bson_document_end() const noexcept
    {
        const container_frame& top = container_stack.back();
        return top.declared_size >= 5 && top.start_position + static_cast<std::size_t>(top.declared_size) - 1 >= chars_read;
    }

    /*!
    @brief report an error that loses the end of a BSON element

    If the rest of the document can be skipped, the error is repairable, and
    the SAX parser asks to recover, the reading loop passes null for the
    element and skips to the end of the document (see @ref
    skip_to_bson_document_end). Otherwise, reading stops.

    @return false, so that the caller stops reading the element
    */
    template<typename Exception>
    bool report_bson_element_error(const std::size_t position, const std::string& last_token, const Exception& ex)
    {
        if (report_error_repairable_if(can_skip_to_bson_document_end(), position, last_token, ex))
        {
            skip_requested = true;
        }
        return false;
    }

    /// the code that recovers is not compiled: stop
    std::false_type skip_to_bson_document_end(std::false_type /*allow_recovery*/) const noexcept
    {
        return {};
    }

    /*!
    @brief skip the rest of a BSON document after an element that could not be
           read

    Called after reading an element failed. If @ref report_bson_element_error
    asked for it, passes null for the element and skips to the document's
    terminator, which the reading loop reads next. The elements after the one
    that could not be read are lost.

    @return whether reading continues
    */
    bool skip_to_bson_document_end(std::true_type /*allow_recovery*/)
    {
        if (!skip_requested)
        {
            return false;
        }
        skip_requested = false;

        const container_frame& top = container_stack.back();
        const std::size_t terminator = top.start_position + static_cast<std::size_t>(top.declared_size) - 1;
        return skip_bytes(terminator - chars_read, "document") && sax->null();
    }

    /*!
    @brief report a BSON element of a type the library does not read

    The BSON specification defines the size of the value of every element
    type, so when recovering, the value is skipped and null passed instead. A
    type the specification does not define, or a string length that cannot be
    right, loses the end of the element (see @ref report_bson_element_error).

    @param[in] element_type  the element's type
    @param[in] element_type_parse_position  where the type was read
    @return whether the value was skipped and null passed instead
    */
    bool skip_unsupported_bson_element(const char_int_type element_type, const std::size_t element_type_parse_position)
    {
        // the type as two uppercase hexadecimal digits, without a format string
        const auto type_byte = static_cast<unsigned int>(static_cast<unsigned char>(element_type));
        const auto hex_digit = [](const unsigned int digit)
        {
            return static_cast<char>(digit < 10 ? '0' + digit : 'A' + (digit - 10));
        };
        const std::string cr_str{hex_digit(type_byte >> 4u), hex_digit(type_byte & 0x0Fu)};
        const auto error = parse_error::create(114, element_type_parse_position, concat("Unsupported BSON record type 0x", cr_str), nullptr);

        // the number of bytes to skip, -1 if the value is read differently, or
        // -2 if the type is unknown
        std::int64_t size = -1;
        switch (element_type)
        {
            case 0x06: // undefined (deprecated)
            case 0x7F: // max key
            case 0xFF: // min key
                size = 0;
                break;

            case 0x07: // ObjectId
                size = 12;
                break;

            case 0x09: // UTC datetime
                size = 8;
                break;

            case 0x13: // 128-bit decimal floating point
                size = 16;
                break;

            case 0x0B: // regular expression: two C strings
            case 0x0C: // DBPointer (deprecated): string and 12 bytes
            case 0x0D: // JavaScript code: string
            case 0x0E: // symbol (deprecated): string
            case 0x0F: // JavaScript code with scope: size of it all, string, document
                break;

            default:
                size = -2;
                break;
        }

        // an element of an unknown type loses its end, like the elements
        // reported with report_bson_element_error
        const bool known = size != -2;
        if (!report_error_repairable_if(known || can_skip_to_bson_document_end(), element_type_parse_position, cr_str, error))
        {
            return false;
        }
        if (!known)
        {
            skip_requested = true;
            return false;
        }

        if (element_type == 0x0B)
        {
            string_t ignored;
            return get_bson_cstr(ignored) && get_bson_cstr(ignored) && sax->null();
        }

        if (size < 0)
        {
            std::int32_t len{};
            if (!get_number<std::int32_t, true>(input_format_t::bson, len))
            {
                return false;
            }
            // the size of code with scope counts the size itself
            size = (element_type == 0x0F) ? static_cast<std::int64_t>(len) - 4 : len;
            if (element_type == 0x0C)
            {
                size += 12;
            }
            if (JSON_HEDLEY_UNLIKELY(size < 0 || (element_type != 0x0F && len < 1)))
            {
                // already reported: skip to the end of the document if that
                // is possible, or stop
                if (!can_skip_to_bson_document_end())
                {
                    close_requested = true;
                    return false;
                }
                skip_requested = true;
                return false;
            }
        }

        return skip_bytes(static_cast<std::uint64_t>(size), "value") && sax->null();
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
        if (!get_number<std::int32_t, true>(input_format_t::bson, document_size))
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

            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::bson, "element list")))
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
                if (!skip_to_bson_document_end(std::integral_constant<bool, AllowRecovery> {}))
                {
                    return value_failed();
                }
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
            return true;
        }

        auto out = std::back_inserter(result);
        while (true)
        {
            get();
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::bson, "cstring")))
            {
                return false;
            }
            if (current == 0x00)
            {
                return true;
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
            return report_bson_element_error(chars_read, last_token, parse_error::create(112, chars_read,
                                             exception_message(input_format_t::bson, concat("string length must be at least 1, is ", std::to_string(len)), "string"), nullptr));
        }

        if (JSON_HEDLEY_UNLIKELY(!get_string(input_format_t::bson, len - static_cast<NumberType>(1), result)))
        {
            return false;
        }

        if (JSON_HEDLEY_UNLIKELY(get() != 0x00))
        {
            // when recovering, a byte in place of the terminator is dropped;
            // the end of the input is not
            auto last_token = get_token_string();
            return report_error_repairable_if(current != char_traits<char_type>::eof(), chars_read, last_token, parse_error::create(112, chars_read,
                                              exception_message(input_format_t::bson,
                                                      "BSON string is not null-terminated",
                                                      "string"), nullptr));
        }

        return true;
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
            return report_bson_element_error(chars_read, last_token, parse_error::create(112, chars_read,
                                             exception_message(input_format_t::bson, concat("byte array length cannot be negative, is ", std::to_string(len)), "binary"), nullptr));
        }

        // All BSON binary values have a subtype
        std::uint8_t subtype{};
        if (JSON_HEDLEY_UNLIKELY(!get_number<std::uint8_t>(input_format_t::bson, subtype)))
        {
            return false;
        }
        result.set_subtype(subtype);

        return get_binary(input_format_t::bson, len, result);
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
                return get_number<double, true>(input_format_t::bson, number) && sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0x02: // string
            {
                std::int32_t len{};
                string_t value;
                return get_number<std::int32_t, true>(input_format_t::bson, len) && get_bson_string(len, value) && sax->string(value);
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
                return get_number<std::int32_t, true>(input_format_t::bson, len) && get_bson_binary(len, value) && sax->binary(value);
            }

            case 0x08: // boolean
            {
                std::uint8_t value{};
                return get_number<std::uint8_t>(input_format_t::bson, value) && sax->boolean(value != 0);
            }

            case 0x0A: // null
            {
                return sax->null();
            }

            case 0x10: // int32
            {
                std::int32_t value{};
                return get_number<std::int32_t, true>(input_format_t::bson, value) && sax->number_integer(conditional_static_cast<number_integer_t>(value));
            }

            case 0x12: // int64
            {
                std::int64_t value{};
                return get_number<std::int64_t, true>(input_format_t::bson, value) && sax->number_integer(conditional_static_cast<number_integer_t>(value));
            }

            case 0x11: // uint64
            {
                std::uint64_t value{};
                return get_number<std::uint64_t, true>(input_format_t::bson, value) && sax->number_unsigned(value);
            }

            default: // anything else is not supported (yet)
                return skip_unsupported_bson_element(element_type, element_type_parse_position);
        }
    }

    //////////
    // CBOR //
    //////////

    template<typename NumberType>
    bool get_cbor_negative_integer()
    {
        NumberType number{};
        if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, number)))
        {
            return false;
        }
        const auto max_val = static_cast<NumberType>((std::numeric_limits<number_integer_t>::max)());
        if (number > max_val)
        {
            if (!report_repairable_error(chars_read, get_token_string(),
                                         parse_error::create(112, chars_read,
                                                 exception_message(input_format_t::cbor, "negative integer overflow", "value"), nullptr)))
            {
                return false;
            }
            // too small for number_integer_t: pass the nearest floating-point number
            return sax->number_float(static_cast<number_float_t>(-1) - static_cast<number_float_t>(number), "");
        }
        return sax->number_integer(conditional_static_cast<number_integer_t>(static_cast<number_integer_t>(-1) - static_cast<number_integer_t>(number)));
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
                std::uint8_t number{};
                return get_number(input_format_t::cbor, number) && sax->number_unsigned(number);
            }

            case 0x19: // Unsigned integer (two-byte uint16_t follows)
            {
                std::uint16_t number{};
                return get_number(input_format_t::cbor, number) && sax->number_unsigned(number);
            }

            case 0x1A: // Unsigned integer (four-byte uint32_t follows)
            {
                std::uint32_t number{};
                return get_number(input_format_t::cbor, number) && sax->number_unsigned(number);
            }

            case 0x1B: // Unsigned integer (eight-byte uint64_t follows)
            {
                std::uint64_t number{};
                return get_number(input_format_t::cbor, number) && sax->number_unsigned(number);
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
                    if (!report_repairable_error(chars_read, last_token, parse_error::create(112, chars_read,
                                                 exception_message(input_format_t::cbor, concat("invalid byte: 0x", last_token), "value"), nullptr)))
                    {
                        return false;
                    }
                    // when recovering, the tag is ignored, as RFC 8949,
                    // Section 6.1 suggests for converting to JSON
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
                        if (!report_repairable_error(chars_read, last_token, parse_error::create(112, chars_read,
                                                     exception_message(input_format_t::cbor, concat("invalid byte: 0x", last_token), "value"), nullptr)))
                        {
                            return false;
                        }
                        // when recovering, the tag is ignored, as RFC 8949,
                        // Section 6.1 suggests for converting to JSON
                        return parse_cbor_value(false, cbor_tag_handler_t::ignore, tag_pending, item_read);
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
                return get_half_float(input_format_t::cbor, false);

            case 0xFA: // Single-Precision Float (four-byte IEEE 754)
            {
                float number{};
                return get_number(input_format_t::cbor, number) && sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xFB: // Double-Precision Float (eight-byte IEEE 754)
            {
                double number{};
                return get_number(input_format_t::cbor, number) && sax->number_float(static_cast<number_float_t>(number), "");
            }

            default: // anything else (0xFF is handled inside the other types)
            {
                auto last_token = get_token_string();
                // the simple values other than false, true, and null (0xE0..0xF3,
                // 0xF7 for undefined, and 0xF8 followed by a byte) are complete
                const bool simple_value = (current >= 0xE0 && current <= 0xF3) || current == 0xF7 || current == 0xF8;
                if (!report_error_repairable_if(simple_value, chars_read, last_token, parse_error::create(112, chars_read,
                                                exception_message(input_format_t::cbor, concat("invalid byte: 0x", last_token), "value"), nullptr)))
                {
                    return false;
                }
                // when recovering, a simple value becomes null, as RFC 8949,
                // Section 6.1 suggests for converting to JSON
                std::uint8_t ignored{};
                return (current != 0xF8 || get_number(input_format_t::cbor, ignored)) && sax->null();
            }
        }
    }

    /*!
    @brief reads a definite-length CBOR string

    Reads everything @ref get_cbor_string accepts except the indefinite-length
    form, which that function handles itself. The bytes are appended to @a
    result, so consecutive chunks of an indefinite-length string can be read
    into the same string.

    @param[out] result  string the bytes are appended to

    @return whether string creation completed

    @pre @a current is not EOF
    */
    bool get_cbor_string_chunk(string_t& result)
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
                return get_string(input_format_t::cbor, static_cast<unsigned int>(current) & 0x1Fu, result);
            }

            case 0x78: // UTF-8 string (one-byte uint8_t for n follows)
            {
                std::uint8_t len{};
                return get_number(input_format_t::cbor, len) && get_string(input_format_t::cbor, len, result);
            }

            case 0x79: // UTF-8 string (two-byte uint16_t for n follow)
            {
                std::uint16_t len{};
                return get_number(input_format_t::cbor, len) && get_string(input_format_t::cbor, len, result);
            }

            case 0x7A: // UTF-8 string (four-byte uint32_t for n follow)
            {
                std::uint32_t len{};
                return get_number(input_format_t::cbor, len) && get_string(input_format_t::cbor, len, result);
            }

            case 0x7B: // UTF-8 string (eight-byte uint64_t for n follow)
            {
                std::uint64_t len{};
                return get_number(input_format_t::cbor, len) && get_string(input_format_t::cbor, len, result);
            }

            default:
            {
                auto last_token = get_token_string();
                return report_error(chars_read, last_token, parse_error::create(113, chars_read,
                                    exception_message(input_format_t::cbor, concat("expected length specification (0x60-0x7B) or indefinite string type (0x7F); last byte: 0x", last_token), "string"), nullptr));
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
        // number of indefinite-length strings that have been opened and not
        // closed yet. RFC 8949, Section 3.2.3 does not permit nesting them,
        // but this reader has always accepted it, so the open levels are
        // counted instead of recursed through, which overflowed the stack for
        // an input of repeated 0x7F bytes (see #5104). Every chunk is appended
        // to the same result, so no per-level state is needed.
        std::size_t open = 0;

        while (true)
        {
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::cbor, "string")))
            {
                return false;
            }

            if (current == 0x7F) // UTF-8 string (indefinite length)
            {
                ++open;
                get();
                continue;
            }

            // a break marker closes the innermost indefinite-length string;
            // outside of one it is not a string and falls through to the error
            if (open != 0 && current == 0xFF)
            {
                if (--open == 0)
                {
                    return true;
                }
                get();
                continue;
            }

            if (JSON_HEDLEY_UNLIKELY(!get_cbor_string_chunk(result)))
            {
                return false;
            }

            if (open == 0)
            {
                return true;
            }

            get();
        }
    }

    /*!
    @brief reads a CBOR object key

    RFC 8949 allows any data item as a map key, but only strings have a
    counterpart in JSON. A key of any other type is rejected with a message
    naming that type, rather than the one @ref get_cbor_string gives for a
    malformed string. When recovering, a key that is a complete item is
    skipped with its value (see @ref skip_member).

    @param[out] result  created key

    @return whether key creation completed
    */
    bool get_cbor_object_key(string_t& result)
    {
        // EOF and major type 3 (text string) are left to get_cbor_string
        if (current == char_traits<char_type>::eof() || (static_cast<unsigned int>(current) & 0xE0u) == 0x60u)
        {
            return get_cbor_string(result);
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

        // a break stop code or a reserved byte begins no item that could be
        // skipped
        auto last_token = get_token_string();
        if (report_error_repairable_if(is_cbor_item_head(current), chars_read, last_token, parse_error::create(113, chars_read,
                                       exception_message(input_format_t::cbor, concat("only string keys are supported, but found ", found, "; last byte: 0x", last_token), "object key"), nullptr)))
        {
            skip_requested = true;
        }
        return false;
    }

    /*!
    @brief reads a definite-length CBOR byte array

    Reads everything @ref get_cbor_binary accepts except the indefinite-length
    form, which that function handles itself. The bytes are appended to @a
    result, so consecutive chunks of an indefinite-length byte array can be
    read into the same byte array.

    @param[out] result  byte array the bytes are appended to

    @return whether byte array creation completed

    @pre @a current is not EOF
    */
    bool get_cbor_binary_chunk(binary_t& result)
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
                return get_binary(input_format_t::cbor, static_cast<unsigned int>(current) & 0x1Fu, result);
            }

            case 0x58: // Binary data (one-byte uint8_t for n follows)
            {
                std::uint8_t len{};
                return get_number(input_format_t::cbor, len) &&
                       get_binary(input_format_t::cbor, len, result);
            }

            case 0x59: // Binary data (two-byte uint16_t for n follow)
            {
                std::uint16_t len{};
                return get_number(input_format_t::cbor, len) &&
                       get_binary(input_format_t::cbor, len, result);
            }

            case 0x5A: // Binary data (four-byte uint32_t for n follow)
            {
                std::uint32_t len{};
                return get_number(input_format_t::cbor, len) &&
                       get_binary(input_format_t::cbor, len, result);
            }

            case 0x5B: // Binary data (eight-byte uint64_t for n follow)
            {
                std::uint64_t len{};
                return get_number(input_format_t::cbor, len) &&
                       get_binary(input_format_t::cbor, len, result);
            }

            default:
            {
                auto last_token = get_token_string();
                return report_error(chars_read, last_token, parse_error::create(113, chars_read,
                                    exception_message(input_format_t::cbor, concat("expected length specification (0x40-0x5B) or indefinite binary array type (0x5F); last byte: 0x", last_token), "binary"), nullptr));
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
        // the open indefinite-length byte arrays are counted rather than
        // recursed through, for the reason given in @ref get_cbor_string
        std::size_t open = 0;

        while (true)
        {
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::cbor, "binary")))
            {
                return false;
            }

            if (current == 0x5F) // Binary data (indefinite length)
            {
                ++open;
                get();
                continue;
            }

            // a break marker closes the innermost indefinite-length byte
            // array; outside of one it falls through to the error below
            if (open != 0 && current == 0xFF)
            {
                if (--open == 0)
                {
                    return true;
                }
                get();
                continue;
            }

            if (JSON_HEDLEY_UNLIKELY(!get_cbor_binary_chunk(result)))
            {
                return false;
            }

            if (open == 0)
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
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, n)))
                {
                    return false;
                }
                value = n;
                return true;
            }

            case 0x19: // 2 bytes
            {
                std::uint16_t n{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, n)))
                {
                    return false;
                }
                value = n;
                return true;
            }

            case 0x1A: // 4 bytes
            {
                std::uint32_t n{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, n)))
                {
                    return false;
                }
                value = n;
                return true;
            }

            case 0x1B: // 8 bytes
            {
                std::uint64_t n{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, n)))
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
            return report_error(chars_read, get_token_string(), out_of_range::create(408,
                                exception_message(input_format_t::cbor, concat("excessive ", context, " size"), "size"), nullptr));
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
                    if (JSON_HEDLEY_UNLIKELY(!get_cbor_object_key(key)))
                    {
                        if (!skip_member(std::integral_constant<bool, AllowRecovery> {}))
                        {
                            return false;
                        }
                        continue;
                    }
                    if (JSON_HEDLEY_UNLIKELY(!sax->key(key)))
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
                    return value_failed();
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

    /*!
    @param[in] byte  a byte
    @return whether @a byte begins a well-formed CBOR data item (RFC 8949,
            Section 3): its additional information is not reserved, and the
            indefinite length is only used for strings, arrays, and maps
    */
    static bool is_cbor_item_head(const char_int_type byte) noexcept
    {
        const auto major_type = static_cast<unsigned int>(byte) >> 5u;
        const auto additional_information = static_cast<unsigned int>(byte) & 0x1Fu;
        if (additional_information < 28)
        {
            return true;
        }
        return additional_information == 31 && major_type >= 2 && major_type <= 5;
    }

    /*!
    @brief skip the head of a CBOR data item, and its content unless it holds
           other items (see @ref skip_items)

    @param[in] first  whether the item's first byte has been read
    @param[in] break_allowed  whether the item may be a break stop code, which
                              ends an indefinite-length item
    @param[out] children  the number of items nested in the item, or npos if
                          they end at a break stop code
    @param[out] is_break  whether the item was a break stop code

    @return whether the item was read
    */
    bool skip_cbor_item_head(const bool first, const bool break_allowed, std::size_t& children, bool& is_break)
    {
        if (!first)
        {
            get();
        }
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::cbor, "value")))
        {
            return false;
        }

        if (current == 0xFF && break_allowed)
        {
            is_break = true;
            return true;
        }

        if (JSON_HEDLEY_UNLIKELY(!is_cbor_item_head(current)))
        {
            auto last_token = get_token_string();
            return report_error(chars_read, last_token, parse_error::create(112, chars_read,
                                exception_message(input_format_t::cbor, concat("invalid byte: 0x", last_token), "value"), nullptr));
        }

        const auto major_type = static_cast<unsigned int>(current) >> 5u;
        std::uint64_t argument = static_cast<unsigned int>(current) & 0x1Fu;
        switch (argument)
        {
            case 24:
            {
                std::uint8_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, number)))
                {
                    return false;
                }
                argument = number;
                break;
            }

            case 25:
            {
                std::uint16_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, number)))
                {
                    return false;
                }
                argument = number;
                break;
            }

            case 26:
            {
                std::uint32_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, number)))
                {
                    return false;
                }
                argument = number;
                break;
            }

            case 27:
            {
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, argument)))
                {
                    return false;
                }
                break;
            }

            case 31: // indefinite length: chunks or elements until a break
                children = npos;
                return true;

            default:
                break;
        }

        switch (major_type)
        {
            case 2: // byte string
            case 3: // text string
                return skip_bytes(argument, major_type == 2 ? "binary" : "string");

            case 4: // array
                children = item_count(argument, false);
                return true;

            case 5: // map
                children = item_count(argument, true);
                return true;

            case 6: // tag: the tagged item follows
                children = 1;
                return true;

            default: // integers, simple values, and floats end with their argument
                return true;
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
                return get_number(input_format_t::msgpack, number) && sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xCB: // float 64
            {
                double number{};
                return get_number(input_format_t::msgpack, number) && sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xCC: // uint 8
            {
                std::uint8_t number{};
                return get_number(input_format_t::msgpack, number) && sax->number_unsigned(number);
            }

            case 0xCD: // uint 16
            {
                std::uint16_t number{};
                return get_number(input_format_t::msgpack, number) && sax->number_unsigned(number);
            }

            case 0xCE: // uint 32
            {
                std::uint32_t number{};
                return get_number(input_format_t::msgpack, number) && sax->number_unsigned(number);
            }

            case 0xCF: // uint 64
            {
                std::uint64_t number{};
                return get_number(input_format_t::msgpack, number) && sax->number_unsigned(number);
            }

            case 0xD0: // int 8
            {
                std::int8_t number{};
                return get_number(input_format_t::msgpack, number) && sax->number_integer(conditional_static_cast<number_integer_t>(number));
            }

            case 0xD1: // int 16
            {
                std::int16_t number{};
                return get_number(input_format_t::msgpack, number) && sax->number_integer(conditional_static_cast<number_integer_t>(number));
            }

            case 0xD2: // int 32
            {
                std::int32_t number{};
                return get_number(input_format_t::msgpack, number) && sax->number_integer(conditional_static_cast<number_integer_t>(number));
            }

            case 0xD3: // int 64
            {
                std::int64_t number{};
                return get_number(input_format_t::msgpack, number) && sax->number_integer(conditional_static_cast<number_integer_t>(number));
            }

            case 0xDC: // array 16
            {
                std::uint16_t len{};
                return get_number(input_format_t::msgpack, len) && enter_array(static_cast<std::size_t>(len));
            }

            case 0xDD: // array 32
            {
                std::uint32_t len{};
                return get_number(input_format_t::msgpack, len) && enter_array(conditional_static_cast<std::size_t>(len));
            }

            case 0xDE: // map 16
            {
                std::uint16_t len{};
                return get_number(input_format_t::msgpack, len) && enter_object(static_cast<std::size_t>(len));
            }

            case 0xDF: // map 32
            {
                std::uint32_t len{};
                return get_number(input_format_t::msgpack, len) && enter_object(conditional_static_cast<std::size_t>(len));
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
                return report_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message(input_format_t::msgpack, concat("invalid byte: 0x", last_token), "value"), nullptr));
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
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::msgpack, "string")))
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
                std::uint8_t len{};
                return get_number(input_format_t::msgpack, len) && get_string(input_format_t::msgpack, len, result);
            }

            case 0xDA: // str 16
            {
                std::uint16_t len{};
                return get_number(input_format_t::msgpack, len) && get_string(input_format_t::msgpack, len, result);
            }

            case 0xDB: // str 32
            {
                std::uint32_t len{};
                return get_number(input_format_t::msgpack, len) && get_string(input_format_t::msgpack, len, result);
            }

            default:
            {
                auto last_token = get_token_string();
                return report_error(chars_read, last_token, parse_error::create(113, chars_read,
                                    exception_message(input_format_t::msgpack, concat("expected length specification (0xA0-0xBF, 0xD9-0xDB); last byte: 0x", last_token), "string"), nullptr));
            }
        }
    }

    /*!
    @brief reads a MessagePack object key

    The MessagePack specification allows any type as a map key, but only
    strings have a counterpart in JSON. A key of any other type is rejected
    with a message naming that type, rather than the one @ref
    get_msgpack_string gives for a malformed string. When recovering, the key
    is skipped with its value (see @ref skip_member).

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
                    return get_msgpack_string(result);
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
                    return get_msgpack_string(result);
                }
                break;
        }

        auto last_token = get_token_string();
        if (report_repairable_error(chars_read, last_token, parse_error::create(113, chars_read,
                                    exception_message(input_format_t::msgpack, concat("only string keys are supported, but found ", found, "; last byte: 0x", last_token), "object key"), nullptr)))
        {
            skip_requested = true;
        }
        return false;
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
                return get_number(input_format_t::msgpack, len) &&
                       get_binary(input_format_t::msgpack, len, result);
            }

            case 0xC5: // bin 16
            {
                std::uint16_t len{};
                return get_number(input_format_t::msgpack, len) &&
                       get_binary(input_format_t::msgpack, len, result);
            }

            case 0xC6: // bin 32
            {
                std::uint32_t len{};
                return get_number(input_format_t::msgpack, len) &&
                       get_binary(input_format_t::msgpack, len, result);
            }

            case 0xC7: // ext 8
            {
                std::uint8_t len{};
                std::int8_t subtype{};
                return get_number(input_format_t::msgpack, len) &&
                       get_number(input_format_t::msgpack, subtype) &&
                       get_binary(input_format_t::msgpack, len, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xC8: // ext 16
            {
                std::uint16_t len{};
                std::int8_t subtype{};
                return get_number(input_format_t::msgpack, len) &&
                       get_number(input_format_t::msgpack, subtype) &&
                       get_binary(input_format_t::msgpack, len, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xC9: // ext 32
            {
                std::uint32_t len{};
                std::int8_t subtype{};
                return get_number(input_format_t::msgpack, len) &&
                       get_number(input_format_t::msgpack, subtype) &&
                       get_binary(input_format_t::msgpack, len, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD4: // fixext 1
            {
                std::int8_t subtype{};
                return get_number(input_format_t::msgpack, subtype) &&
                       get_binary(input_format_t::msgpack, 1, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD5: // fixext 2
            {
                std::int8_t subtype{};
                return get_number(input_format_t::msgpack, subtype) &&
                       get_binary(input_format_t::msgpack, 2, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD6: // fixext 4
            {
                std::int8_t subtype{};
                return get_number(input_format_t::msgpack, subtype) &&
                       get_binary(input_format_t::msgpack, 4, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD7: // fixext 8
            {
                std::int8_t subtype{};
                return get_number(input_format_t::msgpack, subtype) &&
                       get_binary(input_format_t::msgpack, 8, result) &&
                       assign_and_return_true(subtype);
            }

            case 0xD8: // fixext 16
            {
                std::int8_t subtype{};
                return get_number(input_format_t::msgpack, subtype) &&
                       get_binary(input_format_t::msgpack, 16, result) &&
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
                    if (JSON_HEDLEY_UNLIKELY(!get_msgpack_object_key(key)))
                    {
                        if (!skip_member(std::integral_constant<bool, AllowRecovery> {}))
                        {
                            return false;
                        }
                        continue;
                    }
                    if (JSON_HEDLEY_UNLIKELY(!sax->key(key)))
                    {
                        return false;
                    }
                }
            }

            if (JSON_HEDLEY_UNLIKELY(!parse_msgpack_value()))
            {
                return value_failed();
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
    @brief skip the head of a MessagePack item, and its content unless it
           holds other items (see @ref skip_items)

    @param[in] first  whether the item's first byte has been read
    @param[out] children  the number of items nested in the item

    @return whether the item was read
    */
    bool skip_msgpack_item_head(const bool first, std::size_t& children)
    {
        if (!first)
        {
            get();
        }
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::msgpack, "value")))
        {
            return false;
        }

        // positive and negative fixint
        if (current <= 0x7F || current >= 0xE0)
        {
            return true;
        }

        // fixmap, fixarray, and fixstr
        if (current <= 0x8F)
        {
            children = item_count(static_cast<unsigned int>(current) & 0x0Fu, true);
            return true;
        }
        if (current <= 0x9F)
        {
            children = static_cast<unsigned int>(current) & 0x0Fu;
            return true;
        }
        if (current <= 0xBF)
        {
            return skip_bytes(static_cast<unsigned int>(current) & 0x1Fu, "string");
        }

        const auto head = current;
        const char* context = (head >= 0xD9) ? "string" : "binary";
        switch (head)
        {
            case 0xC0: // nil
            case 0xC2: // false
            case 0xC3: // true
                return true;

            case 0xC4: // bin 8
            case 0xC7: // ext 8
            case 0xD9: // str 8
            {
                std::uint8_t len{};
                return get_number(input_format_t::msgpack, len) && skip_bytes(len + (head == 0xC7 ? 1u : 0u), context);
            }

            case 0xC5: // bin 16
            case 0xC8: // ext 16
            case 0xDA: // str 16
            {
                std::uint16_t len{};
                return get_number(input_format_t::msgpack, len) && skip_bytes(len + (head == 0xC8 ? 1u : 0u), context);
            }

            case 0xC6: // bin 32
            case 0xC9: // ext 32
            case 0xDB: // str 32
            {
                std::uint32_t len{};
                return get_number(input_format_t::msgpack, len) && skip_bytes(static_cast<std::uint64_t>(len) + (head == 0xC9 ? 1u : 0u), context);
            }

            case 0xCC: // uint 8
            case 0xD0: // int 8
                return skip_bytes(1, "number");

            case 0xCD: // uint 16
            case 0xD1: // int 16
                return skip_bytes(2, "number");

            case 0xCA: // float 32
            case 0xCE: // uint 32
            case 0xD2: // int 32
                return skip_bytes(4, "number");

            case 0xCB: // float 64
            case 0xCF: // uint 64
            case 0xD3: // int 64
                return skip_bytes(8, "number");

            case 0xD4: // fixext 1
                return skip_bytes(2, "binary");

            case 0xD5: // fixext 2
                return skip_bytes(3, "binary");

            case 0xD6: // fixext 4
                return skip_bytes(5, "binary");

            case 0xD7: // fixext 8
                return skip_bytes(9, "binary");

            case 0xD8: // fixext 16
                return skip_bytes(17, "binary");

            case 0xDC: // array 16
            case 0xDE: // map 16
            {
                std::uint16_t len{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::msgpack, len)))
                {
                    return false;
                }
                children = item_count(len, head == 0xDE);
                return true;
            }

            case 0xDD: // array 32
            case 0xDF: // map 32
            {
                std::uint32_t len{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::msgpack, len)))
                {
                    return false;
                }
                children = item_count(len, head == 0xDF);
                return true;
            }

            default: // 0xC1, which is never used
            {
                auto last_token = get_token_string();
                return report_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message(input_format_t::msgpack, concat("invalid byte: 0x", last_token), "value"), nullptr));
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
                return value_failed();
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
                            if (JSON_HEDLEY_UNLIKELY(!get_ubjson_string(key) || !sax->key(key)))
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
                        if (JSON_HEDLEY_UNLIKELY(!get_ubjson_string(key, false) || !sax->key(key)))
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
            return report_error(chars_read, get_token_string(), parse_error::create(113, chars_read,
                                exception_message(input_format, "string length must not be negative", "string"), nullptr));
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
    bool get_ubjson_string(string_t& result, const bool get_char = true)
    {
        if (get_char)
        {
            // no get_ignore_noop() here: the byte read next must be a string
            // length type specification, and a no-op ('N') is not valid in
            // that position. No-ops at positions where a value may appear are
            // already consumed by the callers via get_ignore_noop().
            get();
        }

        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format, "value")))
        {
            return false;
        }

        switch (current)
        {
            case 'U':
            {
                std::uint8_t len{};
                return get_number(input_format, len) && get_string(input_format, len, result);
            }

            case 'i':
            {
                std::int8_t len{};
                return get_number(input_format, len) && check_ubjson_string_length(len) && get_string(input_format, len, result);
            }

            case 'I':
            {
                std::int16_t len{};
                return get_number(input_format, len) && check_ubjson_string_length(len) && get_string(input_format, len, result);
            }

            case 'l':
            {
                std::int32_t len{};
                return get_number(input_format, len) && check_ubjson_string_length(len) && get_string(input_format, len, result);
            }

            case 'L':
            {
                std::int64_t len{};
                return get_number(input_format, len) && check_ubjson_string_length(len) && get_string(input_format, len, result);
            }

            case 'u':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint16_t len{};
                return get_number(input_format, len) && get_string(input_format, len, result);
            }

            case 'm':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint32_t len{};
                return get_number(input_format, len) && get_string(input_format, len, result);
            }

            case 'M':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint64_t len{};
                return get_number(input_format, len) && get_string(input_format, len, result);
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
        return report_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format, message, "string"), nullptr));
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
        if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
        {
            return false;
        }
        if (JSON_HEDLEY_UNLIKELY(number < 0))
        {
            return report_error(chars_read, get_token_string(), parse_error::create(113, chars_read,
                                exception_message(input_format, "count in an optimized container must be positive", "size"), nullptr));
        }
        if (JSON_HEDLEY_UNLIKELY(!value_in_range_of<std::size_t>(number)))
        {
            return report_error(chars_read, get_token_string(), out_of_range::create(408,
                                exception_message(input_format, "integer value overflow", "size"), nullptr));
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

    @return whether size determination completed
    */
    bool get_ubjson_size_value(std::size_t& result, bool& is_ndarray, char_int_type prefix = 0)
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
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
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
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
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
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
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
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
                {
                    return false;
                }
                if (!value_in_range_of<std::size_t>(number))
                {
                    return report_error(chars_read, get_token_string(), out_of_range::create(408,
                                        exception_message(input_format, "integer value overflow", "size"), nullptr));
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
                    return report_error(chars_read, get_token_string(), parse_error::create(113, chars_read, exception_message(input_format, "ndarray dimensional vector is not allowed", "size"), nullptr));
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

                    string_t key = "_ArraySize_";
                    if (JSON_HEDLEY_UNLIKELY(!sax->start_object(3) || !sax->key(key) || !sax->start_array(dim.size())))
                    {
                        return false;
                    }
                    ndarray_open = 2;
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
                            return report_error(chars_read, get_token_string(), out_of_range::create(408, exception_message(input_format, "excessive ndarray size caused overflow", "size"), nullptr));
                        }
                        result *= i;
                        // the pre-check above already rules out result becoming 0
                        // by overflow; the only value it cannot rule out is an
                        // exact match with npos, the sentinel reserved for an
                        // unknown-size container (see get_ubjson_size_type())
                        if (result == npos)
                        {
                            return report_error(chars_read, get_token_string(), out_of_range::create(408, exception_message(input_format, "excessive ndarray size caused overflow", "size"), nullptr));
                        }
                        if (JSON_HEDLEY_UNLIKELY(!sax->number_unsigned(static_cast<number_unsigned_t>(i))))
                        {
                            return false;
                        }
                    }
                    is_ndarray = true;
                    ndarray_open = 1;
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
        return report_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format, message, "size"), nullptr));
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
                return report_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message(input_format, concat("marker 0x", last_token, " is not a permitted optimized array type"), "type"), nullptr));
            }

            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format, "type")))
            {
                return false;
            }

            get_ignore_noop();
            if (JSON_HEDLEY_UNLIKELY(current != '#'))
            {
                if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format, "value")))
                {
                    return false;
                }
                auto last_token = get_token_string();
                return report_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message(input_format, concat("expected '#' after type information; last byte: 0x", last_token), "size"), nullptr));
            }

            const bool is_error = get_ubjson_size_value(result.first, is_ndarray);
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
                return report_error(chars_read, get_token_string(), parse_error::create(112, chars_read,
                                    exception_message(input_format, "ndarray requires both type and size", "size"), nullptr));
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
                return unexpect_eof(input_format, "value");

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
                return get_number(input_format, number) && sax->number_unsigned(number);
            }

            case 'U':
            {
                std::uint8_t number{};
                return get_number(input_format, number) && sax->number_unsigned(number);
            }

            case 'i':
            {
                std::int8_t number{};
                return get_number(input_format, number) && sax->number_integer(conditional_static_cast<number_integer_t>(number));
            }

            case 'I':
            {
                std::int16_t number{};
                return get_number(input_format, number) && sax->number_integer(conditional_static_cast<number_integer_t>(number));
            }

            case 'l':
            {
                std::int32_t number{};
                return get_number(input_format, number) && sax->number_integer(conditional_static_cast<number_integer_t>(number));
            }

            case 'L':
            {
                std::int64_t number{};
                return get_number(input_format, number) && sax->number_integer(conditional_static_cast<number_integer_t>(number));
            }

            case 'u':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint16_t number{};
                return get_number(input_format, number) && sax->number_unsigned(number);
            }

            case 'm':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint32_t number{};
                return get_number(input_format, number) && sax->number_unsigned(number);
            }

            case 'M':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                std::uint64_t number{};
                return get_number(input_format, number) && sax->number_unsigned(number);
            }

            case 'h':
            {
                if (input_format != input_format_t::bjdata)
                {
                    break;
                }
                return get_half_float(input_format, true);
            }

            case 'd':
            {
                float number{};
                return get_number(input_format, number) && sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 'D':
            {
                double number{};
                return get_number(input_format, number) && sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 'H':
            {
                return get_ubjson_high_precision_number();
            }

            case 'C':  // char
            {
                get();
                if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format, "char")))
                {
                    return false;
                }
                if (JSON_HEDLEY_UNLIKELY(current > 127))
                {
                    auto last_token = get_token_string();
                    if (!report_repairable_error(chars_read, last_token, parse_error::create(113, chars_read,
                                                 exception_message(input_format, concat("byte after 'C' must be in range 0x00..0x7F; last byte: 0x", last_token), "char"), nullptr)))
                    {
                        return false;
                    }
                    // when recovering, the character becomes U+FFFD, as an
                    // invalid byte in a string does
                    string_t replacement;
                    append_replacement_character(replacement);
                    return sax->string(replacement);
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
        return report_error(chars_read, last_token, parse_error::create(112, chars_read, exception_message(input_format, "invalid byte: 0x" + last_token, "value"), nullptr));
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
            const char* type_name = bjd_type_name(size_and_type.second);
            string_t key = "_ArrayType_";
            if (JSON_HEDLEY_UNLIKELY(type_name == nullptr))
            {
                auto last_token = get_token_string();
                return report_error(chars_read, last_token, parse_error::create(112, chars_read,
                                    exception_message(input_format, "invalid byte: 0x" + last_token, "type"), nullptr));
            }

            string_t type = type_name; // sax->string() takes a reference
            if (JSON_HEDLEY_UNLIKELY(!sax->key(key) || !sax->string(type)))
            {
                return false;
            }

            if (size_and_type.second == 'C' || size_and_type.second == 'B')
            {
                size_and_type.second = 'U';
            }

            key = "_ArrayData_";
            if (JSON_HEDLEY_UNLIKELY(!sax->key(key) || !sax->start_array(size_and_type.first) ))
            {
                return false;
            }
            ndarray_open = 2;

            for (std::size_t i = 0; i < size_and_type.first; ++i)
            {
                if (JSON_HEDLEY_UNLIKELY(!get_ubjson_value(size_and_type.second)))
                {
                    return false;
                }
            }

            ndarray_open = 0;
            return (sax->end_array() && sax->end_object());
        }

        // If BJData type marker is 'B' decode as binary
        if (input_format == input_format_t::bjdata && size_and_type.first != npos && size_and_type.second == 'B')
        {
            binary_t result;
            return get_binary(input_format, size_and_type.first, result) && sax->binary(result);
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
                return report_error(chars_read, get_token_string(), out_of_range::create(408,
                                    exception_message(input_format, "excessive array size", "size"), nullptr));
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
            return report_error(chars_read, last_token, parse_error::create(112, chars_read,
                                exception_message(input_format, "BJData object does not support ND-array size in optimized format", "object"), nullptr));
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
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format, "number")))
            {
                return false;
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
            if (!report_repairable_error(chars_read, number_string, parse_error::create(115, chars_read,
                                         exception_message(input_format, concat("invalid number text: ", number_lexer.get_token_string()), "high-precision number"), nullptr)))
            {
                return false;
            }
            return recover_high_precision_number(number_vector);
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
                    // when recovering, the number is passed as infinity with
                    // its text, as it is in JSON text
                    if (!report_repairable_error(
                                chars_read,
                                number_string,
                                out_of_range::create(406, concat("number overflow parsing '", number_string, '\''), nullptr)))
                    {
                        return false;
                    }
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
                if (!report_repairable_error(chars_read, number_string, parse_error::create(115, chars_read,
                                             exception_message(input_format, concat("invalid number text: ", number_lexer.get_token_string()), "high-precision number"), nullptr)))
                {
                    return false;
                }
                return recover_high_precision_number(number_vector);
        }
    }

    /*!
    @brief pass what can be read of an invalid high-precision number

    Like the parser for JSON text when it recovers, keeps the longest beginning
    of the text that is a number, or passes null if there is none.

    @param[in] number_vector  the number's text
    @return whether the SAX parser accepted the value
    */
    bool recover_high_precision_number(const std::vector<char>& number_vector)
    {
        using ia_type = decltype(detail::input_adapter(number_vector));
        auto number_lexer = detail::lexer<BasicJsonType, ia_type>(detail::input_adapter(number_vector), false);
        using token_type = typename detail::lexer_base<BasicJsonType>::token_type;

        auto token = number_lexer.scan();
        if (token == token_type::parse_error)
        {
            token = number_lexer.recover_token();
        }

        switch (token)
        {
            case token_type::value_integer:
                return sax->number_integer(number_lexer.get_number_integer());
            case token_type::value_unsigned:
                return sax->number_unsigned(number_lexer.get_number_unsigned());
            case token_type::value_float:
                return sax->number_float(number_lexer.get_number_float(), number_lexer.get_string());
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
                return sax->null();
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
        return bon8_error_repairable_if(false, detail, context);
    }

    /*!
    @brief report a parse error at the last read byte that is repairable in
           some cases (see @ref report_error_repairable_if)

    @param[in] repairable  whether the error is repairable
    @param[in] detail      a detailed error message
    @param[in] context     further context information
    @return whether the caller repairs the error and reads on
    */
    repair_t bon8_error_repairable_if(const bool repairable, const std::string& detail, const char* context)
    {
        auto last_token = get_token_string();
        return report_error_repairable_if(repairable, chars_read, last_token, parse_error::create(112, chars_read,
                                          exception_message(input_format_t::bon8, concat(detail, ": 0x", last_token), context), nullptr));
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
                    if (JSON_HEDLEY_UNLIKELY(!get_bon8_key(key)))
                    {
                        if (!skip_member(std::integral_constant<bool, AllowRecovery> {}))
                        {
                            return false;
                        }
                        continue;
                    }
                    if (JSON_HEDLEY_UNLIKELY(!sax->key(key)))
                    {
                        return false;
                    }
                }
            }

            if (JSON_HEDLEY_UNLIKELY(!parse_bon8_value()))
            {
                return value_failed();
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
            return unexpect_eof(input_format_t::bon8, "value");
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
                return get_number(input_format_t::bon8, number) && emit_bon8_integer(number);
            }

            case 0x8D: // int64
            {
                std::int64_t number{};
                return get_number(input_format_t::bon8, number) && emit_bon8_integer(number);
            }

            case 0x8E: // binary32
            {
                float number{};
                return get_number(input_format_t::bon8, number) && sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0x8F: // binary64
            {
                double number{};
                return get_number(input_format_t::bon8, number) && sax->number_float(static_cast<number_float_t>(number), "");
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
    numbers, like the other binary formats do.

    @param[in] number  the integer
    @return whether the SAX parser accepted the value
    */
    bool emit_bon8_integer(const std::int64_t number)
    {
        if (number >= 0)
        {
            return sax->number_unsigned(static_cast<number_unsigned_t>(number));
        }
        return sax->number_integer(static_cast<number_integer_t>(number));
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
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::bon8, "number")))
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
                return unexpect_eof(input_format_t::bon8, "number");
            }
            value = (value << 8) | static_cast<std::int64_t>(current);
        }

        return negative ? sax->number_integer(static_cast<number_integer_t>(-(value + offset)))
               : sax->number_unsigned(static_cast<number_unsigned_t>(value + offset));
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
            return unexpect_eof(input_format_t::bon8, "key");
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
                return unexpect_eof(input_format_t::bon8, "key");
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

        // an end-of-container marker is no value; any other byte begins one,
        // and the member is skipped when recovering (see skip_member)
        if (bon8_error_repairable_if(byte != 0xFE, "expected a string; last byte", "key"))
        {
            skip_requested = true;
        }
        return false;
    }

    /*!
    @brief skip a BON8 value, except the elements of a container (see @ref
           skip_items)

    @param[in] first  whether the value's first byte has been read
    @param[in] end_allowed  whether the byte may be an end-of-container marker
    @param[out] children  the number of values nested in the value, or npos if
                          they end at an end-of-container marker
    @param[out] is_end  whether the byte was an end-of-container marker

    @return whether the value was read
    */
    bool skip_bon8_item_head(const bool first, const bool end_allowed, std::size_t& children, bool& is_end)
    {
        const auto byte = first ? current : get_bon8();

        if (byte == char_traits<char_type>::eof())
        {
            return unexpect_eof(input_format_t::bon8, "value");
        }

        if (byte == 0xFE && end_allowed)
        {
            is_end = true;
            return true;
        }

        // string: ASCII character
        if (byte <= 0x7F)
        {
            string_t ignored;
            unget_bon8(byte);
            return get_bon8_string(ignored);
        }

        // arrays and objects
        if (byte <= 0x84)
        {
            children = static_cast<std::size_t>(byte - 0x80);
            return true;
        }
        if (byte == 0x85 || byte == 0x8B)
        {
            children = npos;
            return true;
        }
        if (byte <= 0x8A)
        {
            children = item_count(static_cast<std::uint64_t>(byte - 0x86), true);
            return true;
        }

        switch (byte)
        {
            case 0x8C: // int32
            case 0x8E: // binary32
                return skip_bon8_bytes(4);

            case 0x8D: // int64
            case 0x8F: // binary64
                return skip_bon8_bytes(8);

            case 0xFE: // end of container where a value is expected
                return bon8_error("invalid byte", "value");

            default:
                break;
        }

        // integers 0..39 and -1..-10, and the values 0xF8..0xFD and 0xFF
        if (byte <= 0xC1 || byte >= 0xF8)
        {
            return true;
        }

        // 0xC2..0xF7: a UTF-8 lead byte begins a string if a continuation
        // byte follows and an integer of 2..4 bytes otherwise
        const auto second = get_bon8();
        if (is_bon8_continuation(second))
        {
            string_t ignored;
            unget_bon8(second);
            unget_bon8(byte);
            return get_bon8_string(ignored);
        }
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::bon8, "number")))
        {
            return false;
        }
        if (byte <= 0xDF)
        {
            return skip_bon8_bytes(0);
        }
        return skip_bon8_bytes((byte <= 0xEF) ? 1 : 2);
    }

    /*!
    @param[in] len  the number of bytes to skip
    @return whether the input had that many bytes
    */
    bool skip_bon8_bytes(int len)
    {
        for (; len != 0; --len)
        {
            if (JSON_HEDLEY_UNLIKELY(get_bon8() == char_traits<char_type>::eof()))
            {
                return unexpect_eof(input_format_t::bon8, "number");
            }
        }
        return true;
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
                return unexpect_eof(input_format_t::bon8, "string");
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
                return unexpect_eof(input_format_t::bon8, "string");
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
                    return unexpect_eof(input_format_t::bon8, "string");
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
    bool get_to(T& dest, const input_format_t format, const char* context)
    {
        // false positive: new_chars_read is read on the next lines
        // @infer-ignore DEAD_STORE
        auto new_chars_read = ia.get_elements(&dest);
        chars_read += new_chars_read;
        if (JSON_HEDLEY_UNLIKELY(new_chars_read < sizeof(T)))
        {
            // in case of failure, advance position by 1 to report the failing location
            ++chars_read;
            return report_error(chars_read, "<end of file>", parse_error::create(110, chars_read, exception_message(format, "unexpected end of input", context), nullptr));
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
    @param[in] format   the current format (for diagnostics)
    @param[out] result  number of type @a NumberType

    @return whether conversion completed

    @note This function needs to respect the system's endianness, because
          bytes in CBOR, MessagePack, UBJSON, and BON8 are stored in network
          order (big endian) and therefore need reordering on little endian
          systems. On the other hand, BSON and BJData use little endian and
          should reorder on big endian systems.
    */
    template<typename NumberType, bool InputIsLittleEndian = false>
    bool get_number(const input_format_t format, NumberType& result)
    {
        // read in the original format

        if (JSON_HEDLEY_UNLIKELY(!get_to(result, format, "number")))
        {
            return false;
        }
        if (is_little_endian != (InputIsLittleEndian || format == input_format_t::bjdata))
        {
            byte_swap(result);
        }
        return true;
    }

    /*!
    @brief read and decode an IEEE 754 half-precision (16-bit) float

    Used by CBOR (big endian) and BJData (little endian); the two formats
    only differ in the byte order of the two bytes that make up the half.

    @param[in] format       the current format (for diagnostics)
    @param[in] little_endian whether the two bytes are little endian (BJData)
                             or big endian (CBOR)

    @return whether reading and decoding succeeded
    */
    bool get_half_float(const input_format_t format, const bool little_endian)
    {
        const auto byte1_raw = get();
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(format, "number")))
        {
            return false;
        }
        const auto byte2_raw = get();
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(format, "number")))
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
        // get_bytes() appends to result, and CBOR indefinite-length strings
        // collect all their chunks in the same result; validating only the
        // newly read bytes keeps the check linear in the input size
        const std::size_t old_size = result.size();
        if (JSON_HEDLEY_UNLIKELY(!get_bytes(format, len, "string", result)))
        {
            return false;
        }

        // RFC 8949 (CBOR) §3.1 and the MessagePack/BSON/UBJSON specifications
        // all require text strings to be valid UTF-8; reject anything else
        // right here so malformed input is caught at decode time instead of
        // only surfacing later as a type_error.316 when the value is dumped
        // (which would defeat allow_exceptions=false / strict discarding).
        if (JSON_HEDLEY_UNLIKELY(!is_valid_utf8(result, old_size)))
        {
            if (!report_repairable_error(chars_read, get_token_string(),
                                         parse_error::create(113, chars_read,
                                                 exception_message(format, "invalid string: ill-formed UTF-8 byte", "string"), nullptr)))
            {
                return false;
            }
            // when recovering, each ill-formed sequence becomes U+FFFD, as it
            // does in JSON text
            replace_invalid_utf8(result, old_size);
        }

        return true;
    }

    /*!
    @brief create a byte array by reading bytes from the input

    @tparam NumberType the type of the number
    @param[in] format the current format (for diagnostics)
    @param[in] len number of bytes to read
    @param[out] result byte array created by reading @a len bytes

    @return whether byte array creation completed

    @note We can not reserve @a len bytes for the result, because @a len
          may be too large. Usually, @ref unexpect_eof() detects the end of
          the input before we run out of memory.
    */
    template<typename NumberType>
    bool get_binary(const input_format_t format,
                    const NumberType len,
                    binary_t& result)
    {
        return get_bytes(format, len, "binary", result);
    }

    /*!
    @brief read @a len bytes from the input into a string or byte container

    @tparam NumberType    the type of the length
    @tparam ContainerType the destination container (string_t or binary_t)
    @param[in] format   the current format (for diagnostics)
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
    bool get_bytes(const input_format_t format,
                   NumberType len,
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
                return unexpect_eof(format, context);
            }
            // a full chunk was read; get_elements() never returns more than requested
            JSON_ASSERT(bytes_read == wanted);
            len = static_cast<NumberType>(len - static_cast<NumberType>(wanted));
        }
        return true;
    }

    /*!
    @brief report an error after which the input cannot be read on

    After most errors, it is unknown where the item that was being read ends:
    the input ended, a byte is not a valid type marker, or a size cannot be
    right. The binary formats have no delimiters to find the next item by, so
    reading stops, whatever the SAX parser's parse_error() returns. If it asks
    to recover, the value read so far is completed before @ref sax_parse
    returns (see @ref close_open_containers and #3989).

    @return false, so that the caller stops reading
    */
    template<typename Exception>
    bool report_error(const std::size_t position, const std::string& last_token, const Exception& ex)
    {
        close_requested = sax->parse_error(position, last_token, ex);
        return false;
    }

    /*!
    @brief report an error in an item whose end is known

    Some items are complete, but cannot be passed on as they are: a CBOR tag or
    simple value, a string that is not valid UTF-8, a BSON element of a type
    the library does not read, or an object key that is not a string. If the
    SAX parser's parse_error() returns true, the caller replaces the item and
    reads on after it (RFC 8949, Section 5.3).

    @return whether the caller replaces the item and reads on
    */
    template<typename Exception>
    repair_t report_repairable_error(const std::size_t position, const std::string& last_token, const Exception& ex)
    {
        return accept_repair(sax->parse_error(position, last_token, ex), std::integral_constant<bool, AllowRecovery> {});
    }

    /// the code that recovers is not compiled: stop
    std::false_type accept_repair(const bool /*repair*/, std::false_type /*allow_recovery*/) const noexcept
    {
        return {};
    }

    /// remember that an error was repaired, so that @ref sax_parse returns false
    bool accept_repair(const bool repair, std::true_type /*allow_recovery*/) noexcept
    {
        error_repaired = error_repaired || repair;
        return repair;
    }

    /*!
    @brief report an error that is repairable in some cases

    Like @ref report_repairable_error if @a repairable is true, and like @ref
    report_error otherwise. If the code that recovers is not compiled, the
    error is reported in one place only.

    @return whether the caller repairs the item and reads on
    */
    template<typename Exception>
    repair_t report_error_repairable_if(const bool repairable, const std::size_t position, const std::string& last_token, const Exception& ex)
    {
        return report_error_repairable_if(repairable, position, last_token, ex, std::integral_constant<bool, AllowRecovery> {});
    }

    /// the code that recovers is not compiled: stop
    template<typename Exception>
    std::false_type report_error_repairable_if(const bool /*repairable*/, const std::size_t position, const std::string& last_token, const Exception& ex, std::false_type /*allow_recovery*/)
    {
        static_cast<void>(sax->parse_error(position, last_token, ex));
        return {};
    }

    /// report the error as repairable or not
    template<typename Exception>
    bool report_error_repairable_if(const bool repairable, const std::size_t position, const std::string& last_token, const Exception& ex, std::true_type /*allow_recovery*/)
    {
        return repairable ? report_repairable_error(position, last_token, ex) : report_error(position, last_token, ex);
    }

    /*!
    @brief stop after the value of an array element or object member could not
           be read

    A value that could not be read has passed no event, except the object that
    a BJData ndarray begins with, so the key of an object member still waits
    for its value; @ref close_open_containers passes null for it.

    @return false, so that the caller stops reading
    */
    bool value_failed() noexcept
    {
        return value_failed(std::integral_constant<bool, AllowRecovery> {});
    }

    /// the code that recovers is not compiled: nothing to remember
    std::false_type value_failed(std::false_type /*allow_recovery*/) const noexcept
    {
        return {};
    }

    /// remember whether a key waits for its value
    bool value_failed(std::true_type /*allow_recovery*/) noexcept
    {
        key_pending = !container_stack.empty() && container_stack.back().is_object && ndarray_open == 0;
        return false;
    }

    /// the code that recovers is not compiled: nothing to complete
    void close_open_containers(std::false_type /*allow_recovery*/) const noexcept {}

    /*!
    @brief complete the value read before an error

    Does nothing unless the SAX parser's parse_error() asked to recover from the
    error that stopped reading. Otherwise passes null for a key that waits for
    its value and closes the arrays and objects that are still open, innermost
    first, until an event returns false.
    */
    void close_open_containers(std::true_type /*allow_recovery*/)
    {
        if (!close_requested)
        {
            return;
        }

        if (key_pending && !sax->null())
        {
            return;
        }

        // the object of a BJData ndarray and the array inside it are not on
        // the stack, as their elements are always read in one go
        if (ndarray_open == 2 && !sax->end_array())
        {
            return;
        }
        if (ndarray_open != 0 && !sax->end_object())
        {
            return;
        }

        while (!container_stack.empty())
        {
            const bool is_object = container_stack.back().is_object;
            container_stack.pop_back();
            if (is_object ? !sax->end_object() : !sax->end_array())
            {
                return;
            }
        }
    }

    /// the code that recovers is not compiled: stop
    std::false_type skip_member(std::false_type /*allow_recovery*/) const noexcept
    {
        return {};
    }

    /*!
    @brief skip an object member whose key is not a string

    Called after reading a key failed. If the key is a complete item of another
    type, and the SAX parser asked to recover from the error, the key, whose
    first byte has been read, and the value after it are skipped, like the
    parser for JSON text skips a member without a key.

    @return whether the member was skipped and reading continues
    */
    bool skip_member(std::true_type /*allow_recovery*/)
    {
        if (!skip_requested)
        {
            return false;
        }
        skip_requested = false;
        return skip_items(2);
    }

    /*!
    @brief skip complete items without passing them to the SAX parser

    Reads the items with their nested items, keeping one count of items left to
    skip per nesting level, so that deeply nested items cost heap rather than
    native stack.

    @param[in] count  the number of items to skip; the first byte of the first
                      one has been read

    @return whether the items were skipped
    */
    bool skip_items(const std::size_t count)
    {
        // items left to skip on each level, or npos for a level that ends at
        // a marker
        std::vector<std::size_t> levels(1, count);
        bool first = true;

        while (!levels.empty())
        {
            if (levels.back() == 0)
            {
                levels.pop_back();
                continue;
            }

            // the number of items nested in the item, or npos if they end at
            // a marker
            std::size_t children = 0;
            bool end_marker = false;
            const bool marker_allowed = levels.back() == npos;
            switch (input_format)
            {
                case input_format_t::cbor:
                    if (!skip_cbor_item_head(first, marker_allowed, children, end_marker))
                    {
                        return false;
                    }
                    break;

                case input_format_t::msgpack:
                    if (!skip_msgpack_item_head(first, children))
                    {
                        return false;
                    }
                    break;

                case input_format_t::bon8:
                    if (!skip_bon8_item_head(first, marker_allowed, children, end_marker))
                    {
                        return false;
                    }
                    break;

                // the other formats have no object keys that are skipped
                case input_format_t::json:   // LCOV_EXCL_LINE
                case input_format_t::bson:   // LCOV_EXCL_LINE
                case input_format_t::ubjson: // LCOV_EXCL_LINE
                case input_format_t::bjdata: // LCOV_EXCL_LINE
                default:                     // LCOV_EXCL_LINE
                    JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
                    return false;       // LCOV_EXCL_LINE
            }
            first = false;

            if (end_marker)
            {
                levels.pop_back();
                continue;
            }

            if (levels.back() != npos)
            {
                --levels.back();
            }
            if (children != 0)
            {
                levels.push_back(children);
            }
        }

        return true;
    }

    /*!
    @brief the number of items a container of @a len elements holds

    @param[in] len    the declared number of elements
    @param[in] pairs  whether the container is an object, whose elements are
                      pairs of items
    @return the number of items, capped below npos, which marks a container
            that ends at a marker; the input ends before a capped count is
            reached
    */
    static std::size_t item_count(const std::uint64_t len, const bool pairs) noexcept
    {
        const std::uint64_t max_len = conditional_static_cast<std::uint64_t>(npos - 1) / (pairs ? 2u : 1u);
        const std::uint64_t capped = (len < max_len) ? len : max_len;
        return conditional_static_cast<std::size_t>(pairs ? 2 * capped : capped);
    }

    /*!
    @brief skip bytes of an item that is not passed on

    @param[in] len      the number of bytes to skip
    @param[in] context  further context information (for diagnostics)
    @return whether the input had that many bytes
    */
    bool skip_bytes(std::uint64_t len, const char* context)
    {
        for (; len != 0; --len)
        {
            get();
            if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format, context)))
            {
                return false;
            }
        }
        return true;
    }

    /*!
    @param[in] format   the current format (for diagnostics)
    @param[in] context  further context information (for diagnostics)
    @return whether the last read character is not EOF
    */
    JSON_HEDLEY_NON_NULL(3)
    bool unexpect_eof(const input_format_t format, const char* context)
    {
        if (JSON_HEDLEY_UNLIKELY(current == char_traits<char_type>::eof()))
        {
            return report_error(chars_read, "<end of file>",
                                parse_error::create(110, chars_read, exception_message(format, "unexpected end of input", context), nullptr));
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
    @param[in] format   the current format
    @param[in] detail   a detailed error message
    @param[in] context  further context information
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

    /// the SAX parser
    json_sax_t* sax = nullptr;

    /// the containers that have been opened and not closed yet; see @ref container_frame
    std::vector<container_frame> container_stack{};

    /// BON8: bytes read past the end of a string, returned again by @ref get_bon8
    std::array<char_int_type, 2> bon8_pushback{{}};
    /// BON8: number of bytes in @ref bon8_pushback
    std::size_t bon8_pushback_size = 0;

    /// whether the SAX parser asked to recover from the error that stopped
    /// reading, so that @ref close_open_containers completes the value
    bool close_requested = false;
    /// whether an error was repaired, so that @ref sax_parse returns false
    bool error_repaired = false;
    /// whether an object key waits for the value that could not be read
    bool key_pending = false;
    /// whether the item that could not be read is skipped: an object member
    /// whose key is not a string, or the rest of a BSON document
    bool skip_requested = false;
    /// BJData: the containers of an ndarray's annotated array format that are
    /// open: none, its object, or its object and an array inside it
    std::uint8_t ndarray_open = 0;

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
    template<typename BasicJsonType, typename InputAdapterType, typename SAX, bool AllowRecovery>
    constexpr std::size_t binary_reader<BasicJsonType, InputAdapterType, SAX, AllowRecovery>::npos;
#endif

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
