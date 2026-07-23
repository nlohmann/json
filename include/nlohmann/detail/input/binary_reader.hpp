//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // generate_n
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
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/is_sax.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>
#include <nlohmann/detail/string_concat.hpp>
#include <nlohmann/detail/value_t.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// how to treat CBOR tags
enum class cbor_tag_handler_t
{
    error,   ///< throw a parse_error exception in case of a tag
    ignore,  ///< ignore tags
    store    ///< store tags as binary type
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

///////////////////
// binary reader //
///////////////////

/*!
@brief deserialization of CBOR, MessagePack, and UBJSON values
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
    @param[in] format  the binary format to parse
    @param[in] sax_    a SAX event processor
    @param[in] strict  whether to expect the input to be consumed completed
    @param[in] tag_handler  how to treat CBOR tags

    @return whether parsing was successful
    */
    JSON_HEDLEY_NON_NULL(3)
    bool sax_parse(const input_format_t format,
                   json_sax_t* sax_,
                   const bool strict = true,
                   const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error)
    {
        sax = sax_;
        bool result = false;

        switch (format)
        {
            case input_format_t::bson:
                result = parse_bson_internal();
                break;

            case input_format_t::cbor:
                result = parse_cbor_internal(true, tag_handler);
                break;

            case input_format_t::msgpack:
                result = parse_msgpack_internal();
                break;

            case input_format_t::ubjson:
            case input_format_t::bjdata:
                result = parse_ubjson_internal();
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
            else
            {
                get();
            }

            if (JSON_HEDLEY_UNLIKELY(current != char_traits<char_type>::eof()))
            {
                return sax->parse_error(chars_read, get_token_string(), parse_error::create(110, chars_read,
                                        exception_message(input_format, concat("expected end of input; last byte: 0x", get_token_string()), "value"), nullptr));
            }
        }

        return result;
    }

  private:
    //////////
    // BSON //
    //////////

    /*!
    @brief a single pending "resume this document/array" entry used by the
           iterative container traversal in @ref parse_bson_internal; see
           @ref cbor_container_frame for the general idea.

    BSON documents and arrays share one on-the-wire layout (a size-prefixed,
    0x00-terminated list of typed elements); @ref is_object only controls
    whether each element's key is relayed to the SAX consumer via
    @c sax->key() (an object) or not (an array, whose "0", "1", ... keys the
    SAX array interface has no use for). Every BSON container is
    terminator-based (there is no known-element-count form), so unlike CBOR/
    MessagePack/UBJSON this frame needs no length/indefinite bookkeeping at
    all.
    */
    struct bson_container_frame
    {
        bool is_object; ///< false: array, true: object/document
    };

    /*!
    @brief Reads in a BSON-object and passes it to the SAX-parser.
    @return whether a valid BSON-value was passed to the SAX parser
    */
    bool parse_bson_internal()
    {
        std::vector<bson_container_frame> stack;

        // reads the 4-byte document-size prefix (its value is unused beyond
        // consuming those bytes, matching the pre-existing behavior) and
        // emits the corresponding SAX start_object()/start_array() event
        auto begin_document = [&](const bool is_object) -> bool
        {
            std::int32_t document_size{};
            get_number<std::int32_t, true>(input_format_t::bson, document_size);
            return is_object ? sax->start_object(detail::unknown_size()) : sax->start_array(detail::unknown_size());
        };

        if (JSON_HEDLEY_UNLIKELY(!begin_document(true)))
        {
            return false;
        }
        stack.push_back(bson_container_frame{true});

        while (true)
        {
            bson_container_frame& top = stack.back();

            const auto element_type = get();
            if (element_type == 0)
            {
                // 0x00 terminates the current document/array
                if (JSON_HEDLEY_UNLIKELY(!(top.is_object ? sax->end_object() : sax->end_array())))
                {
                    return false;
                }
                stack.pop_back();
                if (stack.empty())
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
            string_t key;
            if (JSON_HEDLEY_UNLIKELY(!get_bson_cstr(key)))
            {
                return false;
            }
            if (top.is_object && JSON_HEDLEY_UNLIKELY(!sax->key(key)))
            {
                return false;
            }

            switch (element_type)
            {
                case 0x01: // double
                {
                    double number{};
                    if (JSON_HEDLEY_UNLIKELY(!(get_number<double, true>(input_format_t::bson, number) && sax->number_float(static_cast<number_float_t>(number), ""))))
                    {
                        return false;
                    }
                    continue;
                }

                case 0x02: // string
                {
                    std::int32_t len{};
                    string_t value;
                    if (JSON_HEDLEY_UNLIKELY(!(get_number<std::int32_t, true>(input_format_t::bson, len) && get_bson_string(len, value) && sax->string(value))))
                    {
                        return false;
                    }
                    continue;
                }

                case 0x03: // object
                {
                    if (JSON_HEDLEY_UNLIKELY(!begin_document(true)))
                    {
                        return false;
                    }
                    if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
                    {
                        return sax->parse_error(chars_read, get_token_string(),
                                                parse_error::create(116, chars_read,
                                                        exception_message(input_format_t::bson, "maximum depth of nested objects/arrays exceeded", "value"), nullptr));
                    }
                    stack.push_back(bson_container_frame{true});
                    continue;
                }

                case 0x04: // array
                {
                    if (JSON_HEDLEY_UNLIKELY(!begin_document(false)))
                    {
                        return false;
                    }
                    if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
                    {
                        return sax->parse_error(chars_read, get_token_string(),
                                                parse_error::create(116, chars_read,
                                                        exception_message(input_format_t::bson, "maximum depth of nested objects/arrays exceeded", "value"), nullptr));
                    }
                    stack.push_back(bson_container_frame{false});
                    continue;
                }

                case 0x05: // binary
                {
                    std::int32_t len{};
                    binary_t value;
                    if (JSON_HEDLEY_UNLIKELY(!(get_number<std::int32_t, true>(input_format_t::bson, len) && get_bson_binary(len, value) && sax->binary(value))))
                    {
                        return false;
                    }
                    continue;
                }

                case 0x08: // boolean
                    if (JSON_HEDLEY_UNLIKELY(!sax->boolean(get() != 0)))
                    {
                        return false;
                    }
                    continue;

                case 0x0A: // null
                    if (JSON_HEDLEY_UNLIKELY(!sax->null()))
                    {
                        return false;
                    }
                    continue;

                case 0x10: // int32
                {
                    std::int32_t value{};
                    if (JSON_HEDLEY_UNLIKELY(!(get_number<std::int32_t, true>(input_format_t::bson, value) && sax->number_integer(value))))
                    {
                        return false;
                    }
                    continue;
                }

                case 0x12: // int64
                {
                    std::int64_t value{};
                    if (JSON_HEDLEY_UNLIKELY(!(get_number<std::int64_t, true>(input_format_t::bson, value) && sax->number_integer(value))))
                    {
                        return false;
                    }
                    continue;
                }

                case 0x11: // uint64
                {
                    std::uint64_t value{};
                    if (JSON_HEDLEY_UNLIKELY(!(get_number<std::uint64_t, true>(input_format_t::bson, value) && sax->number_unsigned(value))))
                    {
                        return false;
                    }
                    continue;
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
    }

    /*!
    @brief Parses a C-style string from the BSON input.
    @param[in,out] result  A reference to the string variable where the read
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
                                    exception_message(input_format_t::bson, concat("string length must be at least 1, is ", std::to_string(len)), "string"), nullptr));
        }

        return get_string(input_format_t::bson, len - static_cast<NumberType>(1), result) && get() != char_traits<char_type>::eof();
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
                                    exception_message(input_format_t::bson, concat("byte array length cannot be negative, is ", std::to_string(len)), "binary"), nullptr));
        }

        // All BSON binary values have a subtype
        std::uint8_t subtype{};
        get_number<std::uint8_t>(input_format_t::bson, subtype);
        result.set_subtype(subtype);

        return get_binary(input_format_t::bson, len, result);
    }

    //////////
    // CBOR //
    //////////

    /*!
    @param[in] get_char  whether a new character should be retrieved from the
                         input (true) or whether the last read character should
                         be considered instead (false)
    @param[in] tag_handler how CBOR tags should be treated

    @return whether a valid CBOR value was passed to the SAX parser
    */

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
            return sax->parse_error(chars_read, get_token_string(),
                                    parse_error::create(112, chars_read,
                                            exception_message(input_format_t::cbor, "negative integer overflow", "value"), nullptr));
        }
        return sax->number_integer(static_cast<number_integer_t>(-1) - static_cast<number_integer_t>(number));
    }

    /*!
    @brief a single pending "resume this array/object" entry used by the
           iterative container traversal in @ref parse_cbor_internal

    Nested CBOR containers are parsed by pushing one of these onto a
    heap-allocated std::vector instead of recursing on the native call stack
    for every nesting level (see #5104): parsing a scalar never recurses,
    and parsing a container just pushes a frame here and loops back around
    to parse its first child; when a container finishes, its frame is
    popped and parsing resumes where the parent left off. Native call-stack
    depth used while parsing is therefore O(1) regardless of how deeply the
    input nests.
    */
    struct cbor_container_frame
    {
        bool is_object;          ///< false: array, true: object/map
        bool indefinite;         ///< true: length is unknown; read until a 0xFF break marker
        std::size_t remaining;   ///< remaining element count; meaningful only if !indefinite
        bool awaiting_key;       ///< object only: true if the next thing to read is a key, not a value
    };

    bool parse_cbor_internal(const bool get_char,
                             const cbor_tag_handler_t tag_handler)
    {
        std::vector<cbor_container_frame> stack;

        // whether the next value-read below should fetch a fresh byte via
        // get() (true) or reuse the byte already sitting in `current` (false)
        bool fetch_char = get_char;

        // called whenever a value (scalar, or a container that was just
        // completed/immediately-empty) was produced at the position the
        // current top-of-stack frame is waiting on; returns true if that
        // means the whole parse is finished (the stack is empty, i.e. this
        // was the outermost value), false if parsing should continue.
        auto produce = [&]() -> bool
        {
            if (stack.empty())
            {
                return true;
            }
            cbor_container_frame& top = stack.back();
            if (top.is_object)
            {
                top.awaiting_key = true;
            }
            if (!top.indefinite)
            {
                --top.remaining;
            }
            return false;
        };

        // begin parsing a nested array/object of the given length
        // (detail::unknown_size() for indefinite length); returns 0 on SAX
        // failure or exceeding max_depth (caller should `return false`), 1
        // if a frame was pushed (caller should `continue` the outer loop to
        // parse the container's first element), 2 if the container was
        // immediately completed because it is empty (caller should treat
        // this like any other produced value via `produce()`).
        auto enter_container = [&](const bool is_object, const std::size_t len) -> int
        {
            const bool started = is_object ? sax->start_object(len) : sax->start_array(len);
            if (JSON_HEDLEY_UNLIKELY(!started))
            {
                return 0;
            }
            if (len == 0)
            {
                return (is_object ? sax->end_object() : sax->end_array()) ? 2 : 0;
            }
            if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
            {
                sax->parse_error(chars_read, get_token_string(),
                                 parse_error::create(116, chars_read,
                                                     exception_message(input_format_t::cbor, "maximum depth of nested arrays/objects exceeded", "value"), nullptr));
                return 0;
            }
            stack.push_back(cbor_container_frame{is_object, len == detail::unknown_size(), len, is_object});
            return 1;
        };

#define JSON_CBOR_VALUE(expr) \
    if (JSON_HEDLEY_UNLIKELY(!(expr))) { return false; } \
    if (produce()) { return true; } \
    continue

#define JSON_CBOR_ENTER(is_obj, length) \
    switch (enter_container(is_obj, length)) \
    { \
        case 0: return false; \
        case 2: if (produce()) { return true; } continue; \
        default: continue; \
    }

        while (true)
        {
            if (!stack.empty())
            {
                cbor_container_frame& top = stack.back();

                if (top.is_object && top.awaiting_key)
                {
                    const bool finished = top.indefinite ? (get() == 0xFF) : (top.remaining == 0);
                    if (finished)
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->end_object()))
                        {
                            return false;
                        }
                        stack.pop_back();
                        if (produce())
                        {
                            return true;
                        }
                        continue;
                    }

                    if (!top.indefinite)
                    {
                        get();
                    }
                    string_t key;
                    if (JSON_HEDLEY_UNLIKELY(!get_cbor_string(key) || !sax->key(key)))
                    {
                        return false;
                    }
                    top.awaiting_key = false;
                    fetch_char = true;
                }
                else if (!top.is_object)
                {
                    const bool finished = top.indefinite ? (get() == 0xFF) : (top.remaining == 0);
                    if (finished)
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->end_array()))
                        {
                            return false;
                        }
                        stack.pop_back();
                        if (produce())
                        {
                            return true;
                        }
                        continue;
                    }
                    fetch_char = !top.indefinite;
                }
                // else: object frame with a key already read; fetch_char is
                // already set to true from when the key was read above.
            }

read_value:
            switch (fetch_char ? get() : current)
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
                    JSON_CBOR_VALUE(sax->number_unsigned(static_cast<number_unsigned_t>(current)));

                case 0x18: // Unsigned integer (one-byte uint8_t follows)
                {
                    std::uint8_t number{};
                    JSON_CBOR_VALUE(get_number(input_format_t::cbor, number) && sax->number_unsigned(number));
                }

                case 0x19: // Unsigned integer (two-byte uint16_t follows)
                {
                    std::uint16_t number{};
                    JSON_CBOR_VALUE(get_number(input_format_t::cbor, number) && sax->number_unsigned(number));
                }

                case 0x1A: // Unsigned integer (four-byte uint32_t follows)
                {
                    std::uint32_t number{};
                    JSON_CBOR_VALUE(get_number(input_format_t::cbor, number) && sax->number_unsigned(number));
                }

                case 0x1B: // Unsigned integer (eight-byte uint64_t follows)
                {
                    std::uint64_t number{};
                    JSON_CBOR_VALUE(get_number(input_format_t::cbor, number) && sax->number_unsigned(number));
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
                    JSON_CBOR_VALUE(sax->number_integer(static_cast<std::int8_t>(0x20 - 1 - current)));

                case 0x38: // Negative integer (one-byte uint8_t follows)
                    JSON_CBOR_VALUE(get_cbor_negative_integer<std::uint8_t>());

                case 0x39: // Negative integer -1-n (two-byte uint16_t follows)
                    JSON_CBOR_VALUE(get_cbor_negative_integer<std::uint16_t>());

                case 0x3A: // Negative integer -1-n (four-byte uint32_t follows)
                    JSON_CBOR_VALUE(get_cbor_negative_integer<std::uint32_t>());

                case 0x3B: // Negative integer -1-n (eight-byte uint64_t follows)
                    JSON_CBOR_VALUE(get_cbor_negative_integer<std::uint64_t>());

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
                    JSON_CBOR_VALUE(get_cbor_binary(b) && sax->binary(b));
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
                    JSON_CBOR_VALUE(get_cbor_string(s) && sax->string(s));
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
                    JSON_CBOR_ENTER(false, conditional_static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x1Fu));

                case 0x98: // array (one-byte uint8_t for n follows)
                {
                    std::uint8_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, len)))
                    {
                        return false;
                    }
                    JSON_CBOR_ENTER(false, static_cast<std::size_t>(len));
                }

                case 0x99: // array (two-byte uint16_t for n follow)
                {
                    std::uint16_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, len)))
                    {
                        return false;
                    }
                    JSON_CBOR_ENTER(false, static_cast<std::size_t>(len));
                }

                case 0x9A: // array (four-byte uint32_t for n follow)
                {
                    std::uint32_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, len)))
                    {
                        return false;
                    }
                    JSON_CBOR_ENTER(false, conditional_static_cast<std::size_t>(len));
                }

                case 0x9B: // array (eight-byte uint64_t for n follow)
                {
                    std::uint64_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, len)))
                    {
                        return false;
                    }
                    JSON_CBOR_ENTER(false, conditional_static_cast<std::size_t>(len));
                }

                case 0x9F: // array (indefinite length)
                    JSON_CBOR_ENTER(false, detail::unknown_size());

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
                    JSON_CBOR_ENTER(true, conditional_static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x1Fu));

                case 0xB8: // map (one-byte uint8_t for n follows)
                {
                    std::uint8_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, len)))
                    {
                        return false;
                    }
                    JSON_CBOR_ENTER(true, static_cast<std::size_t>(len));
                }

                case 0xB9: // map (two-byte uint16_t for n follow)
                {
                    std::uint16_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, len)))
                    {
                        return false;
                    }
                    JSON_CBOR_ENTER(true, static_cast<std::size_t>(len));
                }

                case 0xBA: // map (four-byte uint32_t for n follow)
                {
                    std::uint32_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, len)))
                    {
                        return false;
                    }
                    JSON_CBOR_ENTER(true, conditional_static_cast<std::size_t>(len));
                }

                case 0xBB: // map (eight-byte uint64_t for n follow)
                {
                    std::uint64_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::cbor, len)))
                    {
                        return false;
                    }
                    JSON_CBOR_ENTER(true, conditional_static_cast<std::size_t>(len));
                }

                case 0xBF: // map (indefinite length)
                    JSON_CBOR_ENTER(true, detail::unknown_size());

                case 0xC6: // tagged item
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
                                                    exception_message(input_format_t::cbor, concat("invalid byte: 0x", last_token), "value"), nullptr));
                        }

                        case cbor_tag_handler_t::ignore:
                        {
                            // ignore binary subtype
                            switch (current)
                            {
                                case 0xD8:
                                {
                                    std::uint8_t subtype_to_ignore{};
                                    get_number(input_format_t::cbor, subtype_to_ignore);
                                    break;
                                }
                                case 0xD9:
                                {
                                    std::uint16_t subtype_to_ignore{};
                                    get_number(input_format_t::cbor, subtype_to_ignore);
                                    break;
                                }
                                case 0xDA:
                                {
                                    std::uint32_t subtype_to_ignore{};
                                    get_number(input_format_t::cbor, subtype_to_ignore);
                                    break;
                                }
                                case 0xDB:
                                {
                                    std::uint64_t subtype_to_ignore{};
                                    get_number(input_format_t::cbor, subtype_to_ignore);
                                    break;
                                }
                                default:
                                    break;
                            }
                            fetch_char = true;
                            goto read_value;
                        }

                        case cbor_tag_handler_t::store:
                        {
                            binary_t b;
                            // use binary subtype and store in a binary container
                            switch (current)
                            {
                                case 0xD8:
                                {
                                    std::uint8_t subtype{};
                                    get_number(input_format_t::cbor, subtype);
                                    b.set_subtype(detail::conditional_static_cast<typename binary_t::subtype_type>(subtype));
                                    break;
                                }
                                case 0xD9:
                                {
                                    std::uint16_t subtype{};
                                    get_number(input_format_t::cbor, subtype);
                                    b.set_subtype(detail::conditional_static_cast<typename binary_t::subtype_type>(subtype));
                                    break;
                                }
                                case 0xDA:
                                {
                                    std::uint32_t subtype{};
                                    get_number(input_format_t::cbor, subtype);
                                    b.set_subtype(detail::conditional_static_cast<typename binary_t::subtype_type>(subtype));
                                    break;
                                }
                                case 0xDB:
                                {
                                    std::uint64_t subtype{};
                                    get_number(input_format_t::cbor, subtype);
                                    b.set_subtype(detail::conditional_static_cast<typename binary_t::subtype_type>(subtype));
                                    break;
                                }
                                default:
                                    fetch_char = true;
                                    goto read_value;
                            }
                            get();
                            JSON_CBOR_VALUE(get_cbor_binary(b) && sax->binary(b));
                        }

                        default:                 // LCOV_EXCL_LINE
                            JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
                            return false;        // LCOV_EXCL_LINE
                    }
                }

                case 0xF4: // false
                    JSON_CBOR_VALUE(sax->boolean(false));

                case 0xF5: // true
                    JSON_CBOR_VALUE(sax->boolean(true));

                case 0xF6: // null
                    JSON_CBOR_VALUE(sax->null());

                case 0xF9: // Half-Precision Float (two-byte IEEE 754)
                {
                    const auto byte1_raw = get();
                    if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::cbor, "number")))
                    {
                        return false;
                    }
                    const auto byte2_raw = get();
                    if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::cbor, "number")))
                    {
                        return false;
                    }

                    const auto byte1 = static_cast<unsigned char>(byte1_raw);
                    const auto byte2 = static_cast<unsigned char>(byte2_raw);

                    // Code from RFC 7049, Appendix D, Figure 3:
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
                        JSON_ASSERT(0 <= exp&& exp <= 32);
                        JSON_ASSERT(mant <= 1024);
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
                    JSON_CBOR_VALUE(sax->number_float((half & 0x8000u) != 0
                                                      ? static_cast<number_float_t>(-val)
                                                      : static_cast<number_float_t>(val), ""));
                }

                case 0xFA: // Single-Precision Float (four-byte IEEE 754)
                {
                    float number{};
                    JSON_CBOR_VALUE(get_number(input_format_t::cbor, number) && sax->number_float(static_cast<number_float_t>(number), ""));
                }

                case 0xFB: // Double-Precision Float (eight-byte IEEE 754)
                {
                    double number{};
                    JSON_CBOR_VALUE(get_number(input_format_t::cbor, number) && sax->number_float(static_cast<number_float_t>(number), ""));
                }

                default: // anything else (0xFF is handled inside the other types)
                {
                    auto last_token = get_token_string();
                    return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                            exception_message(input_format_t::cbor, concat("invalid byte: 0x", last_token), "value"), nullptr));
                }
            }
        }

#undef JSON_CBOR_VALUE
#undef JSON_CBOR_ENTER
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
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::cbor, "string")))
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

            case 0x7F: // UTF-8 string (indefinite length)
            {
                while (get() != 0xFF)
                {
                    string_t chunk;
                    if (!get_cbor_string(chunk))
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
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                        exception_message(input_format_t::cbor, concat("expected length specification (0x60-0x7B) or indefinite string type (0x7F); last byte: 0x", last_token), "string"), nullptr));
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
        if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format_t::cbor, "binary")))
        {
            return false;
        }

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

            case 0x5F: // Binary data (indefinite length)
            {
                while (get() != 0xFF)
                {
                    binary_t chunk;
                    if (!get_cbor_binary(chunk))
                    {
                        return false;
                    }
                    result.insert(result.end(), chunk.begin(), chunk.end());
                }
                return true;
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                        exception_message(input_format_t::cbor, concat("expected length specification (0x40-0x5B) or indefinite binary array type (0x5F); last byte: 0x", last_token), "binary"), nullptr));
            }
        }
    }

    /////////////
    // MsgPack //
    /////////////

    /*!
    @brief a single pending "resume this array/object" entry used by the
           iterative container traversal in @ref parse_msgpack_internal;
           see @ref cbor_container_frame for the general idea. MessagePack
           has no indefinite-length containers, so unlike CBOR this frame
           does not need an "indefinite" flag.
    */
    struct msgpack_container_frame
    {
        bool is_object;         ///< false: array, true: map
        std::size_t remaining;  ///< remaining element count
        bool awaiting_key;      ///< map only: true if the next thing to read is a key, not a value
    };

    /*!
    @return whether a valid MessagePack value was passed to the SAX parser
    */
    bool parse_msgpack_internal()
    {
        std::vector<msgpack_container_frame> stack;

        auto produce = [&]() -> bool
        {
            if (stack.empty())
            {
                return true;
            }
            msgpack_container_frame& top = stack.back();
            if (top.is_object)
            {
                top.awaiting_key = true;
            }
            --top.remaining;
            return false;
        };

        auto enter_container = [&](const bool is_object, const std::size_t len) -> int
        {
            const bool started = is_object ? sax->start_object(len) : sax->start_array(len);
            if (JSON_HEDLEY_UNLIKELY(!started))
            {
                return 0;
            }
            if (len == 0)
            {
                return (is_object ? sax->end_object() : sax->end_array()) ? 2 : 0;
            }
            if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
            {
                sax->parse_error(chars_read, get_token_string(),
                                 parse_error::create(116, chars_read,
                                                     exception_message(input_format_t::msgpack, "maximum depth of nested arrays/objects exceeded", "value"), nullptr));
                return 0;
            }
            stack.push_back(msgpack_container_frame{is_object, len, is_object});
            return 1;
        };

#define JSON_MSGPACK_VALUE(expr) \
    if (JSON_HEDLEY_UNLIKELY(!(expr))) { return false; } \
    if (produce()) { return true; } \
    continue

#define JSON_MSGPACK_ENTER(is_obj, length) \
    switch (enter_container(is_obj, length)) \
    { \
        case 0: return false; \
        case 2: if (produce()) { return true; } continue; \
        default: continue; \
    }

        while (true)
        {
            if (!stack.empty())
            {
                msgpack_container_frame& top = stack.back();

                if (top.is_object && top.awaiting_key)
                {
                    if (top.remaining == 0)
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->end_object()))
                        {
                            return false;
                        }
                        stack.pop_back();
                        if (produce())
                        {
                            return true;
                        }
                        continue;
                    }
                    get();
                    string_t key;
                    if (JSON_HEDLEY_UNLIKELY(!get_msgpack_string(key) || !sax->key(key)))
                    {
                        return false;
                    }
                    top.awaiting_key = false;
                }
                else if (!top.is_object)
                {
                    if (top.remaining == 0)
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->end_array()))
                        {
                            return false;
                        }
                        stack.pop_back();
                        if (produce())
                        {
                            return true;
                        }
                        continue;
                    }
                }
                // else: map frame with a key already read; fall through to
                // read that key's value.
            }

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
                    JSON_MSGPACK_VALUE(sax->number_unsigned(static_cast<number_unsigned_t>(current)));

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
                    JSON_MSGPACK_ENTER(true, conditional_static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x0Fu));

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
                    JSON_MSGPACK_ENTER(false, conditional_static_cast<std::size_t>(static_cast<unsigned int>(current) & 0x0Fu));

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
                    JSON_MSGPACK_VALUE(get_msgpack_string(s) && sax->string(s));
                }

                case 0xC0: // nil
                    JSON_MSGPACK_VALUE(sax->null());

                case 0xC2: // false
                    JSON_MSGPACK_VALUE(sax->boolean(false));

                case 0xC3: // true
                    JSON_MSGPACK_VALUE(sax->boolean(true));

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
                    JSON_MSGPACK_VALUE(get_msgpack_binary(b) && sax->binary(b));
                }

                case 0xCA: // float 32
                {
                    float number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_float(static_cast<number_float_t>(number), ""));
                }

                case 0xCB: // float 64
                {
                    double number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_float(static_cast<number_float_t>(number), ""));
                }

                case 0xCC: // uint 8
                {
                    std::uint8_t number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_unsigned(number));
                }

                case 0xCD: // uint 16
                {
                    std::uint16_t number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_unsigned(number));
                }

                case 0xCE: // uint 32
                {
                    std::uint32_t number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_unsigned(number));
                }

                case 0xCF: // uint 64
                {
                    std::uint64_t number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_unsigned(number));
                }

                case 0xD0: // int 8
                {
                    std::int8_t number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_integer(number));
                }

                case 0xD1: // int 16
                {
                    std::int16_t number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_integer(number));
                }

                case 0xD2: // int 32
                {
                    std::int32_t number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_integer(number));
                }

                case 0xD3: // int 64
                {
                    std::int64_t number{};
                    JSON_MSGPACK_VALUE(get_number(input_format_t::msgpack, number) && sax->number_integer(number));
                }

                case 0xDC: // array 16
                {
                    std::uint16_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::msgpack, len)))
                    {
                        return false;
                    }
                    JSON_MSGPACK_ENTER(false, static_cast<std::size_t>(len));
                }

                case 0xDD: // array 32
                {
                    std::uint32_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::msgpack, len)))
                    {
                        return false;
                    }
                    JSON_MSGPACK_ENTER(false, conditional_static_cast<std::size_t>(len));
                }

                case 0xDE: // map 16
                {
                    std::uint16_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::msgpack, len)))
                    {
                        return false;
                    }
                    JSON_MSGPACK_ENTER(true, static_cast<std::size_t>(len));
                }

                case 0xDF: // map 32
                {
                    std::uint32_t len{};
                    if (JSON_HEDLEY_UNLIKELY(!get_number(input_format_t::msgpack, len)))
                    {
                        return false;
                    }
                    JSON_MSGPACK_ENTER(true, conditional_static_cast<std::size_t>(len));
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
                    JSON_MSGPACK_VALUE(sax->number_integer(static_cast<std::int8_t>(current)));

                default: // anything else
                {
                    auto last_token = get_token_string();
                    return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                            exception_message(input_format_t::msgpack, concat("invalid byte: 0x", last_token), "value"), nullptr));
                }
            }
        }

#undef JSON_MSGPACK_VALUE
#undef JSON_MSGPACK_ENTER
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
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                        exception_message(input_format_t::msgpack, concat("expected length specification (0xA0-0xBF, 0xD9-0xDB); last byte: 0x", last_token), "string"), nullptr));
            }
        }
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

    ////////////
    // UBJSON //
    ////////////

    /*!
    @brief a single pending "resume this array/object" entry used by the
           iterative container traversal in @ref parse_ubjson_internal; see
           @ref cbor_container_frame for the general idea.

    UBJSON/BJData needs two extra bits of state beyond CBOR/MessagePack:
    @ref fixed_type captures the optimized `$type#count` container's
    homogeneous element type (0 means "heterogeneous": read a fresh type
    marker per element, like an ordinary UBJSON array/object); @ref
    extra_close_object is set for the synthetic JData-annotated-array object
    ("_ArrayType_"/"_ArraySize_"/"_ArrayData_") BJData wraps an ND-array in,
    where finishing the `_ArrayData_` array must also close that wrapping
    object.
    */
    struct ubjson_container_frame
    {
        bool is_object;             ///< false: array, true: object
        bool indefinite;            ///< true: no known count; read until a ']'/'}' terminator
        std::size_t remaining;      ///< remaining element count; meaningful only if !indefinite
        bool awaiting_key;          ///< object only: true if the next thing to read is a key, not a value
        char_int_type fixed_type;   ///< 0: heterogeneous; else every element has this known type marker
        bool extra_close_object;    ///< true: end_array() for this frame must be followed by an end_object()
    };

    /*!
    @param[in] get_char  whether a new character should be retrieved from the
                         input (true, default) or whether the last read
                         character should be considered instead

    @return whether a valid UBJSON value was passed to the SAX parser
    */
    bool parse_ubjson_internal(const bool get_char = true)
    {
        std::vector<ubjson_container_frame> stack;
        bool fetch_char = get_char;

        auto produce = [&]() -> bool
        {
            if (stack.empty())
            {
                return true;
            }
            ubjson_container_frame& top = stack.back();
            if (top.is_object)
            {
                top.awaiting_key = true;
            }
            if (!top.indefinite)
            {
                --top.remaining;
            }
            else
            {
                // indefinite-length containers are terminated by inspecting
                // `current`, so advance past the just-produced element/pair
                // to whatever byte should be inspected next (mirrors the
                // `get_ignore_noop()` at the end of each iteration of the
                // original recursive implementation's while-loops)
                get_ignore_noop();
            }
            return false;
        };

        // returns 0 = failure (caller returns false), 1 = a frame was
        // pushed (caller continues the outer loop to parse the first
        // element), 2 = a value was produced immediately - either because
        // the container turned out to be empty, or (BJData only) because
        // the "optimized binary array" special case produced a single
        // binary value directly, without ever being a SAX array at all
        // (caller should invoke produce() same as for any other value)
        auto enter_array = [&]() -> int
        {
            std::pair<std::size_t, char_int_type> size_and_type;
            if (JSON_HEDLEY_UNLIKELY(!get_ubjson_size_type(size_and_type)))
            {
                return 0;
            }

            // ND-array: encode as an object in JData annotated array format
            // (https://github.com/NeuroJSON/jdata). The wrapping object was
            // already start_object()'d (with the "_ArraySize_" key/array
            // already emitted) inside get_ubjson_size_type(), so only
            // "_ArrayType_" and "_ArrayData_" remain to be added here.
            if (input_format == input_format_t::bjdata && size_and_type.first != npos && (size_and_type.second & (1 << 8)) != 0)
            {
                size_and_type.second &= ~(static_cast<char_int_type>(1) << 8);
                auto it = std::lower_bound(bjd_types_map.begin(), bjd_types_map.end(), size_and_type.second, [](const bjd_type & p, char_int_type t)
                {
                    return p.first < t;
                });
                string_t key = "_ArrayType_";
                if (JSON_HEDLEY_UNLIKELY(it == bjd_types_map.end() || it->first != size_and_type.second))
                {
                    auto last_token = get_token_string();
                    sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                     exception_message(input_format, "invalid byte: 0x" + last_token, "type"), nullptr));
                    return 0;
                }

                string_t type = it->second; // sax->string() takes a reference
                if (JSON_HEDLEY_UNLIKELY(!sax->key(key) || !sax->string(type)))
                {
                    return 0;
                }

                if (size_and_type.second == 'C' || size_and_type.second == 'B')
                {
                    size_and_type.second = 'U';
                }

                key = "_ArrayData_";
                if (JSON_HEDLEY_UNLIKELY(!sax->key(key) || !sax->start_array(size_and_type.first)))
                {
                    return 0;
                }

                if (size_and_type.first == 0)
                {
                    return (sax->end_array() && sax->end_object()) ? 2 : 0;
                }
                if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
                {
                    sax->parse_error(chars_read, get_token_string(), parse_error::create(116, chars_read,
                                     exception_message(input_format, "maximum depth of nested arrays/objects exceeded", "value"), nullptr));
                    return 0;
                }
                stack.push_back(ubjson_container_frame{false, false, size_and_type.first, false, size_and_type.second, true});
                return 1;
            }

            // BJData type marker 'B': decode as binary (not a SAX array at all)
            if (input_format == input_format_t::bjdata && size_and_type.first != npos && size_and_type.second == 'B')
            {
                binary_t result;
                return (get_binary(input_format, size_and_type.first, result) && sax->binary(result)) ? 2 : 0;
            }

            if (size_and_type.first != npos)
            {
                if (JSON_HEDLEY_UNLIKELY(!sax->start_array(size_and_type.first)))
                {
                    return 0;
                }

                // a homogeneous type of 'N' (no-op) means no elements are
                // actually read, no matter what count was declared
                if (size_and_type.second == 'N' || size_and_type.first == 0)
                {
                    return sax->end_array() ? 2 : 0;
                }
                if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
                {
                    sax->parse_error(chars_read, get_token_string(), parse_error::create(116, chars_read,
                                     exception_message(input_format, "maximum depth of nested arrays/objects exceeded", "value"), nullptr));
                    return 0;
                }
                stack.push_back(ubjson_container_frame{false, false, size_and_type.first, false, size_and_type.second, false});
                return 1;
            }

            // indefinite length
            if (JSON_HEDLEY_UNLIKELY(!sax->start_array(detail::unknown_size())))
            {
                return 0;
            }
            if (current == ']')
            {
                return sax->end_array() ? 2 : 0;
            }
            if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
            {
                sax->parse_error(chars_read, get_token_string(), parse_error::create(116, chars_read,
                                 exception_message(input_format, "maximum depth of nested arrays/objects exceeded", "value"), nullptr));
                return 0;
            }
            stack.push_back(ubjson_container_frame{false, true, 0, false, 0, false});
            return 1;
        };

        auto enter_object = [&]() -> int
        {
            std::pair<std::size_t, char_int_type> size_and_type;
            if (JSON_HEDLEY_UNLIKELY(!get_ubjson_size_type(size_and_type)))
            {
                return 0;
            }

            // do not accept ND-array size in objects in BJData
            if (input_format == input_format_t::bjdata && size_and_type.first != npos && (size_and_type.second & (1 << 8)) != 0)
            {
                auto last_token = get_token_string();
                sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                 exception_message(input_format, "BJData object does not support ND-array size in optimized format", "object"), nullptr));
                return 0;
            }

            if (size_and_type.first != npos)
            {
                if (JSON_HEDLEY_UNLIKELY(!sax->start_object(size_and_type.first)))
                {
                    return 0;
                }
                if (size_and_type.first == 0)
                {
                    return sax->end_object() ? 2 : 0;
                }
                if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
                {
                    sax->parse_error(chars_read, get_token_string(), parse_error::create(116, chars_read,
                                     exception_message(input_format, "maximum depth of nested arrays/objects exceeded", "value"), nullptr));
                    return 0;
                }
                stack.push_back(ubjson_container_frame{true, false, size_and_type.first, true, size_and_type.second, false});
                return 1;
            }

            if (JSON_HEDLEY_UNLIKELY(!sax->start_object(detail::unknown_size())))
            {
                return 0;
            }
            if (current == '}')
            {
                return sax->end_object() ? 2 : 0;
            }
            if (JSON_HEDLEY_UNLIKELY(stack.size() >= max_depth))
            {
                sax->parse_error(chars_read, get_token_string(), parse_error::create(116, chars_read,
                                 exception_message(input_format, "maximum depth of nested arrays/objects exceeded", "value"), nullptr));
                return 0;
            }
            stack.push_back(ubjson_container_frame{true, true, 0, true, 0, false});
            return 1;
        };

#define JSON_UBJSON_VALUE(expr) \
    if (JSON_HEDLEY_UNLIKELY(!(expr))) { return false; } \
    if (produce()) { return true; } \
    continue

#define JSON_UBJSON_ENTER(fn) \
    switch (fn()) \
    { \
        case 0: return false; \
        case 2: if (produce()) { return true; } continue; \
        default: continue; \
    }

        while (true)
        {
            if (!stack.empty())
            {
                ubjson_container_frame& top = stack.back();

                if (top.is_object && top.awaiting_key)
                {
                    const bool finished = top.indefinite ? (current == '}') : (top.remaining == 0);
                    if (finished)
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->end_object()))
                        {
                            return false;
                        }
                        stack.pop_back();
                        if (produce())
                        {
                            return true;
                        }
                        continue;
                    }

                    string_t key;
                    if (JSON_HEDLEY_UNLIKELY(!get_ubjson_string(key, !top.indefinite) || !sax->key(key)))
                    {
                        return false;
                    }
                    top.awaiting_key = false;
                }
                else if (!top.is_object)
                {
                    const bool finished = top.indefinite ? (current == ']') : (top.remaining == 0);
                    if (finished)
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->end_array()))
                        {
                            return false;
                        }
                        const bool extra_close = top.extra_close_object;
                        stack.pop_back();
                        if (extra_close && JSON_HEDLEY_UNLIKELY(!sax->end_object()))
                        {
                            return false;
                        }
                        if (produce())
                        {
                            return true;
                        }
                        continue;
                    }
                }
                // else: object frame with a key already read; fall through
                // to read that key's value below.
            }

            char_int_type prefix;
            if (!stack.empty())
            {
                ubjson_container_frame& top = stack.back();
                if (top.fixed_type != 0)
                {
                    prefix = top.fixed_type;
                }
                else if (!top.is_object && top.indefinite)
                {
                    prefix = current;
                }
                else
                {
                    prefix = get_ignore_noop();
                }
            }
            else
            {
                prefix = fetch_char ? get_ignore_noop() : current;
            }

            switch (prefix)
            {
                case char_traits<char_type>::eof():  // EOF
                    return unexpect_eof(input_format, "value");

                case 'T':  // true
                    JSON_UBJSON_VALUE(sax->boolean(true));
                case 'F':  // false
                    JSON_UBJSON_VALUE(sax->boolean(false));

                case 'Z':  // null
                    JSON_UBJSON_VALUE(sax->null());

                case 'B':  // byte
                {
                    if (input_format != input_format_t::bjdata)
                    {
                        break;
                    }
                    std::uint8_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_unsigned(number));
                }

                case 'U':
                {
                    std::uint8_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_unsigned(number));
                }

                case 'i':
                {
                    std::int8_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_integer(number));
                }

                case 'I':
                {
                    std::int16_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_integer(number));
                }

                case 'l':
                {
                    std::int32_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_integer(number));
                }

                case 'L':
                {
                    std::int64_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_integer(number));
                }

                case 'u':
                {
                    if (input_format != input_format_t::bjdata)
                    {
                        break;
                    }
                    std::uint16_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_unsigned(number));
                }

                case 'm':
                {
                    if (input_format != input_format_t::bjdata)
                    {
                        break;
                    }
                    std::uint32_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_unsigned(number));
                }

                case 'M':
                {
                    if (input_format != input_format_t::bjdata)
                    {
                        break;
                    }
                    std::uint64_t number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_unsigned(number));
                }

                case 'h':
                {
                    if (input_format != input_format_t::bjdata)
                    {
                        break;
                    }
                    const auto byte1_raw = get();
                    if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format, "number")))
                    {
                        return false;
                    }
                    const auto byte2_raw = get();
                    if (JSON_HEDLEY_UNLIKELY(!unexpect_eof(input_format, "number")))
                    {
                        return false;
                    }

                    const auto byte1 = static_cast<unsigned char>(byte1_raw);
                    const auto byte2 = static_cast<unsigned char>(byte2_raw);

                    // Code from RFC 7049, Appendix D, Figure 3:
                    // As half-precision floating-point numbers were only added
                    // to IEEE 754 in 2008, today's programming platforms often
                    // still only have limited support for them. It is very
                    // easy to include at least decoding support for them even
                    // without such support. An example of a small decoder for
                    // half-precision floating-point numbers in the C language
                    // is shown in Fig. 3.
                    const auto half = static_cast<unsigned int>((byte2 << 8u) + byte1);
                    const double val = [&half]
                    {
                        const int exp = (half >> 10u) & 0x1Fu;
                        const unsigned int mant = half & 0x3FFu;
                        JSON_ASSERT(0 <= exp&& exp <= 32);
                        JSON_ASSERT(mant <= 1024);
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
                    JSON_UBJSON_VALUE(sax->number_float((half & 0x8000u) != 0
                                                        ? static_cast<number_float_t>(-val)
                                                        : static_cast<number_float_t>(val), ""));
                }

                case 'd':
                {
                    float number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_float(static_cast<number_float_t>(number), ""));
                }

                case 'D':
                {
                    double number{};
                    JSON_UBJSON_VALUE(get_number(input_format, number) && sax->number_float(static_cast<number_float_t>(number), ""));
                }

                case 'H':
                {
                    JSON_UBJSON_VALUE(get_ubjson_high_precision_number());
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
                        return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read,
                                                exception_message(input_format, concat("byte after 'C' must be in range 0x00..0x7F; last byte: 0x", last_token), "char"), nullptr));
                    }
                    string_t s(1, static_cast<typename string_t::value_type>(current));
                    JSON_UBJSON_VALUE(sax->string(s));
                }

                case 'S':  // string
                {
                    string_t s;
                    JSON_UBJSON_VALUE(get_ubjson_string(s) && sax->string(s));
                }

                case '[':  // array
                    JSON_UBJSON_ENTER(enter_array);

                case '{':  // object
                    JSON_UBJSON_ENTER(enter_object);

                default: // anything else
                    break;
            }
            auto last_token = get_token_string();
            return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, exception_message(input_format, "invalid byte: 0x" + last_token, "value"), nullptr));
        }

#undef JSON_UBJSON_VALUE
#undef JSON_UBJSON_ENTER
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
            get();  // TODO(niels): may we ignore N here?
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
        return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format, message, "string"), nullptr));
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
            {
                std::int8_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
                {
                    return false;
                }
                if (number < 0)
                {
                    return sax->parse_error(chars_read, get_token_string(), parse_error::create(113, chars_read,
                                            exception_message(input_format, "count in an optimized container must be positive", "size"), nullptr));
                }
                result = static_cast<std::size_t>(number); // NOLINT(bugprone-signed-char-misuse,cert-str34-c): number is not a char
                return true;
            }

            case 'I':
            {
                std::int16_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
                {
                    return false;
                }
                if (number < 0)
                {
                    return sax->parse_error(chars_read, get_token_string(), parse_error::create(113, chars_read,
                                            exception_message(input_format, "count in an optimized container must be positive", "size"), nullptr));
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'l':
            {
                std::int32_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
                {
                    return false;
                }
                if (number < 0)
                {
                    return sax->parse_error(chars_read, get_token_string(), parse_error::create(113, chars_read,
                                            exception_message(input_format, "count in an optimized container must be positive", "size"), nullptr));
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'L':
            {
                std::int64_t number{};
                if (JSON_HEDLEY_UNLIKELY(!get_number(input_format, number)))
                {
                    return false;
                }
                if (number < 0)
                {
                    return sax->parse_error(chars_read, get_token_string(), parse_error::create(113, chars_read,
                                            exception_message(input_format, "count in an optimized container must be positive", "size"), nullptr));
                }
                if (!value_in_range_of<std::size_t>(number))
                {
                    return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408,
                                            exception_message(input_format, "integer value overflow", "size"), nullptr));
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

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
                    return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408,
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
                    return sax->parse_error(chars_read, get_token_string(), parse_error::create(113, chars_read, exception_message(input_format, "ndarray dimensional vector is not allowed", "size"), nullptr));
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
                    result = 1;
                    for (auto i : dim)
                    {
                        // Pre-multiplication overflow check: if i > 0 and result > SIZE_MAX/i, then result*i would overflow.
                        // This check must happen before multiplication since overflow detection after the fact is unreliable
                        // as modular arithmetic can produce any value, not just 0 or SIZE_MAX.
                        if (JSON_HEDLEY_UNLIKELY(i > 0 && result > (std::numeric_limits<std::size_t>::max)() / i))
                        {
                            return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408, exception_message(input_format, "excessive ndarray size caused overflow", "size"), nullptr));
                        }
                        result *= i;
                        // Additional post-multiplication check to catch any edge cases the pre-check might miss
                        if (result == 0 || result == npos)
                        {
                            return sax->parse_error(chars_read, get_token_string(), out_of_range::create(408, exception_message(input_format, "excessive ndarray size caused overflow", "size"), nullptr));
                        }
                        if (JSON_HEDLEY_UNLIKELY(!sax->number_unsigned(static_cast<number_unsigned_t>(i))))
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
        return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, exception_message(input_format, message, "size"), nullptr));
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
        bool is_ndarray = false;

        get_ignore_noop();

        if (current == '$')
        {
            result.second = get();  // must not ignore 'N', because 'N' maybe the type
            if (input_format == input_format_t::bjdata
                    && JSON_HEDLEY_UNLIKELY(std::binary_search(bjd_optimized_type_markers.begin(), bjd_optimized_type_markers.end(), result.second)))
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
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
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read,
                                        exception_message(input_format, concat("expected '#' after type information; last byte: 0x", last_token), "size"), nullptr));
            }

            const bool is_error = get_ubjson_size_value(result.first, is_ndarray);
            if (input_format == input_format_t::bjdata && is_ndarray)
            {
                if (inside_ndarray)
                {
                    return sax->parse_error(chars_read, get_token_string(), parse_error::create(112, chars_read,
                                            exception_message(input_format, "ndarray can not be recursive", "size"), nullptr));
                }
                result.second |= (1 << 8); // use bit 8 to indicate ndarray, all UBJSON and BJData markers should be ASCII letters
            }
            return is_error;
        }

        if (current == '#')
        {
            const bool is_error = get_ubjson_size_value(result.first, is_ndarray);
            if (input_format == input_format_t::bjdata && is_ndarray)
            {
                return sax->parse_error(chars_read, get_token_string(), parse_error::create(112, chars_read,
                                        exception_message(input_format, "ndarray requires both type and size", "size"), nullptr));
            }
            return is_error;
        }

        return true;
    }

    // Note, no reader for UBJSON binary types is implemented because they do
    // not exist

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
            return sax->parse_error(chars_read, number_string, parse_error::create(115, chars_read,
                                    exception_message(input_format, concat("invalid number text: ", number_lexer.get_token_string()), "high-precision number"), nullptr));
        }

        switch (result_number)
        {
            case token_type::value_integer:
                return sax->number_integer(number_lexer.get_number_integer());
            case token_type::value_unsigned:
                return sax->number_unsigned(number_lexer.get_number_unsigned());
            case token_type::value_float:
                return sax->number_float(number_lexer.get_number_float(), std::move(number_string));
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
                                        exception_message(input_format, concat("invalid number text: ", number_lexer.get_token_string()), "high-precision number"), nullptr));
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
        auto new_chars_read = ia.get_elements(&dest);
        chars_read += new_chars_read;
        if (JSON_HEDLEY_UNLIKELY(new_chars_read < sizeof(T)))
        {
            // in case of failure, advance position by 1 to report the failing location
            ++chars_read;
            sax->parse_error(chars_read, "<end of file>", parse_error::create(110, chars_read, exception_message(format, "unexpected end of input", context), nullptr));
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

    /*
    @brief read a number from the input

    @tparam NumberType the type of the number
    @param[in] format   the current format (for diagnostics)
    @param[out] result  number of type @a NumberType

    @return whether conversion completed

    @note This function needs to respect the system's endianness, because
          bytes in CBOR, MessagePack, and UBJSON are stored in network order
          (big endian) and therefore need reordering on little endian systems.
          On the other hand, BSON and BJData use little endian and should reorder
          on big endian systems.
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
        return get_bytes(format, len, "string", result);
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
    @param[in] format   the current format (for diagnostics)
    @param[in] context  further context information (for diagnostics)
    @return whether the last read character is not EOF
    */
    JSON_HEDLEY_NON_NULL(3)
    bool unexpect_eof(const input_format_t format, const char* context) const
    {
        if (JSON_HEDLEY_UNLIKELY(current == char_traits<char_type>::eof()))
        {
            return sax->parse_error(chars_read, "<end of file>",
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

            case input_format_t::json: // LCOV_EXCL_LINE
            default:            // LCOV_EXCL_LINE
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
        }

        return concat(error_msg, ' ', context, ": ", detail);
    }

  private:
    static JSON_INLINE_VARIABLE constexpr std::size_t npos = detail::unknown_size();

    /// maximum allowed nesting depth of arrays/objects for the binary input
    /// formats.
    ///
    /// The container-parsing loops in this file are iterative (see e.g.
    /// @ref cbor_container_frame): nesting depth is tracked as the size of a
    /// heap-allocated std::vector, not native call-stack recursion, so this
    /// limit is no longer a stack-safety mechanism - arbitrarily deep input
    /// can no longer overflow the stack regardless of this value. It is kept
    /// purely as a sanity/DoS cap on absurd inputs (e.g. a malicious payload
    /// nesting billions of levels deep to exhaust memory/time), so it can
    /// afford to be generous; it is far above the library's own deepest
    /// legitimate test fixture (tests/data/json_testsuite/sample.json, 458
    /// levels).
    static JSON_INLINE_VARIABLE constexpr std::size_t max_depth = 100000;

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

    // excluded markers in bjdata optimized type
#define JSON_BINARY_READER_MAKE_BJD_OPTIMIZED_TYPE_MARKERS_ \
    make_array<char_int_type>('F', 'H', 'N', 'S', 'T', 'Z', '[', '{')

#define JSON_BINARY_READER_MAKE_BJD_TYPES_MAP_ \
    make_array<bjd_type>(                      \
    bjd_type{'B', "byte"},                     \
    bjd_type{'C', "char"},                     \
    bjd_type{'D', "double"},                   \
    bjd_type{'I', "int16"},                    \
    bjd_type{'L', "int64"},                    \
    bjd_type{'M', "uint64"},                   \
    bjd_type{'U', "uint8"},                    \
    bjd_type{'d', "single"},                   \
    bjd_type{'i', "int8"},                     \
    bjd_type{'l', "int32"},                    \
    bjd_type{'m', "uint32"},                   \
    bjd_type{'u', "uint16"})

  JSON_PRIVATE_UNLESS_TESTED:
    // lookup tables
    // NOLINTNEXTLINE(cppcoreguidelines-non-private-member-variables-in-classes)
    const decltype(JSON_BINARY_READER_MAKE_BJD_OPTIMIZED_TYPE_MARKERS_) bjd_optimized_type_markers =
        JSON_BINARY_READER_MAKE_BJD_OPTIMIZED_TYPE_MARKERS_;

    using bjd_type = std::pair<char_int_type, string_t>;
    // NOLINTNEXTLINE(cppcoreguidelines-non-private-member-variables-in-classes)
    const decltype(JSON_BINARY_READER_MAKE_BJD_TYPES_MAP_) bjd_types_map =
        JSON_BINARY_READER_MAKE_BJD_TYPES_MAP_;

#undef JSON_BINARY_READER_MAKE_BJD_OPTIMIZED_TYPE_MARKERS_
#undef JSON_BINARY_READER_MAKE_BJD_TYPES_MAP_
};

#ifndef JSON_HAS_CPP_17
    template<typename BasicJsonType, typename InputAdapterType, typename SAX>
    constexpr std::size_t binary_reader<BasicJsonType, InputAdapterType, SAX>::npos;
#endif

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
