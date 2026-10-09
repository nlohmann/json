//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

/////////////////////////////////////////////////////////////////////
// Tests that call basic_json::sax_parse have a file of their own: every
// sax_parse call instantiates the parser and binary reader that recover from
// errors (see #3989), and in unit-regression2.cpp, unit-regression3.cpp, and
// unit-msgpack.cpp this made the objects too large for the MinGW linker to
// relocate (see #5511).
/////////////////////////////////////////////////////////////////////

#include "doctest_compatibility.h"

// capture whether JSON_DELETE_DEPRECATED_FUNCTIONS was enabled on the command
// line *before* including json.hpp, since the library #undefs it once the header
// has been fully processed (see include/nlohmann/detail/macro_unscope.hpp); the
// tests of deprecated functions are skipped if these functions are deleted
#if defined(JSON_DELETE_DEPRECATED_FUNCTIONS) && (JSON_DELETE_DEPRECATED_FUNCTIONS == 1)
    #define JSON_TEST_DEPRECATED_FUNCTIONS_DELETED
#endif

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "sax_countdown.hpp"
using utils::SaxCountdown;

// a narrow number_float_t, so that a double read from binary input can
// overflow it
using float_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;

DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

namespace
{
/// builds a value from SAX events, asks the parser to recover from its first
/// 100 errors, and checks that the events are balanced (see #3989)
template<typename BasicJsonType>
class BasicRecoveringParser
{
  public:
    explicit BasicRecoveringParser(BasicJsonType& j)
        : dom(j, false)
    {}

    bool null()
    {
        value();
        return dom.null();
    }

    bool boolean(bool val)
    {
        value();
        return dom.boolean(val);
    }

    bool number_integer(typename BasicJsonType::number_integer_t val)
    {
        value();
        return dom.number_integer(val);
    }

    bool number_unsigned(typename BasicJsonType::number_unsigned_t val)
    {
        value();
        return dom.number_unsigned(val);
    }

    bool number_float(typename BasicJsonType::number_float_t val, const std::string& s)
    {
        value();
        return dom.number_float(val, s);
    }

    bool string(std::string& val)
    {
        value();
        return dom.string(val);
    }

    bool binary(typename BasicJsonType::binary_t& val)
    {
        value();
        return dom.binary(val);
    }

    bool start_object(std::size_t elements)
    {
        value();
        stack.push_back('o');
        return dom.start_object(elements);
    }

    bool key(std::string& val)
    {
        if (stack.empty() || stack.back() != 'o')
        {
            well_formed = false;
            return false;
        }
        stack.back() = 'v';
        return dom.key(val);
    }

    bool end_object()
    {
        if (stack.empty() || stack.back() != 'o')
        {
            well_formed = false;
            return false;
        }
        stack.pop_back();
        return dom.end_object();
    }

    bool start_array(std::size_t elements)
    {
        value();
        stack.push_back('a');
        return dom.start_array(elements);
    }

    bool end_array()
    {
        if (stack.empty() || stack.back() != 'a')
        {
            well_formed = false;
            return false;
        }
        stack.pop_back();
        return dom.end_array();
    }

    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const json::exception& ex)
    {
        messages.emplace_back(ex.what());
        // a limit, so that a reader that does not stop fails the test
        // instead of making it hang
        return ++errors < 100;
    }

    /// whether the events were balanced and every key was followed by a value
    bool balanced() const
    {
        return well_formed && stack.empty();
    }

    /// builds the value
    nlohmann::detail::json_sax_dom_parser<BasicJsonType> dom;
    std::size_t errors = 0;
    std::vector<std::string> messages {}; // NOLINT(readability-redundant-member-init)
    std::vector<char> stack {}; // NOLINT(readability-redundant-member-init)
    bool well_formed = true;

  private:
    void value()
    {
        if (!stack.empty())
        {
            if (stack.back() == 'v')
            {
                stack.back() = 'o';
            }
            else if (stack.back() == 'o')
            {
                well_formed = false;
            }
        }
    }

};

using RecoveringParser = BasicRecoveringParser<json>;

struct BinaryParseResult
{
    json value;
    std::size_t errors;
    std::vector<std::string> messages;
    bool ok;
    bool balanced;
};

BinaryParseResult parse_binary_recovering(const std::vector<std::uint8_t>& input, const json::input_format_t format)
{
    json j;
    RecoveringParser sax(j);
    const bool ok = json::sax_parse(input, &sax, format);
    return {j, sax.errors, sax.messages, ok, sax.balanced()};
}

#if !defined(JSON_NOEXCEPTION)
/// the message of the exception that reading @a input into a JSON value
/// throws, or an empty string if reading succeeds
std::string binary_error_message(const std::vector<std::uint8_t>& input, const json::input_format_t format)
{
    try
    {
        json _;
        switch (format)
        {
            case json::input_format_t::cbor:
                _ = json::from_cbor(input);
                break;
            case json::input_format_t::msgpack:
                _ = json::from_msgpack(input);
                break;
            case json::input_format_t::ubjson:
                _ = json::from_ubjson(input);
                break;
            case json::input_format_t::bjdata:
                _ = json::from_bjdata(input);
                break;
            case json::input_format_t::bson:
                _ = json::from_bson(input);
                break;
            case json::input_format_t::bon8:
                _ = json::from_bon8(input);
                break;
            case json::input_format_t::json:
            default:
                break;
        }
    }
    catch (const json::exception& e)
    {
        return e.what();
    }
    return "";
}
#endif

/// a BSON element: its type, its name, and its value
std::vector<std::uint8_t> bson_element(const std::uint8_t type, const std::string& name, const std::vector<std::uint8_t>& value)
{
    std::vector<std::uint8_t> result = {type};
    result.insert(result.end(), name.begin(), name.end());
    result.push_back(0x00);
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

/// a BSON document of the given elements; @a size_offset is added to the
/// size it declares
std::vector<std::uint8_t> bson_document(const std::vector<std::vector<std::uint8_t>>& elements, const int size_offset = 0)
{
    std::vector<std::uint8_t> body;
    for (const auto& element : elements)
    {
        body.insert(body.end(), element.begin(), element.end());
    }
    const auto size = static_cast<std::uint32_t>(static_cast<int>(body.size()) + 5 + size_offset);
    std::vector<std::uint8_t> result = {static_cast<std::uint8_t>(size & 0xFFu), static_cast<std::uint8_t>((size >> 8u) & 0xFFu),
                                        static_cast<std::uint8_t>((size >> 16u) & 0xFFu), static_cast<std::uint8_t>((size >> 24u) & 0xFFu)
                                       };
    result.insert(result.end(), body.begin(), body.end());
    result.push_back(0x00);
    return result;
}

/// a BSON int32 value
std::vector<std::uint8_t> bson_int32(const std::int32_t value)
{
    const auto u = static_cast<std::uint32_t>(value);
    return {static_cast<std::uint8_t>(u & 0xFFu), static_cast<std::uint8_t>((u >> 8u) & 0xFFu),
            static_cast<std::uint8_t>((u >> 16u) & 0xFFu), static_cast<std::uint8_t>((u >> 24u) & 0xFFu)};
}

/// a BSON string value, whose length is @a length_offset off
std::vector<std::uint8_t> bson_string(const std::string& value, const std::int32_t length_offset = 0)
{
    auto result = bson_int32(static_cast<std::int32_t>(value.size() + 1) + length_offset);
    result.insert(result.end(), value.begin(), value.end());
    result.push_back(0x00);
    return result;
}

/// @a count bytes of value 0xAB
std::vector<std::uint8_t> bytes(const std::size_t count)
{
    return std::vector<std::uint8_t>(count, 0xAB);
}

/// the bytes of @a parts, one after the other
std::vector<std::uint8_t> concatenated(std::initializer_list<std::vector<std::uint8_t>> parts)
{
    std::vector<std::uint8_t> result;
    for (const auto& part : parts)
    {
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

/// U+FFFD REPLACEMENT CHARACTER
std::string replacement_character()
{
    return "\xEF\xBF\xBD";
}
}  // namespace

TEST_CASE("regression test - #3989 SAX parse_error() returning true")
{
    SECTION("binary formats complete what was read before the input ends")
    {
        const json j = {{"a", {1, -2, {{"b", "c"}}, json::array()}}, {"d", {{"e", nullptr}, {"f", true}}}, {"g", 1.5}, {"h", json::binary({1, 2, 3})}};

        const std::vector<std::pair<json::input_format_t, std::vector<std::uint8_t>>> encodings =
        {
            {json::input_format_t::cbor, json::to_cbor(j)},
            {json::input_format_t::msgpack, json::to_msgpack(j)},
            {json::input_format_t::ubjson, json::to_ubjson(j)},
            {json::input_format_t::ubjson, json::to_ubjson(j, true, true)},
            {json::input_format_t::bjdata, json::to_bjdata(j)},
            {json::input_format_t::bjdata, json::to_bjdata(j, true, true)},
            {json::input_format_t::bson, json::to_bson(j)},
            {json::input_format_t::bon8, json::to_bon8(j)},
        };

        for (const auto& encoding : encodings)
        {
            const auto format = encoding.first;
            const auto& bytes = encoding.second;
            CAPTURE(format)

            // every prefix is truncated input
            for (std::size_t length = 0; length < bytes.size(); ++length)
            {
                CAPTURE(length)
                const auto result = parse_binary_recovering(std::vector<std::uint8_t>(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length)), format);
                CHECK(!result.ok);
                CHECK(result.errors == 1);
                CHECK(result.balanced);
            }

            // the complete input is read as usual (binary values do not
            // round-trip through every format, so compare with a plain parse)
            json expected;
            nlohmann::detail::json_sax_dom_parser<json> dom(expected);
            CHECK(json::sax_parse(bytes, &dom, format));
            const auto complete = parse_binary_recovering(bytes, format);
            CHECK(complete.ok);
            CHECK(complete.errors == 0);
            CHECK(complete.value == expected);

            // a byte after the value
            auto trailing_bytes = bytes;
            trailing_bytes.push_back(0x01);
            const auto trailing = parse_binary_recovering(trailing_bytes, format);
            CHECK(!trailing.ok);
            CHECK(trailing.errors == 1);
            CHECK(trailing.value == expected);
        }
    }

    SECTION("containers without an end")
    {
        // these made the readers loop, or read on, after the error
        const auto cbor_array = parse_binary_recovering({0x9F}, json::input_format_t::cbor);
        CHECK(cbor_array.errors == 1);
        CHECK(cbor_array.value == json::array());

        const auto cbor_map = parse_binary_recovering({0xBF, 0x61, 'a'}, json::input_format_t::cbor);
        CHECK(cbor_map.errors == 1);
        CHECK(cbor_map.value == json({{"a", nullptr}}));

        const auto msgpack_array = parse_binary_recovering({0xDD, 0xFF, 0xFF, 0xFF, 0xFF}, json::input_format_t::msgpack);
        CHECK(msgpack_array.errors == 1);
        CHECK(msgpack_array.value == json::array());

        const auto msgpack_map = parse_binary_recovering({0x81, 0xA1, 'a', 0x92, 0x01}, json::input_format_t::msgpack);
        CHECK(msgpack_map.errors == 1);
        CHECK(msgpack_map.value == json({{"a", {1}}}));
    }

    SECTION("BJData ndarray")
    {
        // a 2x3 int8 array with two of its six elements; the annotated array
        // format opens an object and two arrays of its own
        const auto result = parse_binary_recovering({'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 1, 2}, json::input_format_t::bjdata);
        CHECK(result.errors == 1);
        CHECK(result.balanced);
        CHECK(result.value == json({{"_ArrayType_", "int8"}, {"_ArraySize_", {2, 3}}, {"_ArrayData_", {1, 2}}}));
    }

    SECTION("binary formats repair items whose end is known")
    {
        struct Repair
        {
            json::input_format_t format;
            std::vector<std::uint8_t> input;
            json expected;
            std::size_t errors;
        };

        const std::vector<Repair> repairs =
        {
            // CBOR: tags are ignored (here tag 1 and the self-describe tag 55799)
            {json::input_format_t::cbor, {0x82, 0xC1, 0x05, 0xD9, 0xD9, 0xF7, 0x06}, {5, 6}, 2},
            // CBOR: undefined and other simple values become null
            {json::input_format_t::cbor, {0x84, 0xF7, 0xE0, 0xF8, 0x20, 0x01}, {nullptr, nullptr, nullptr, 1}, 3},
            // CBOR: members whose key is not a string are skipped, whatever their key and value
            {json::input_format_t::cbor, {0xA4, 0x01, 0x02, 0x82, 0x01, 0x02, 0xA1, 0x61, 'x', 0x9F, 0xFF, 0xC1, 0x01, 0x5F, 0x41, 0x00, 0xFF, 0x61, 'a', 0x03}, {{"a", 3}}, 3},
            {json::input_format_t::cbor, {0xBF, 0xF5, 0xBF, 0x61, 'x', 0x7F, 0x61, 'y', 0xFF, 0xFF, 0x61, 'a', 0x03, 0xFF}, {{"a", 3}}, 1},
            // MessagePack: members whose key is not a string are skipped
            {json::input_format_t::msgpack, {0x84, 0x01, 0x02, 0x81, 0xA1, 'x', 0x01, 0x92, 0x01, 0x02, 0xD4, 0x01, 0x02, 0xC0, 0xA1, 'a', 0x04}, {{"a", 4}}, 3},
            // UBJSON: a char that is not ASCII becomes U+FFFD
            {json::input_format_t::ubjson, {'[', 'C', 0x80, 'C', 'A', ']'}, {replacement_character(), "A"}, 1},
            // UBJSON: the longest beginning of a high-precision number is kept
            {json::input_format_t::ubjson, {'[', 'H', 'i', 5, '1', '2', 'a', 'b', 'c', 'H', 'i', 2, '1', '.', 'H', 'i', 3, 'a', 'b', 'c', 'H', 'i', 3, '4', '.', '5', ']'}, {12, 1, nullptr, 4.5}, 3},
            // BJData, too
            {json::input_format_t::bjdata, {'[', 'C', 0xFF, 'H', 'i', 2, '-', '1', 'H', 'i', 2, '-', 'x', ']'}, {replacement_character(), -1, nullptr}, 2},
            // a NUL ends a high-precision number, as it ends JSON text
            {json::input_format_t::ubjson, {'[', 'H', 'i', 4, '1', '2', 0, '9', 'H', 'i', 2, 0, '1', 'i', 3, ']'}, {12, nullptr, 3}, 2},
            // BON8: members whose key is not a string are skipped
            {json::input_format_t::bon8, {0x89, 0x91, 0x92, 0xC9, 0x40, 0x82, 0x91, 0x92, 0x61, 0x93}, {{"a", 3}}, 2},
            {json::input_format_t::bon8, {0x8B, 0x91, 0x85, 0x91, 0xFE, 0xFA, 0x8B, 'x', 0x91, 0xFE, 0x61, 0x93, 0xFE}, {{"a", 3}}, 2},
            // BSON: elements of types the library does not read become null
            {
                json::input_format_t::bson, bson_document(
                {
                    bson_element(0x07, "_id", bytes(12)),                         // ObjectId
                    bson_element(0x09, "date", bytes(8)),                         // UTC datetime
                    bson_element(0x13, "decimal", bytes(16)),                     // 128-bit decimal
                    bson_element(0x0B, "regex", {'a', '+', 0, 'i', 0}),           // regular expression
                    bson_element(0x0D, "code", bson_string("f()")),               // JavaScript code
                    bson_element(0x0E, "symbol", bson_string("s")),               // symbol
                    bson_element(0x0C, "pointer", concatenated({bson_string("c"), bytes(12)})), // DBPointer
                    bson_element(0x0F, "scope", concatenated({bson_int32(15), bson_string("g"), bson_document({})})), // code with scope
                    bson_element(0x06, "undefined", {}),                          // undefined
                    bson_element(0xFF, "min", {}),                                // min key
                    bson_element(0x7F, "max", {}),                                // max key
                    bson_element(0x10, "z", bson_int32(7)),
                }),
                {{"_id", nullptr}, {"date", nullptr}, {"decimal", nullptr}, {"regex", nullptr}, {"code", nullptr}, {"symbol", nullptr}, {"pointer", nullptr}, {"scope", nullptr}, {"undefined", nullptr}, {"min", nullptr}, {"max", nullptr}, {"z", 7}},
                11
            },
            // BSON: an element of an unknown type becomes null, and the rest of its document is skipped
            {
                json::input_format_t::bson, bson_document(
                {
                    bson_element(0x03, "inner", bson_document({bson_element(0x10, "a", bson_int32(1)), bson_element(0x42, "x", bytes(3)), bson_element(0x10, "b", bson_int32(2))})),
                    bson_element(0x04, "array", bson_document({bson_element(0x10, "0", bson_int32(1)), bson_element(0x42, "1", bytes(3))})),
                    bson_element(0x10, "after", bson_int32(3)),
                }),
                {{"inner", {{"a", 1}, {"x", nullptr}}}, {"array", {1, nullptr}}, {"after", 3}},
                2
            },
            // BSON: so does a string or byte array whose length cannot be right
            {
                json::input_format_t::bson, bson_document(
                {
                    bson_element(0x03, "inner", bson_document({bson_element(0x02, "s", bson_string("abc", -10)), bson_element(0x10, "b", bson_int32(2))})),
                    bson_element(0x03, "bin", bson_document({bson_element(0x05, "b", concatenated({bson_int32(-1), bytes(1)})), bson_element(0x10, "b", bson_int32(2))})),
                    bson_element(0x10, "after", bson_int32(3)),
                }),
                {{"inner", {{"s", nullptr}}}, {"bin", {{"b", nullptr}}}, {"after", 3}},
                2
            },
            // BSON: a string without its terminator, and a document whose size does not match, are kept
            {
                json::input_format_t::bson, bson_document(
                {
                    bson_element(0x02, "s", {2, 0, 0, 0, 'a', 'X'}),
                    bson_element(0x03, "inner", bson_document({bson_element(0x10, "a", bson_int32(1))}, 1)),
                }),
                {{"s", "a"}, {"inner", {{"a", 1}}}},
                2
            },
        };

        for (const auto& repair : repairs)
        {
            CAPTURE(repair.format)
            CAPTURE(repair.input)
            const auto result = parse_binary_recovering(repair.input, repair.format);
            CHECK(!result.ok);
            CHECK(result.balanced);
            CHECK(result.errors == repair.errors);
            CHECK(result.value == repair.expected);
            REQUIRE(!result.messages.empty());
#if !defined(JSON_NOEXCEPTION)
            // the first error is the one reported without recovering; under
            // JSON_NOEXCEPTION, reading without recovering aborts instead of
            // throwing, so there is no message to compare with
            CHECK(result.messages.front() == binary_error_message(repair.input, repair.format));
#endif
        }
    }

    SECTION("binary formats repair numbers that are out of range")
    {
        // CBOR: a double too large for a float number_float_t
        float_json cbor;
        BasicRecoveringParser<float_json> sax(cbor);
        const std::vector<std::uint8_t> cbor_input = {0x82, 0xFB, 0x7E, 0x37, 0xE4, 0x3C, 0x88, 0x00, 0x75, 0x9C, 0x01}; // [1e300, 1]
        CHECK(!float_json::sax_parse(cbor_input, &sax, float_json::input_format_t::cbor));
        CHECK(sax.errors == 1);
        CHECK(sax.messages.front() == "[json.exception.out_of_range.406] syntax error while parsing CBOR value: number overflow");
        REQUIRE(cbor.size() == 2);
        CHECK(std::isinf(cbor[0].get<float>()));
        CHECK(cbor[1] == 1);

        // UBJSON: a high-precision number too large for number_float_t
        const auto ubjson = parse_binary_recovering({'H', 'i', 5, '1', 'e', '9', '9', '9'}, json::input_format_t::ubjson);
        CHECK(ubjson.errors == 1);
        CHECK(ubjson.value.is_number_float());
        CHECK(std::isinf(ubjson.value.get<double>()));
    }

    SECTION("binary formats stop where the end of an item is not known")
    {
        // a byte that begins no item
        const auto cbor = parse_binary_recovering({0x82, 0x01, 0x1C, 0x02}, json::input_format_t::cbor);
        CHECK(cbor.errors == 1);
        CHECK(cbor.value == json({1}));

        // a key that is no item: the unused MessagePack byte, a CBOR break
        // in a map of known size, and the end of a BON8 container
        const auto msgpack = parse_binary_recovering({0x82, 0xA1, 'a', 0x01, 0xC1, 0x02}, json::input_format_t::msgpack);
        CHECK(msgpack.errors == 1);
        CHECK(msgpack.value == json({{"a", 1}}));
        const auto cbor_break = parse_binary_recovering({0xA2, 0x61, 'a', 0x01, 0xFF, 0x02}, json::input_format_t::cbor);
        CHECK(cbor_break.errors == 1);
        CHECK(cbor_break.value == json({{"a", 1}}));
        const auto bon8 = parse_binary_recovering({0x88, 0x61, 0x91, 0xFE}, json::input_format_t::bon8);
        CHECK(bon8.errors == 1);
        CHECK(bon8.value == json({{"a", 1}}));

        // an indefinite-length string inside an indefinite-length string
        const auto nested = parse_binary_recovering({0x82, 0x01, 0x7F, 0x7F, 0x61, 'a', 0xFF, 0xFF}, json::input_format_t::cbor);
        CHECK(nested.errors == 1);
        CHECK(nested.value == json({1}));

        // a BJData ndarray whose element type has no name: the object that
        // holds the ndarray was already begun
        const auto ndarray = parse_binary_recovering({'[', '$', 0x01, '#', '[', '$', 'i', '#', 'i', 2, 2, 3}, json::input_format_t::bjdata);
        CHECK(ndarray.errors == 1);
        CHECK(ndarray.balanced);
        CHECK(ndarray.value == json::object());

        // a skipped member that the input ends in
        const auto truncated = parse_binary_recovering({0xA2, 0x01, 0x82, 0x01}, json::input_format_t::cbor);
        CHECK(truncated.errors == 2);
        CHECK(truncated.balanced);
        CHECK(truncated.value == json::object());

        // a BSON element of an unknown type in a document whose size cannot be right
        const auto bson = parse_binary_recovering(bson_document({bson_element(0x10, "a", bson_int32(1)), bson_element(0x42, "x", bytes(3))}, -10), json::input_format_t::bson);
        CHECK(bson.errors == 1);
        CHECK(bson.value == json({{"a", 1}, {"x", nullptr}}));
    }

    SECTION("changed bytes in binary input")
    {
        const json j = {{"a", {1, -2, {{"b", "c"}}, json::array()}}, {"d", {{"e", nullptr}, {"f", true}}}, {"g", 1.5}, {"h", json::binary({1, 2, 3})}, {"i", "\xC3\xA4"}};

        const std::vector<std::pair<json::input_format_t, std::vector<std::uint8_t>>> encodings =
        {
            {json::input_format_t::cbor, json::to_cbor(j)},
            {json::input_format_t::msgpack, json::to_msgpack(j)},
            {json::input_format_t::ubjson, json::to_ubjson(j)},
            {json::input_format_t::ubjson, json::to_ubjson(j, true, true)},
            {json::input_format_t::bjdata, json::to_bjdata(j)},
            {json::input_format_t::bjdata, json::to_bjdata(j, true, true)},
            {json::input_format_t::bson, json::to_bson(j)},
            {json::input_format_t::bon8, json::to_bon8(j)},
        };
        const std::vector<std::uint8_t> replacements = {0x00, 0x01, 0x7F, 0x80, 0xC1, 0xD9, 0xE0, 0xF7, 0xFE, 0xFF};

        for (const auto& encoding : encodings)
        {
            const auto format = encoding.first;
            const auto& original = encoding.second;
            CAPTURE(format)

            std::vector<std::vector<std::uint8_t>> inputs;
            for (std::size_t position = 0; position < original.size(); ++position)
            {
                for (const auto replacement : replacements)
                {
                    auto changed = original;
                    changed[position] = replacement;
                    inputs.push_back(changed);
                }
                auto removed = original;
                removed.erase(removed.begin() + static_cast<std::ptrdiff_t>(position));
                inputs.push_back(removed);
            }

            for (const auto& input : inputs)
            {
                CAPTURE(input)
                const auto result = parse_binary_recovering(input, format);
                CHECK(result.balanced);
                CHECK(result.errors <= input.size() + 1);
#if !defined(JSON_NOEXCEPTION)
                // an error is reported exactly if reading into a JSON value
                // fails, and the first one is the same (under JSON_NOEXCEPTION,
                // that reading aborts instead of throwing)
                const auto message = binary_error_message(input, format);
                CHECK(result.ok == message.empty());
                if (!result.ok && result.errors < 100)
                {
                    CHECK(result.messages.front() == message);
                }
#endif
            }
        }
    }

    SECTION("JSON text")
    {
        // the parser stopped, but reported success
        json j;
        RecoveringParser sax(j);
        CHECK(!json::sax_parse("[1,2,3,]", &sax));
        CHECK(sax.errors == 1);
        CHECK(j == json({1, 2, 3}));
    }

    SECTION("the SAX parsers of the library stop")
    {
        json _;
        CHECK(json::from_cbor(std::vector<std::uint8_t> {0x9F}, true, false).is_discarded());
        CHECK_THROWS_WITH_AS(_ = json::from_cbor(std::vector<std::uint8_t> {0x9F}), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR value: unexpected end of input", json::parse_error&);
        CHECK(json::parse("[1,2,3,]", nullptr, false).is_discarded());
        CHECK(!json::accept("[1,2,3,]"));
    }
}


TEST_CASE("issue #5676 - SAX parsing of CBOR tags")
{
    const json expected = json::binary({1, 2, 3}, 42);
    const auto cbor = json::to_cbor(expected);

    nlohmann::detail::json_sax_acceptor<json> acceptor;
    CHECK_FALSE(json::sax_parse(cbor, &acceptor, json::input_format_t::cbor));
    CHECK_FALSE(json::sax_parse(cbor, &acceptor, json::input_format_t::cbor,
                                true, false, false, json::cbor_tag_handler_t::error));

    CHECK(json::sax_parse(cbor, &acceptor, json::input_format_t::cbor,
                          true, false, false, json::cbor_tag_handler_t::ignore));

    json parsed;
    nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type> sax(parsed);
    CHECK(json::sax_parse(cbor, &sax, json::input_format_t::cbor,
                          true, false, false, json::cbor_tag_handler_t::store));
    CHECK(parsed == expected);

    json iterator_parsed;
    nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type> iterator_sax(iterator_parsed);
    CHECK(json::sax_parse(cbor.begin(), cbor.end(), &iterator_sax, json::input_format_t::cbor,
                          true, false, false, json::cbor_tag_handler_t::store));
    CHECK(iterator_parsed == expected);

#ifndef JSON_TEST_DEPRECATED_FUNCTIONS_DELETED
    json span_parsed;
    nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type> span_sax(span_parsed);
    CHECK(json::sax_parse(nlohmann::detail::span_input_adapter(cbor.data(), cbor.size()), &span_sax,
                          json::input_format_t::cbor, true, false, false, json::cbor_tag_handler_t::store));
    CHECK(span_parsed == expected);
#endif

    const std::string text = "null";
    CHECK(json::sax_parse(text, &acceptor, json::input_format_t::json,
                          true, false, false, json::cbor_tag_handler_t::store));
    CHECK(json::sax_parse(text.begin(), text.end(), &acceptor, json::input_format_t::json,
                          true, false, false, json::cbor_tag_handler_t::store));
#ifndef JSON_TEST_DEPRECATED_FUNCTIONS_DELETED
    CHECK(json::sax_parse(nlohmann::detail::span_input_adapter(text.data(), text.size()), &acceptor,
                          json::input_format_t::json, true, false, false, json::cbor_tag_handler_t::store));
#endif
}


TEST_CASE("MessagePack SAX aborts")
{
    SECTION("start_array(len)")
    {
        std::vector<uint8_t> const v = {0x93, 0x01, 0x02, 0x03};
        SaxCountdown scp(0);
        CHECK(!json::sax_parse(v, &scp, json::input_format_t::msgpack));
    }

    SECTION("start_object(len)")
    {
        std::vector<uint8_t> const v = {0x81, 0xa3, 0x66, 0x6F, 0x6F, 0xc2};
        SaxCountdown scp(0);
        CHECK(!json::sax_parse(v, &scp, json::input_format_t::msgpack));
    }

    SECTION("key()")
    {
        std::vector<uint8_t> const v = {0x81, 0xa3, 0x66, 0x6F, 0x6F, 0xc2};
        SaxCountdown scp(1);
        CHECK(!json::sax_parse(v, &scp, json::input_format_t::msgpack));
    }
}

TEST_CASE("issue #5405 - a user-defined SAX consumer is unaffected by the internal DOM reserve optimization")
{
    // the reserve() call is local to json_sax_dom_parser / json_sax_dom_callback_parser;
    // a custom SAX consumer that does not touch a DOM array sees identical events
    json j = json::array();
    for (int i = 0; i < 100; ++i)
    {
        j.push_back(i);
    }
    const auto packed = json::to_msgpack(j);

    SaxCountdown scp(1000000); // large enough to never trigger an abort
    CHECK(json::sax_parse(packed, &scp, json::input_format_t::msgpack));
}

TEST_CASE("MessagePack nesting does not consume the call stack - SAX interface")
{
    // see the test case of the same name in unit-msgpack.cpp (#5104)
    std::vector<uint8_t> input(300000, 0x91);
    input.push_back(0x01); // innermost value

    SaxCountdown accept_all(600001);
    CHECK(json::sax_parse(input, &accept_all, json::input_format_t::msgpack));
}

TEST_CASE("MessagePack SAX parsing stops at every event")
{
    // Containers are opened and closed by the loop that reads them; a SAX
    // handler that rejects any event - including the end of a nested
    // container - must stop the parse right there.
    const auto count_events = [](const std::vector<std::uint8_t>& input)
    {
        int events = 0;
        while (true)
        {
            SaxCountdown scp(events);
            if (json::sax_parse(input, &scp, json::input_format_t::msgpack))
            {
                return events;
            }
            ++events;
            REQUIRE(events < 1000);
        }
    };

    // 20 events: every container kind closes inside another one
    const json j = json::parse(R"({"a": [1, {"b": []}], "c": {"d": [[2]]}})");
    CHECK(count_events(json::to_msgpack(j)) == 20);
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
