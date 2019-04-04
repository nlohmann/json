/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.6.1
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <fstream>
#include <sstream>

TEST_CASE("BSON")
{
    SECTION("individual values not supported")
    {
        SECTION("null")
        {
            json j = nullptr;
            CHECK_THROWS_AS(json::to_bson(j), json::type_error&);
            CHECK_THROWS_WITH(json::to_bson(j), "[json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is null");
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json j = true;
                CHECK_THROWS_AS(json::to_bson(j), json::type_error&);
                CHECK_THROWS_WITH(json::to_bson(j), "[json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is boolean");
            }

            SECTION("false")
            {
                json j = false;
                CHECK_THROWS_AS(json::to_bson(j), json::type_error&);
                CHECK_THROWS_WITH(json::to_bson(j), "[json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is boolean");
            }
        }

        SECTION("number")
        {
            json j = 42;
            CHECK_THROWS_AS(json::to_bson(j), json::type_error&);
            CHECK_THROWS_WITH(json::to_bson(j), "[json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is number");
        }

        SECTION("float")
        {
            json j = 4.2;
            CHECK_THROWS_AS(json::to_bson(j), json::type_error&);
            CHECK_THROWS_WITH(json::to_bson(j), "[json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is number");
        }

        SECTION("string")
        {
            json j = "not supported";
            CHECK_THROWS_AS(json::to_bson(j), json::type_error&);
            CHECK_THROWS_WITH(json::to_bson(j), "[json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is string");
        }

        SECTION("array")
        {
            json j = std::vector<int> {1, 2, 3, 4, 5, 6, 7};
            CHECK_THROWS_AS(json::to_bson(j), json::type_error&);
            CHECK_THROWS_WITH(json::to_bson(j), "[json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is array");
        }
    }

    SECTION("keys containing code-point U+0000 cannot be serialized to BSON")
    {
        json j =
        {
            { std::string("en\0try", 6), true }
        };
        CHECK_THROWS_AS(json::to_bson(j), json::out_of_range&);
        CHECK_THROWS_WITH(json::to_bson(j), "[json.exception.out_of_range.409] BSON key cannot contain code point U+0000 (at byte 2)");
    }

    SECTION("string length must be at least 1")
    {
        // from https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=11175
        std::vector<uint8_t> v =
        {
            0x20, 0x20, 0x20, 0x20,
            0x02,
            0x00,
            0x00, 0x00, 0x00, 0x80
        };
        CHECK_THROWS_AS(json::from_bson(v), json::parse_error&);
        CHECK_THROWS_WITH(json::from_bson(v), "[json.exception.parse_error.112] parse error at byte 10: syntax error while parsing BSON string: string length must be at least 1, is -2147483648");
    }

    SECTION("objects")
    {
        SECTION("empty object")
        {
            json j = json::object();
            std::vector<uint8_t> expected =
            {
                0x05, 0x00, 0x00, 0x00, // size (little endian)
                // no entries
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with bool")
        {
            json j =
            {
                { "entry", true }
            };

            std::vector<uint8_t> expected =
            {
                0x0D, 0x00, 0x00, 0x00, // size (little endian)
                0x08,               // entry: boolean
                'e', 'n', 't', 'r', 'y', '\x00',
                0x01,           // value = true
                0x00                    // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with bool")
        {
            json j =
            {
                { "entry", false }
            };

            std::vector<uint8_t> expected =
            {
                0x0D, 0x00, 0x00, 0x00, // size (little endian)
                0x08,               // entry: boolean
                'e', 'n', 't', 'r', 'y', '\x00',
                0x00,           // value = false
                0x00                    // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with double")
        {
            json j =
            {
                { "entry", 4.2 }
            };

            std::vector<uint8_t> expected =
            {
                0x14, 0x00, 0x00, 0x00, // size (little endian)
                0x01, /// entry: double
                'e', 'n', 't', 'r', 'y', '\x00',
                0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x10, 0x40,
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with string")
        {
            json j =
            {
                { "entry", "bsonstr" }
            };

            std::vector<uint8_t> expected =
            {
                0x18, 0x00, 0x00, 0x00, // size (little endian)
                0x02, /// entry: string (UTF-8)
                'e', 'n', 't', 'r', 'y', '\x00',
                0x08, 0x00, 0x00, 0x00, 'b', 's', 'o', 'n', 's', 't', 'r', '\x00',
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with null member")
        {
            json j =
            {
                { "entry", nullptr }
            };

            std::vector<uint8_t> expected =
            {
                0x0C, 0x00, 0x00, 0x00, // size (little endian)
                0x0A, /// entry: null
                'e', 'n', 't', 'r', 'y', '\x00',
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with integer (32-bit) member")
        {
            json j =
            {
                { "entry", std::int32_t{0x12345678} }
            };

            std::vector<uint8_t> expected =
            {
                0x10, 0x00, 0x00, 0x00, // size (little endian)
                0x10, /// entry: int32
                'e', 'n', 't', 'r', 'y', '\x00',
                0x78, 0x56, 0x34, 0x12,
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with integer (64-bit) member")
        {
            json j =
            {
                { "entry", std::int64_t{0x1234567804030201} }
            };

            std::vector<uint8_t> expected =
            {
                0x14, 0x00, 0x00, 0x00, // size (little endian)
                0x12, /// entry: int64
                'e', 'n', 't', 'r', 'y', '\x00',
                0x01, 0x02, 0x03, 0x04, 0x78, 0x56, 0x34, 0x12,
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with negative integer (32-bit) member")
        {
            json j =
            {
                { "entry", std::int32_t{-1} }
            };

            std::vector<uint8_t> expected =
            {
                0x10, 0x00, 0x00, 0x00, // size (little endian)
                0x10, /// entry: int32
                'e', 'n', 't', 'r', 'y', '\x00',
                0xFF, 0xFF, 0xFF, 0xFF,
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with negative integer (64-bit) member")
        {
            json j =
            {
                { "entry", std::int64_t{-1} }
            };

            std::vector<uint8_t> expected =
            {
                0x10, 0x00, 0x00, 0x00, // size (little endian)
                0x10, /// entry: int32
                'e', 'n', 't', 'r', 'y', '\x00',
                0xFF, 0xFF, 0xFF, 0xFF,
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with unsigned integer (64-bit) member")
        {
            // directly encoding uint64 is not supported in bson (only for timestamp values)
            json j =
            {
                { "entry", std::uint64_t{0x1234567804030201} }
            };

            std::vector<uint8_t> expected =
            {
                0x14, 0x00, 0x00, 0x00, // size (little endian)
                0x12, /// entry: int64
                'e', 'n', 't', 'r', 'y', '\x00',
                0x01, 0x02, 0x03, 0x04, 0x78, 0x56, 0x34, 0x12,
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with small unsigned integer member")
        {
            json j =
            {
                { "entry", std::uint64_t{0x42} }
            };

            std::vector<uint8_t> expected =
            {
                0x10, 0x00, 0x00, 0x00, // size (little endian)
                0x10, /// entry: int32
                'e', 'n', 't', 'r', 'y', '\x00',
                0x42, 0x00, 0x00, 0x00,
                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with object member")
        {
            json j =
            {
                { "entry", json::object() }
            };

            std::vector<uint8_t> expected =
            {
                0x11, 0x00, 0x00, 0x00, // size (little endian)
                0x03, /// entry: embedded document
                'e', 'n', 't', 'r', 'y', '\x00',

                0x05, 0x00, 0x00, 0x00, // size (little endian)
                // no entries
                0x00, // end marker (embedded document)

                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with array member")
        {
            json j =
            {
                { "entry", json::array() }
            };

            std::vector<uint8_t> expected =
            {
                0x11, 0x00, 0x00, 0x00, // size (little endian)
                0x04, /// entry: embedded document
                'e', 'n', 't', 'r', 'y', '\x00',

                0x05, 0x00, 0x00, 0x00, // size (little endian)
                // no entries
                0x00, // end marker (embedded document)

                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("non-empty object with non-empty array member")
        {
            json j =
            {
                { "entry", json::array({1, 2, 3, 4, 5, 6, 7, 8}) }
            };

            std::vector<uint8_t> expected =
            {
                0x49, 0x00, 0x00, 0x00, // size (little endian)
                0x04, /// entry: embedded document
                'e', 'n', 't', 'r', 'y', '\x00',

                0x3D, 0x00, 0x00, 0x00, // size (little endian)
                0x10, '0', 0x00, 0x01, 0x00, 0x00, 0x00,
                0x10, '1', 0x00, 0x02, 0x00, 0x00, 0x00,
                0x10, '2', 0x00, 0x03, 0x00, 0x00, 0x00,
                0x10, '3', 0x00, 0x04, 0x00, 0x00, 0x00,
                0x10, '4', 0x00, 0x05, 0x00, 0x00, 0x00,
                0x10, '5', 0x00, 0x06, 0x00, 0x00, 0x00,
                0x10, '6', 0x00, 0x07, 0x00, 0x00, 0x00,
                0x10, '7', 0x00, 0x08, 0x00, 0x00, 0x00,
                0x00, // end marker (embedded document)

                0x00 // end marker
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }

        SECTION("Some more complex document")
        {
            // directly encoding uint64 is not supported in bson (only for timestamp values)
            json j =
            {
                {"double", 42.5},
                {"entry", 4.2},
                {"number", 12345},
                {"object", {{ "string", "value" }}}
            };

            std::vector<uint8_t> expected =
            {
                /*size */ 0x4f, 0x00, 0x00, 0x00,
                /*entry*/ 0x01, 'd',  'o',  'u',  'b',  'l',  'e',  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x45, 0x40,
                /*entry*/ 0x01, 'e',  'n',  't',  'r',  'y',  0x00, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x10, 0x40,
                /*entry*/ 0x10, 'n',  'u',  'm',  'b',  'e',  'r',  0x00, 0x39, 0x30, 0x00, 0x00,
                /*entry*/ 0x03, 'o',  'b',  'j',  'e',  'c',  't',  0x00,
                /*entry: obj-size */ 0x17, 0x00, 0x00, 0x00,
                /*entry: obj-entry*/0x02, 's',  't',  'r',  'i',  'n',  'g', 0x00, 0x06, 0x00, 0x00, 0x00, 'v', 'a', 'l', 'u', 'e', 0,
                /*entry: obj-term.*/0x00,
                /*obj-term*/ 0x00
            };

            const auto result = json::to_bson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bson(result) == j);
            CHECK(json::from_bson(result, true, false) == j);
        }
    }

    SECTION("Examples from http://bsonspec.org/faq.html")
    {
        SECTION("Example 1")
        {
            std::vector<std::uint8_t> input = {0x16, 0x00, 0x00, 0x00, 0x02, 'h', 'e', 'l', 'l', 'o', 0x00, 0x06, 0x00, 0x00, 0x00, 'w', 'o', 'r', 'l', 'd', 0x00, 0x00};
            json parsed = json::from_bson(input);
            json expected = {{"hello", "world"}};
            CHECK(parsed == expected);
            auto dumped = json::to_bson(parsed);
            CHECK(dumped == input);
            CHECK(json::from_bson(dumped) == expected);
        }

        SECTION("Example 2")
        {
            std::vector<std::uint8_t> input = {0x31, 0x00, 0x00, 0x00, 0x04, 'B', 'S', 'O', 'N', 0x00, 0x26, 0x00, 0x00, 0x00, 0x02, 0x30, 0x00, 0x08, 0x00, 0x00, 0x00, 'a', 'w', 'e', 's', 'o', 'm', 'e', 0x00, 0x01, 0x31, 0x00, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x14, 0x40, 0x10, 0x32, 0x00, 0xc2, 0x07, 0x00, 0x00, 0x00, 0x00};
            json parsed = json::from_bson(input);
            json expected = {{"BSON", {"awesome", 5.05, 1986}}};
            CHECK(parsed == expected);
            auto dumped = json::to_bson(parsed);
            CHECK(dumped == input);
            CHECK(json::from_bson(dumped) == expected);
        }
    }
}

TEST_CASE("BSON input/output_adapters")
{
    json json_representation =
    {
        {"double", 42.5},
        {"entry", 4.2},
        {"number", 12345},
        {"object", {{ "string", "value" }}}
    };

    std::vector<uint8_t> bson_representation =
    {
        /*size */ 0x4f, 0x00, 0x00, 0x00,
        /*entry*/ 0x01, 'd',  'o',  'u',  'b',  'l',  'e',  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x45, 0x40,
        /*entry*/ 0x01, 'e',  'n',  't',  'r',  'y',  0x00, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x10, 0x40,
        /*entry*/ 0x10, 'n',  'u',  'm',  'b',  'e',  'r',  0x00, 0x39, 0x30, 0x00, 0x00,
        /*entry*/ 0x03, 'o',  'b',  'j',  'e',  'c',  't',  0x00,
        /*entry: obj-size */ 0x17, 0x00, 0x00, 0x00,
        /*entry: obj-entry*/0x02, 's',  't',  'r',  'i',  'n',  'g', 0x00, 0x06, 0x00, 0x00, 0x00, 'v', 'a', 'l', 'u', 'e', 0,
        /*entry: obj-term.*/0x00,
        /*obj-term*/ 0x00
    };

    json j2;
    CHECK_NOTHROW(j2 = json::from_bson(bson_representation));

    // compare parsed JSON values
    CHECK(json_representation == j2);

    SECTION("roundtrips")
    {
        SECTION("std::ostringstream")
        {
            std::ostringstream ss;
            json::to_bson(json_representation, ss);
            std::istringstream iss(ss.str());
            json j3 = json::from_bson(iss);
            CHECK(json_representation == j3);
        }

        SECTION("std::string")
        {
            std::string s;
            json::to_bson(json_representation, s);
            json j3 = json::from_bson(s);
            CHECK(json_representation == j3);
        }

        SECTION("std::vector")
        {
            std::vector<std::uint8_t> v;
            json::to_bson(json_representation, v);
            json j3 = json::from_bson(v);
            CHECK(json_representation == j3);
        }
    }
}

namespace
{
class SaxCountdown
{
  public:
    explicit SaxCountdown(const int count) : events_left(count)
    {}

    bool null()
    {
        return events_left-- > 0;
    }

    bool boolean(bool)
    {
        return events_left-- > 0;
    }

    bool number_integer(json::number_integer_t)
    {
        return events_left-- > 0;
    }

    bool number_unsigned(json::number_unsigned_t)
    {
        return events_left-- > 0;
    }

    bool number_float(json::number_float_t, const std::string&)
    {
        return events_left-- > 0;
    }

    bool string(std::string&)
    {
        return events_left-- > 0;
    }

    bool start_object(std::size_t)
    {
        return events_left-- > 0;
    }

    bool key(std::string&)
    {
        return events_left-- > 0;
    }

    bool end_object()
    {
        return events_left-- > 0;
    }

    bool start_array(std::size_t)
    {
        return events_left-- > 0;
    }

    bool end_array()
    {
        return events_left-- > 0;
    }

    bool parse_error(std::size_t, const std::string&, const json::exception&)
    {
        return false;
    }

  private:
    int events_left = 0;
};
}

TEST_CASE("Incomplete BSON Input")
{
    SECTION("Incomplete BSON Input 1")
    {
        std::vector<uint8_t> incomplete_bson =
        {
            0x0D, 0x00, 0x00, 0x00, // size (little endian)
            0x08,                   // entry: boolean
            'e', 'n', 't'           // unexpected EOF
        };

        CHECK_THROWS_AS(json::from_bson(incomplete_bson), json::parse_error&);
        CHECK_THROWS_WITH(json::from_bson(incomplete_bson),
                          "[json.exception.parse_error.110] parse error at byte 9: syntax error while parsing BSON cstring: unexpected end of input");

        CHECK(json::from_bson(incomplete_bson, true, false).is_discarded());

        SaxCountdown scp(0);
        CHECK(not json::sax_parse(incomplete_bson, &scp, json::input_format_t::bson));
    }

    SECTION("Incomplete BSON Input 2")
    {
        std::vector<uint8_t> incomplete_bson =
        {
            0x0D, 0x00, 0x00, 0x00, // size (little endian)
            0x08,                   // entry: boolean, unexpected EOF
        };

        CHECK_THROWS_AS(json::from_bson(incomplete_bson), json::parse_error&);
        CHECK_THROWS_WITH(json::from_bson(incomplete_bson),
                          "[json.exception.parse_error.110] parse error at byte 6: syntax error while parsing BSON cstring: unexpected end of input");
        CHECK(json::from_bson(incomplete_bson, true, false).is_discarded());

        SaxCountdown scp(0);
        CHECK(not json::sax_parse(incomplete_bson, &scp, json::input_format_t::bson));
    }

    SECTION("Incomplete BSON Input 3")
    {
        std::vector<uint8_t> incomplete_bson =
        {
            0x41, 0x00, 0x00, 0x00, // size (little endian)
            0x04, /// entry: embedded document
            'e', 'n', 't', 'r', 'y', '\x00',

            0x35, 0x00, 0x00, 0x00, // size (little endian)
            0x10, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x02, 0x00, 0x00, 0x00
            // missing input data...
        };

        CHECK_THROWS_AS(json::from_bson(incomplete_bson), json::parse_error&);
        CHECK_THROWS_WITH(json::from_bson(incomplete_bson),
                          "[json.exception.parse_error.110] parse error at byte 28: syntax error while parsing BSON element list: unexpected end of input");
        CHECK(json::from_bson(incomplete_bson, true, false).is_discarded());

        SaxCountdown scp(1);
        CHECK(not json::sax_parse(incomplete_bson, &scp, json::input_format_t::bson));
    }

    SECTION("Incomplete BSON Input 4")
    {
        std::vector<uint8_t> incomplete_bson =
        {
            0x0D, 0x00, // size (incomplete), unexpected EOF
        };

        CHECK_THROWS_AS(json::from_bson(incomplete_bson), json::parse_error&);
        CHECK_THROWS_WITH(json::from_bson(incomplete_bson),
                          "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BSON number: unexpected end of input");
        CHECK(json::from_bson(incomplete_bson, true, false).is_discarded());

        SaxCountdown scp(0);
        CHECK(not json::sax_parse(incomplete_bson, &scp, json::input_format_t::bson));
    }

    SECTION("Improve coverage")
    {
        SECTION("key")
        {
            json j = {{"key", "value"}};
            auto bson_vec = json::to_bson(j);
            SaxCountdown scp(2);
            CHECK(not json::sax_parse(bson_vec, &scp, json::input_format_t::bson));
        }

        SECTION("array")
        {
            json j =
            {
                { "entry", json::array() }
            };
            auto bson_vec = json::to_bson(j);
            SaxCountdown scp(2);
            CHECK(not json::sax_parse(bson_vec, &scp, json::input_format_t::bson));
        }
    }
}

TEST_CASE("Unsupported BSON input")
{
    std::vector<uint8_t> bson =
    {
        0x0C, 0x00, 0x00, 0x00, // size (little endian)
        0xFF,                   // entry type: Min key (not supported yet)
        'e', 'n', 't', 'r', 'y', '\x00',
        0x00 // end marker
    };

    CHECK_THROWS_AS(json::from_bson(bson), json::parse_error&);
    CHECK_THROWS_WITH(json::from_bson(bson),
                      "[json.exception.parse_error.114] parse error at byte 5: Unsupported BSON record type 0xFF");
    CHECK(json::from_bson(bson, true, false).is_discarded());

    SaxCountdown scp(0);
    CHECK(not json::sax_parse(bson, &scp, json::input_format_t::bson));
}

TEST_CASE("BSON numerical data")
{
    SECTION("number")
    {
        SECTION("signed")
        {
            SECTION("std::int64_t: INT64_MIN .. INT32_MIN-1")
            {
                std::vector<int64_t> numbers
                {
                    INT64_MIN,
                    -1000000000000000000LL,
                    -100000000000000000LL,
                    -10000000000000000LL,
                    -1000000000000000LL,
                    -100000000000000LL,
                    -10000000000000LL,
                    -1000000000000LL,
                    -100000000000LL,
                    -10000000000LL,
                    static_cast<std::int64_t>(INT32_MIN) - 1,
                };

                for (auto i : numbers)
                {

                    CAPTURE(i)

                    json j =
                    {
                        { "entry", i }
                    };
                    CHECK(j.at("entry").is_number_integer());

                    std::uint64_t iu = *reinterpret_cast<std::uint64_t*>(&i);
                    std::vector<uint8_t> expected_bson =
                    {
                        0x14u, 0x00u, 0x00u, 0x00u, // size (little endian)
                        0x12u, /// entry: int64
                        'e', 'n', 't', 'r', 'y', '\x00',
                        static_cast<uint8_t>((iu >> (8u * 0u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 1u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 2u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 3u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 4u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 5u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 6u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 7u)) & 0xffu),
                        0x00u // end marker
                    };

                    const auto bson = json::to_bson(j);
                    CHECK(bson == expected_bson);

                    auto j_roundtrip = json::from_bson(bson);

                    CHECK(j_roundtrip.at("entry").is_number_integer());
                    CHECK(j_roundtrip == j);
                    CHECK(json::from_bson(bson, true, false) == j);

                }
            }


            SECTION("signed std::int32_t: INT32_MIN .. INT32_MAX")
            {
                std::vector<int32_t> numbers
                {
                    INT32_MIN,
                    -2147483647L,
                    -1000000000L,
                    -100000000L,
                    -10000000L,
                    -1000000L,
                    -100000L,
                    -10000L,
                    -1000L,
                    -100L,
                    -10L,
                    -1L,
                    0L,
                    1L,
                    10L,
                    100L,
                    1000L,
                    10000L,
                    100000L,
                    1000000L,
                    10000000L,
                    100000000L,
                    1000000000L,
                    2147483646L,
                    INT32_MAX
                };

                for (auto i : numbers)
                {

                    CAPTURE(i)

                    json j =
                    {
                        { "entry", i }
                    };
                    CHECK(j.at("entry").is_number_integer());

                    std::uint32_t iu = *reinterpret_cast<std::uint32_t*>(&i);
                    std::vector<uint8_t> expected_bson =
                    {
                        0x10u, 0x00u, 0x00u, 0x00u, // size (little endian)
                        0x10u, /// entry: int32
                        'e', 'n', 't', 'r', 'y', '\x00',
                        static_cast<uint8_t>((iu >> (8u * 0u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 1u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 2u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 3u)) & 0xffu),
                        0x00u // end marker
                    };

                    const auto bson = json::to_bson(j);
                    CHECK(bson == expected_bson);

                    auto j_roundtrip = json::from_bson(bson);

                    CHECK(j_roundtrip.at("entry").is_number_integer());
                    CHECK(j_roundtrip == j);
                    CHECK(json::from_bson(bson, true, false) == j);

                }
            }

            SECTION("signed std::int64_t: INT32_MAX+1 .. INT64_MAX")
            {
                std::vector<int64_t> numbers
                {
                    INT64_MAX,
                    1000000000000000000LL,
                    100000000000000000LL,
                    10000000000000000LL,
                    1000000000000000LL,
                    100000000000000LL,
                    10000000000000LL,
                    1000000000000LL,
                    100000000000LL,
                    10000000000LL,
                    static_cast<std::int64_t>(INT32_MAX) + 1,
                };

                for (auto i : numbers)
                {

                    CAPTURE(i)

                    json j =
                    {
                        { "entry", i }
                    };
                    CHECK(j.at("entry").is_number_integer());

                    std::uint64_t iu = *reinterpret_cast<std::uint64_t*>(&i);
                    std::vector<uint8_t> expected_bson =
                    {
                        0x14u, 0x00u, 0x00u, 0x00u, // size (little endian)
                        0x12u, /// entry: int64
                        'e', 'n', 't', 'r', 'y', '\x00',
                        static_cast<uint8_t>((iu >> (8u * 0u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 1u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 2u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 3u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 4u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 5u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 6u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 7u)) & 0xffu),
                        0x00u // end marker
                    };

                    const auto bson = json::to_bson(j);
                    CHECK(bson == expected_bson);

                    auto j_roundtrip = json::from_bson(bson);

                    CHECK(j_roundtrip.at("entry").is_number_integer());
                    CHECK(j_roundtrip == j);
                    CHECK(json::from_bson(bson, true, false) == j);

                }
            }
        }

        SECTION("unsigned")
        {
            SECTION("unsigned std::uint64_t: 0 .. INT32_MAX")
            {
                std::vector<std::uint64_t> numbers
                {
                    0ULL,
                    1ULL,
                    10ULL,
                    100ULL,
                    1000ULL,
                    10000ULL,
                    100000ULL,
                    1000000ULL,
                    10000000ULL,
                    100000000ULL,
                    1000000000ULL,
                    2147483646ULL,
                    static_cast<std::uint64_t>(INT32_MAX)
                };

                for (auto i : numbers)
                {

                    CAPTURE(i)

                    json j =
                    {
                        { "entry", i }
                    };

                    auto iu = i;
                    std::vector<uint8_t> expected_bson =
                    {
                        0x10u, 0x00u, 0x00u, 0x00u, // size (little endian)
                        0x10u, /// entry: int32
                        'e', 'n', 't', 'r', 'y', '\x00',
                        static_cast<uint8_t>((iu >> (8u * 0u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 1u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 2u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 3u)) & 0xffu),
                        0x00u // end marker
                    };

                    const auto bson = json::to_bson(j);
                    CHECK(bson == expected_bson);

                    auto j_roundtrip = json::from_bson(bson);

                    CHECK(j.at("entry").is_number_unsigned());
                    CHECK(j_roundtrip.at("entry").is_number_integer());
                    CHECK(j_roundtrip == j);
                    CHECK(json::from_bson(bson, true, false) == j);

                }
            }

            SECTION("unsigned std::uint64_t: INT32_MAX+1 .. INT64_MAX")
            {
                std::vector<std::uint64_t> numbers
                {
                    static_cast<std::uint64_t>(INT32_MAX) + 1,
                    4000000000ULL,
                    static_cast<std::uint64_t>(UINT32_MAX),
                    10000000000ULL,
                    100000000000ULL,
                    1000000000000ULL,
                    10000000000000ULL,
                    100000000000000ULL,
                    1000000000000000ULL,
                    10000000000000000ULL,
                    100000000000000000ULL,
                    1000000000000000000ULL,
                    static_cast<std::uint64_t>(INT64_MAX),
                };

                for (auto i : numbers)
                {

                    CAPTURE(i)

                    json j =
                    {
                        { "entry", i }
                    };

                    auto iu = i;
                    std::vector<uint8_t> expected_bson =
                    {
                        0x14u, 0x00u, 0x00u, 0x00u, // size (little endian)
                        0x12u, /// entry: int64
                        'e', 'n', 't', 'r', 'y', '\x00',
                        static_cast<uint8_t>((iu >> (8u * 0u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 1u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 2u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 3u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 4u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 5u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 6u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 7u)) & 0xffu),
                        0x00u // end marker
                    };

                    const auto bson = json::to_bson(j);
                    CHECK(bson == expected_bson);

                    auto j_roundtrip = json::from_bson(bson);

                    CHECK(j.at("entry").is_number_unsigned());
                    CHECK(j_roundtrip.at("entry").is_number_integer());
                    CHECK(j_roundtrip == j);
                    CHECK(json::from_bson(bson, true, false) == j);
                }
            }

            SECTION("unsigned std::uint64_t: INT64_MAX+1 .. UINT64_MAX")
            {
                std::vector<std::uint64_t> numbers
                {
                    static_cast<std::uint64_t>(INT64_MAX) + 1ULL,
                    10000000000000000000ULL,
                    18000000000000000000ULL,
                    UINT64_MAX - 1ULL,
                    UINT64_MAX,
                };

                for (auto i : numbers)
                {

                    CAPTURE(i)

                    json j =
                    {
                        { "entry", i }
                    };

                    auto iu = i;
                    std::vector<uint8_t> expected_bson =
                    {
                        0x14u, 0x00u, 0x00u, 0x00u, // size (little endian)
                        0x12u, /// entry: int64
                        'e', 'n', 't', 'r', 'y', '\x00',
                        static_cast<uint8_t>((iu >> (8u * 0u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 1u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 2u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 3u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 4u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 5u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 6u)) & 0xffu),
                        static_cast<uint8_t>((iu >> (8u * 7u)) & 0xffu),
                        0x00u // end marker
                    };

                    CHECK_THROWS_AS(json::to_bson(j), json::out_of_range&);
                    CHECK_THROWS_WITH_STD_STR(json::to_bson(j), "[json.exception.out_of_range.407] integer number " + std::to_string(i) + " cannot be represented by BSON as it does not fit int64");
                }
            }

        }
    }
}

TEST_CASE("BSON roundtrips" * doctest::skip())
{
    SECTION("reference files")
    {
        for (std::string filename :
                {
                    "test/data/json.org/1.json",
                    "test/data/json.org/2.json",
                    "test/data/json.org/3.json",
                    "test/data/json.org/4.json",
                    "test/data/json.org/5.json"
                })
        {
            CAPTURE(filename)

            {
                INFO_WITH_TEMP(filename + ": std::vector<uint8_t>");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse BSON file
                std::ifstream f_bson(filename + ".bson", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_bson)),
                    std::istreambuf_iterator<char>());
                json j2;
                CHECK_NOTHROW(j2 = json::from_bson(packed));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": std::ifstream");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse BSON file
                std::ifstream f_bson(filename + ".bson", std::ios::binary);
                json j2;
                CHECK_NOTHROW(j2 = json::from_bson(f_bson));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": uint8_t* and size");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse BSON file
                std::ifstream f_bson(filename + ".bson", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_bson)),
                    std::istreambuf_iterator<char>());
                json j2;
                CHECK_NOTHROW(j2 = json::from_bson({packed.data(), packed.size()}));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": output to output adapters");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse BSON file
                std::ifstream f_bson(filename + ".bson", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_bson)),
                    std::istreambuf_iterator<char>());

                {
                    INFO_WITH_TEMP(filename + ": output adapters: std::vector<uint8_t>");
                    std::vector<uint8_t> vec;
                    json::to_bson(j1, vec);

                    if (vec != packed)
                    {
                        // the exact serializations may differ due to the order of
                        // object keys; in these cases, just compare whether both
                        // serializations create the same JSON value
                        CHECK(json::from_bson(vec) == json::from_bson(packed));
                    }
                }
            }
        }
    }
}
