/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.2.0
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2018 Niels Lohmann <http://nlohmann.me>.

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

#include "catch.hpp"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <fstream>

TEST_CASE("BSON")
{
    SECTION("individual values not supported")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            json j = json::value_t::discarded;
            const auto result = json::to_bson(j);
            CHECK(result.empty());
        }

        SECTION("null")
        {
            json j = nullptr;
            REQUIRE_THROWS_AS(json::to_bson(j), json::type_error);
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json j = true;
                REQUIRE_THROWS_AS(json::to_bson(j), json::type_error);
            }

            SECTION("false")
            {
                json j = false;
                REQUIRE_THROWS_AS(json::to_bson(j), json::type_error);
            }
        }

        SECTION("number")
        {
            json j = 42;
            REQUIRE_THROWS_AS(json::to_bson(j), json::type_error);
        }

        SECTION("float")
        {
            json j = 4.2;
            REQUIRE_THROWS_AS(json::to_bson(j), json::type_error);
        }

        SECTION("string")
        {
            json j = "not supported";
            REQUIRE_THROWS_AS(json::to_bson(j), json::type_error);
        }

        SECTION("array")
        {
            json j = std::vector<int> {1, 2, 3, 4, 5, 6, 7};
            REQUIRE_THROWS_AS(json::to_bson(j), json::type_error);
        }
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
                0x41, 0x00, 0x00, 0x00, // size (little endian)
                0x04, /// entry: embedded document
                'e', 'n', 't', 'r', 'y', '\x00',

                0x35, 0x00, 0x00, 0x00, // size (little endian)
                0x10, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x02, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x03, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x05, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x06, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x07, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x08, 0x00, 0x00, 0x00,
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


TEST_CASE("Incomplete BSON INPUT")
{
    std::vector<uint8_t> incomplete_bson =
    {
        0x0D, 0x00, 0x00, 0x00, // size (little endian)
        0x08,                   // entry: boolean
        'e', 'n', 't'           // unexpected EOF
    };

    CHECK_THROWS_WITH(json::from_bson(incomplete_bson),
                      "[json.exception.parse_error.110] parse error at 9: unexpected end of input");
    CHECK(json::from_bson(incomplete_bson, true, false).is_discarded());

    SaxCountdown scp(0);
    CHECK(not json::sax_parse(incomplete_bson, &scp, json::input_format_t::bson));
}

TEST_CASE("Incomplete BSON INPUT 2")
{
    std::vector<uint8_t> incomplete_bson =
    {
        0x0D, 0x00, 0x00, 0x00, // size (little endian)
        0x08,                   // entry: boolean, unexpected EOF
    };

    CHECK_THROWS_WITH(json::from_bson(incomplete_bson),
                      "[json.exception.parse_error.110] parse error at 6: unexpected end of input");
    CHECK(json::from_bson(incomplete_bson, true, false).is_discarded());

    SaxCountdown scp(0);
    CHECK(not json::sax_parse(incomplete_bson, &scp, json::input_format_t::bson));
}


TEST_CASE("Incomplete BSON INPUT 3")
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
    CHECK_THROWS_WITH(json::from_bson(incomplete_bson),
                      "[json.exception.parse_error.110] parse error at 29: unexpected end of input");
    CHECK(json::from_bson(incomplete_bson, true, false).is_discarded());

    SaxCountdown scp(1);
    CHECK(not json::sax_parse(incomplete_bson, &scp, json::input_format_t::bson));
}



TEST_CASE("Incomplete BSON INPUT 4")
{
    std::vector<uint8_t> incomplete_bson =
    {
        0x0D, 0x00, // size (incomplete), unexpected EOF
    };

    CHECK_THROWS_WITH(json::from_bson(incomplete_bson),
                      "[json.exception.parse_error.110] parse error at 3: unexpected end of input");
    CHECK(json::from_bson(incomplete_bson, true, false).is_discarded());

    SaxCountdown scp(0);
    CHECK(not json::sax_parse(incomplete_bson, &scp, json::input_format_t::bson));
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

    CHECK_THROWS_WITH(json::from_bson(bson),
                      "[json.exception.parse_error.114] parse error at 5: Unsupported BSON record type 0xFF");
    CHECK(json::from_bson(bson, true, false).is_discarded());

    SaxCountdown scp(0);
    CHECK(not json::sax_parse(bson, &scp, json::input_format_t::bson));
}


