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

        // SECTION("non-empty object with double")
        // {
        //     json j =
        //     {
        //         { "entry", true }
        //     };

        //     std::vector<uint8_t> expected =
        //     {
        //         0x14, 0x00, 0x00, 0x00, // size (little endian)
        //         0x01, /// entry: double
        //         'e', 'n', 't', 'r', 'y', '\x00',
        //         0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x10, 0x40,
        //         0x00 // end marker
        //     };

        //     const auto result = json::to_bson(j);
        //     CHECK(result == expected);

        //     // roundtrip
        //     //CHECK(json::from_bson(result) == j);
        //     //CHECK(json::from_bson(result, true, false) == j);
        // }
    }
}
