/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.4
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
#include <test_data.hpp>

TEST_CASE("object inspection")
{
    SECTION("convenience type checker")
    {
        SECTION("object")
        {
            json j {{"foo", 1}, {"bar", false}};
            CHECK(!j.is_null());
            CHECK(!j.is_boolean());
            CHECK(!j.is_number());
            CHECK(!j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(j.is_object());
            CHECK(!j.is_array());
            CHECK(!j.is_string());
            CHECK(!j.is_discarded());
            CHECK(!j.is_primitive());
            CHECK(j.is_structured());
        }

        SECTION("array")
        {
            json j {"foo", 1, 1u, 42.23, false};
            CHECK(!j.is_null());
            CHECK(!j.is_boolean());
            CHECK(!j.is_number());
            CHECK(!j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(!j.is_object());
            CHECK(j.is_array());
            CHECK(!j.is_string());
            CHECK(!j.is_discarded());
            CHECK(!j.is_primitive());
            CHECK(j.is_structured());
        }

        SECTION("null")
        {
            json j(nullptr);
            CHECK(j.is_null());
            CHECK(!j.is_boolean());
            CHECK(!j.is_number());
            CHECK(!j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(!j.is_object());
            CHECK(!j.is_array());
            CHECK(!j.is_string());
            CHECK(!j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(!j.is_structured());
        }

        SECTION("boolean")
        {
            json j(true);
            CHECK(!j.is_null());
            CHECK(j.is_boolean());
            CHECK(!j.is_number());
            CHECK(!j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(!j.is_object());
            CHECK(!j.is_array());
            CHECK(!j.is_string());
            CHECK(!j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(!j.is_structured());
        }

        SECTION("string")
        {
            json j("Hello world");
            CHECK(!j.is_null());
            CHECK(!j.is_boolean());
            CHECK(!j.is_number());
            CHECK(!j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(!j.is_object());
            CHECK(!j.is_array());
            CHECK(j.is_string());
            CHECK(!j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(!j.is_structured());
        }

        SECTION("number (integer)")
        {
            json j(42);
            CHECK(!j.is_null());
            CHECK(!j.is_boolean());
            CHECK(j.is_number());
            CHECK(j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(!j.is_object());
            CHECK(!j.is_array());
            CHECK(!j.is_string());
            CHECK(!j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(!j.is_structured());
        }

        SECTION("number (unsigned)")
        {
            json j(42u);
            CHECK(!j.is_null());
            CHECK(!j.is_boolean());
            CHECK(j.is_number());
            CHECK(j.is_number_integer());
            CHECK(j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(!j.is_object());
            CHECK(!j.is_array());
            CHECK(!j.is_string());
            CHECK(!j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(!j.is_structured());
        }

        SECTION("number (floating-point)")
        {
            json j(42.23);
            CHECK(!j.is_null());
            CHECK(!j.is_boolean());
            CHECK(j.is_number());
            CHECK(!j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(!j.is_object());
            CHECK(!j.is_array());
            CHECK(!j.is_string());
            CHECK(!j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(!j.is_structured());
        }

        SECTION("binary")
        {
            json j(json::value_t::binary);
            CHECK(!j.is_null());
            CHECK(!j.is_boolean());
            CHECK(!j.is_number());
            CHECK(!j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(j.is_binary());
            CHECK(!j.is_object());
            CHECK(!j.is_array());
            CHECK(!j.is_string());
            CHECK(!j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(!j.is_structured());
        }

        SECTION("discarded")
        {
            json j(json::value_t::discarded);
            CHECK(!j.is_null());
            CHECK(!j.is_boolean());
            CHECK(!j.is_number());
            CHECK(!j.is_number_integer());
            CHECK(!j.is_number_unsigned());
            CHECK(!j.is_number_float());
            CHECK(!j.is_binary());
            CHECK(!j.is_object());
            CHECK(!j.is_array());
            CHECK(!j.is_string());
            CHECK(j.is_discarded());
            CHECK(!j.is_primitive());
            CHECK(!j.is_structured());
        }
    }

    SECTION("serialization")
    {
        json j {{"object", json::object()}, {"array", {1, 2, 3, 4}}, {"number", 42}, {"boolean", false}, {"null", nullptr}, {"string", "Hello world"} };

        SECTION("no indent / indent=-1")
        {
            CHECK(j.dump() ==
                  "{\"array\":[1,2,3,4],\"boolean\":false,\"null\":null,\"number\":42,\"object\":{},\"string\":\"Hello world\"}");

            CHECK(j.dump() == j.dump(-1));
        }

        SECTION("indent=0")
        {
            CHECK(j.dump(0) ==
                  "{\n\"array\": [\n1,\n2,\n3,\n4\n],\n\"boolean\": false,\n\"null\": null,\n\"number\": 42,\n\"object\": {},\n\"string\": \"Hello world\"\n}");
        }

        SECTION("indent=1, space='\t'")
        {
            CHECK(j.dump(1, '\t') ==
                  "{\n\t\"array\": [\n\t\t1,\n\t\t2,\n\t\t3,\n\t\t4\n\t],\n\t\"boolean\": false,\n\t\"null\": null,\n\t\"number\": 42,\n\t\"object\": {},\n\t\"string\": \"Hello world\"\n}");
        }

        SECTION("indent=4")
        {
            CHECK(j.dump(4) ==
                  "{\n    \"array\": [\n        1,\n        2,\n        3,\n        4\n    ],\n    \"boolean\": false,\n    \"null\": null,\n    \"number\": 42,\n    \"object\": {},\n    \"string\": \"Hello world\"\n}");
        }

        SECTION("indent=x")
        {
            CHECK(j.dump().size() == 94);
            CHECK(j.dump(1).size() == 127);
            CHECK(j.dump(2).size() == 142);
            CHECK(j.dump(512).size() == 7792);

            // important test, because it yields a resize of the indent_string
            // inside the dump() function
            CHECK(j.dump(1024).size() == 15472);

            const auto binary = json::binary({1, 2, 3}, 128);
            CHECK(binary.dump(1024).size() == 2086);
        }

        SECTION("dump and floating-point numbers")
        {
            auto s = json(42.23).dump();
            CHECK(s.find("42.23") != std::string::npos);
        }

        SECTION("dump and small floating-point numbers")
        {
            auto s = json(1.23456e-78).dump();
            CHECK(s.find("1.23456e-78") != std::string::npos);
        }

        SECTION("dump and non-ASCII characters")
        {
            CHECK(json("ä").dump() == "\"ä\"");
            CHECK(json("Ö").dump() == "\"Ö\"");
            CHECK(json("❤️").dump() == "\"❤️\"");
        }

        SECTION("dump with ensure_ascii and non-ASCII characters")
        {
            CHECK(json("ä").dump(-1, ' ', true) == "\"\\u00e4\"");
            CHECK(json("Ö").dump(-1, ' ', true) == "\"\\u00d6\"");
            CHECK(json("❤️").dump(-1, ' ', true) == "\"\\u2764\\ufe0f\"");
        }

        SECTION("full Unicode escaping to ASCII")
        {
            SECTION("parsing yields the same JSON value")
            {
                std::ifstream f_escaped(TEST_DATA_DIRECTORY "/json_nlohmann_tests/all_unicode_ascii.json");
                std::ifstream f_unescaped(TEST_DATA_DIRECTORY "/json_nlohmann_tests/all_unicode.json");

                json j1 = json::parse(f_escaped);
                json j2 = json::parse(f_unescaped);
                CHECK(j1 == j2);
            }

            SECTION("dumping yields the same JSON text")
            {
                std::ifstream f_escaped(TEST_DATA_DIRECTORY "/json_nlohmann_tests/all_unicode_ascii.json");
                std::ifstream f_unescaped(TEST_DATA_DIRECTORY "/json_nlohmann_tests/all_unicode.json");

                json value = json::parse(f_unescaped);
                std::string text = value.dump(4, ' ', true);

                std::string expected((std::istreambuf_iterator<char>(f_escaped)),
                                     std::istreambuf_iterator<char>());
                CHECK(text == expected);
            }
        }

        SECTION("serialization of discarded element")
        {
            json j_discarded(json::value_t::discarded);
            CHECK(j_discarded.dump() == "<discarded>");
        }

        SECTION("check that precision is reset after serialization")
        {
            // create stringstream and set precision
            std::stringstream ss;
            ss.precision(3);
            ss << 3.141592653589793 << std::fixed;
            CHECK(ss.str() == "3.14");

            // reset stringstream
            ss.str(std::string());

            // use stringstream for JSON serialization
            json j_number = 3.14159265358979;
            ss << j_number;

            // check that precision has been overridden during serialization
            CHECK(ss.str() == "3.14159265358979");

            // check that precision has been restored
            CHECK(ss.precision() == 3);
        }
    }

    SECTION("round trips")
    {
        for (const auto& s :
                {"3.141592653589793", "1000000000000000010E5"
                })
        {
            json j1 = json::parse(s);
            std::string s1 = j1.dump();
            json j2 = json::parse(s1);
            std::string s2 = j2.dump();
            CHECK(s1 == s2);
        }
    }

    SECTION("return the type of the object (explicit)")
    {
        SECTION("null")
        {
            json j = nullptr;
            CHECK(j.type() == json::value_t::null);
        }

        SECTION("object")
        {
            json j = {{"foo", "bar"}};
            CHECK(j.type() == json::value_t::object);
        }

        SECTION("array")
        {
            json j = {1, 2, 3, 4};
            CHECK(j.type() == json::value_t::array);
        }

        SECTION("boolean")
        {
            json j = true;
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("string")
        {
            json j = "Hello world";
            CHECK(j.type() == json::value_t::string);
        }

        SECTION("number (integer)")
        {
            json j = 23;
            CHECK(j.type() == json::value_t::number_integer);
        }

        SECTION("number (unsigned)")
        {
            json j = 23u;
            CHECK(j.type() == json::value_t::number_unsigned);
        }

        SECTION("number (floating-point)")
        {
            json j = 42.23;
            CHECK(j.type() == json::value_t::number_float);
        }
    }

    SECTION("return the type of the object (implicit)")
    {
        SECTION("null")
        {
            json j = nullptr;
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("object")
        {
            json j = {{"foo", "bar"}};
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("array")
        {
            json j = {1, 2, 3, 4};
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("boolean")
        {
            json j = true;
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("string")
        {
            json j = "Hello world";
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("number (unsigned)")
        {
            json j = 23u;
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("number (floating-point)")
        {
            json j = 42.23;
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("binary")
        {
            json j = json::binary({});
            json::value_t t = j;
            CHECK(t == j.type());
        }
    }
}
