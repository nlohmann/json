/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.10
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2017 Niels Lohmann <http://nlohmann.me>.

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

#include "json.hpp"
using nlohmann::json;

TEST_CASE("object inspection")
{
    SECTION("convenience type checker")
    {
        SECTION("object")
        {
            json j {{"foo", 1}, {"bar", false}};
            CHECK(not j.is_null());
            CHECK(not j.is_boolean());
            CHECK(not j.is_number());
            CHECK(not j.is_number_integer());
            CHECK(not j.is_number_unsigned());
            CHECK(not j.is_number_float());
            CHECK(j.is_object());
            CHECK(not j.is_array());
            CHECK(not j.is_string());
            CHECK(not j.is_discarded());
            CHECK(not j.is_primitive());
            CHECK(j.is_structured());
        }

        SECTION("array")
        {
            json j {"foo", 1, 1u, 42.23, false};
            CHECK(not j.is_null());
            CHECK(not j.is_boolean());
            CHECK(not j.is_number());
            CHECK(not j.is_number_integer());
            CHECK(not j.is_number_unsigned());
            CHECK(not j.is_number_float());
            CHECK(not j.is_object());
            CHECK(j.is_array());
            CHECK(not j.is_string());
            CHECK(not j.is_discarded());
            CHECK(not j.is_primitive());
            CHECK(j.is_structured());
        }

        SECTION("null")
        {
            json j(nullptr);
            CHECK(j.is_null());
            CHECK(not j.is_boolean());
            CHECK(not j.is_number());
            CHECK(not j.is_number_integer());
            CHECK(not j.is_number_unsigned());
            CHECK(not j.is_number_float());
            CHECK(not j.is_object());
            CHECK(not j.is_array());
            CHECK(not j.is_string());
            CHECK(not j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(not j.is_structured());
        }

        SECTION("boolean")
        {
            json j(true);
            CHECK(not j.is_null());
            CHECK(j.is_boolean());
            CHECK(not j.is_number());
            CHECK(not j.is_number_integer());
            CHECK(not j.is_number_unsigned());
            CHECK(not j.is_number_float());
            CHECK(not j.is_object());
            CHECK(not j.is_array());
            CHECK(not j.is_string());
            CHECK(not j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(not j.is_structured());
        }

        SECTION("string")
        {
            json j("Hello world");
            CHECK(not j.is_null());
            CHECK(not j.is_boolean());
            CHECK(not j.is_number());
            CHECK(not j.is_number_integer());
            CHECK(not j.is_number_unsigned());
            CHECK(not j.is_number_float());
            CHECK(not j.is_object());
            CHECK(not j.is_array());
            CHECK(j.is_string());
            CHECK(not j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(not j.is_structured());
        }

        SECTION("number (integer)")
        {
            json j(42);
            CHECK(not j.is_null());
            CHECK(not j.is_boolean());
            CHECK(j.is_number());
            CHECK(j.is_number_integer());
            CHECK(not j.is_number_unsigned());
            CHECK(not j.is_number_float());
            CHECK(not j.is_object());
            CHECK(not j.is_array());
            CHECK(not j.is_string());
            CHECK(not j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(not j.is_structured());
        }

        SECTION("number (unsigned)")
        {
            json j(42u);
            CHECK(not j.is_null());
            CHECK(not j.is_boolean());
            CHECK(j.is_number());
            CHECK(j.is_number_integer());
            CHECK(j.is_number_unsigned());
            CHECK(not j.is_number_float());
            CHECK(not j.is_object());
            CHECK(not j.is_array());
            CHECK(not j.is_string());
            CHECK(not j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(not j.is_structured());
        }

        SECTION("number (floating-point)")
        {
            json j(42.23);
            CHECK(not j.is_null());
            CHECK(not j.is_boolean());
            CHECK(j.is_number());
            CHECK(not j.is_number_integer());
            CHECK(not j.is_number_unsigned());
            CHECK(j.is_number_float());
            CHECK(not j.is_object());
            CHECK(not j.is_array());
            CHECK(not j.is_string());
            CHECK(not j.is_discarded());
            CHECK(j.is_primitive());
            CHECK(not j.is_structured());
        }

        SECTION("discarded")
        {
            json j(json::value_t::discarded);
            CHECK(not j.is_null());
            CHECK(not j.is_boolean());
            CHECK(not j.is_number());
            CHECK(not j.is_number_integer());
            CHECK(not j.is_number_unsigned());
            CHECK(not j.is_number_float());
            CHECK(not j.is_object());
            CHECK(not j.is_array());
            CHECK(not j.is_string());
            CHECK(j.is_discarded());
            CHECK(not j.is_primitive());
            CHECK(not j.is_structured());
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

        SECTION("indent=4")
        {
            CHECK(j.dump(4) ==
                  "{\n    \"array\": [\n        1,\n        2,\n        3,\n        4\n    ],\n    \"boolean\": false,\n    \"null\": null,\n    \"number\": 42,\n    \"object\": {},\n    \"string\": \"Hello world\"\n}");
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
            json j_number = 3.141592653589793;
            ss << j_number;

            // check that precision has been overridden during serialization
            CHECK(ss.str() == "3.141592653589793");

            // check that precision has been restored
            CHECK(ss.precision() == 3);
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
    }
}
