//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <fstream>
#include <sstream>
#include "make_test_data_available.hpp"

TEST_CASE("object inspection")
{
    SECTION("convenience type checker")
    {
        SECTION("object")
        {
            json const j {{"foo", 1}, {"bar", false}};
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
            json const j {"foo", 1, 1u, 42.23, false};
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
            json const j(nullptr);
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
            json const j(true);
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
            json const j("Hello world");
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
            json const j(42);
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
            json const j(42u);
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
            json const j(42.23);
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
            json const j(json::value_t::binary);
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
            json const j(json::value_t::discarded);
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
        json const j {{"object", json::object()}, {"array", {1, 2, 3, 4}}, {"number", 42}, {"boolean", false}, {"null", nullptr}, {"string", "Hello world"} };

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

                const json j1 = json::parse(f_escaped);
                const json j2 = json::parse(f_unescaped);
                CHECK(j1 == j2);
            }

            SECTION("dumping yields the same JSON text")
            {
                std::ifstream f_escaped(TEST_DATA_DIRECTORY "/json_nlohmann_tests/all_unicode_ascii.json");
                std::ifstream f_unescaped(TEST_DATA_DIRECTORY "/json_nlohmann_tests/all_unicode.json");

                json const value = json::parse(f_unescaped);
                const std::string text = value.dump(4, ' ', true);

                const std::string expected((std::istreambuf_iterator<char>(f_escaped)),
                                           std::istreambuf_iterator<char>());
                CHECK(text == expected);
            }
        }

        SECTION("serialization of discarded element")
        {
            json const j_discarded(json::value_t::discarded);
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
            json const j_number = 3.14159265358979;
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
            json const j1 = json::parse(s);
            const std::string s1 = j1.dump();
            json const j2 = json::parse(s1);
            std::string s2 = j2.dump();
            CHECK(s1 == s2);
        }
    }

    SECTION("return the type of the object (explicit)")
    {
        SECTION("null")
        {
            json const j = nullptr;
            CHECK(j.type() == json::value_t::null);
        }

        SECTION("object")
        {
            json const j = {{"foo", "bar"}};
            CHECK(j.type() == json::value_t::object);
        }

        SECTION("array")
        {
            json const j = {1, 2, 3, 4};
            CHECK(j.type() == json::value_t::array);
        }

        SECTION("boolean")
        {
            json const j = true;
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("string")
        {
            json const j = "Hello world";
            CHECK(j.type() == json::value_t::string);
        }

        SECTION("number (integer)")
        {
            json const j = 23;
            CHECK(j.type() == json::value_t::number_integer);
        }

        SECTION("number (unsigned)")
        {
            json const j = 23u;
            CHECK(j.type() == json::value_t::number_unsigned);
        }

        SECTION("number (floating-point)")
        {
            json const j = 42.23;
            CHECK(j.type() == json::value_t::number_float);
        }
    }

    SECTION("return the type of the object (implicit)")
    {
        SECTION("null")
        {
            json const j = nullptr;
            const json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("object")
        {
            json const j = {{"foo", "bar"}};
            const json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("array")
        {
            json const j = {1, 2, 3, 4};
            const json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("boolean")
        {
            json const j = true;
            const json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("string")
        {
            json const j = "Hello world";
            const json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("number (integer)")
        {
            json const j = 23;
            const json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("number (unsigned)")
        {
            json const j = 23u;
            const json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("number (floating-point)")
        {
            json const j = 42.23;
            const json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("binary")
        {
            json const j = json::binary({});
            const json::value_t t = j;
            CHECK(t == j.type());
        }
    }
}
