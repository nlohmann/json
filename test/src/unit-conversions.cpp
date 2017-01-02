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

#define private public
#include "json.hpp"
using nlohmann::json;

#include <deque>
#include <forward_list>
#include <list>
#include <unordered_map>
#include <unordered_set>

TEST_CASE("value conversion")
{
    SECTION("get an object (explicit)")
    {
        json::object_t o_reference = {{"object", json::object()}, {"array", {1, 2, 3, 4}}, {"number", 42}, {"boolean", false}, {"null", nullptr}, {"string", "Hello world"} };
        json j(o_reference);

        SECTION("json::object_t")
        {
            json::object_t o = j.get<json::object_t>();
            CHECK(json(o) == j);
        }

        SECTION("std::map<json::string_t, json>")
        {
            std::map<json::string_t, json> o = j.get<std::map<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            std::multimap<json::string_t, json> o = j.get<std::multimap<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            std::unordered_map<json::string_t, json> o = j.get<std::unordered_map<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            std::unordered_multimap<json::string_t, json> o =
                j.get<std::unordered_multimap<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("exception in case of a non-object type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_unsigned).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::object_t>(), std::logic_error);

            CHECK_THROWS_WITH(json(json::value_t::null).get<json::object_t>(),
                              "type must be object, but is null");
            CHECK_THROWS_WITH(json(json::value_t::array).get<json::object_t>(),
                              "type must be object, but is array");
            CHECK_THROWS_WITH(json(json::value_t::string).get<json::object_t>(),
                              "type must be object, but is string");
            CHECK_THROWS_WITH(json(json::value_t::boolean).get<json::object_t>(),
                              "type must be object, but is boolean");
            CHECK_THROWS_WITH(json(json::value_t::number_integer).get<json::object_t>(),
                              "type must be object, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_unsigned).get<json::object_t>(),
                              "type must be object, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_float).get<json::object_t>(),
                              "type must be object, but is number");
        }
    }

    SECTION("get an object (implicit)")
    {
        json::object_t o_reference = {{"object", json::object()}, {"array", {1, 2, 3, 4}}, {"number", 42}, {"boolean", false}, {"null", nullptr}, {"string", "Hello world"} };
        json j(o_reference);

        SECTION("json::object_t")
        {
            json::object_t o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::map<json::string_t, json>")
        {
            std::map<json::string_t, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            std::multimap<json::string_t, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            std::unordered_map<json::string_t, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            std::unordered_multimap<json::string_t, json> o = j;
            CHECK(json(o) == j);
        }
    }

    SECTION("get an array (explicit)")
    {
        json::array_t a_reference {json(1), json(1u), json(2.2), json(false), json("string"), json()};
        json j(a_reference);

        SECTION("json::array_t")
        {
            json::array_t a = j.get<json::array_t>();
            CHECK(json(a) == j);
        }

        SECTION("std::list<json>")
        {
            std::list<json> a = j.get<std::list<json>>();
            CHECK(json(a) == j);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a = j.get<std::forward_list<json>>();
            CHECK(json(a) == j);
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a = j.get<std::vector<json>>();
            CHECK(json(a) == j);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a = j.get<std::deque<json>>();
            CHECK(json(a) == j);
        }

        SECTION("exception in case of a non-array type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_unsigned).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::array_t>(), std::logic_error);

            CHECK_THROWS_WITH(json(json::value_t::null).get<json::array_t>(),
                              "type must be array, but is null");
            CHECK_THROWS_WITH(json(json::value_t::object).get<json::array_t>(),
                              "type must be array, but is object");
            CHECK_THROWS_WITH(json(json::value_t::string).get<json::array_t>(),
                              "type must be array, but is string");
            CHECK_THROWS_WITH(json(json::value_t::boolean).get<json::array_t>(),
                              "type must be array, but is boolean");
            CHECK_THROWS_WITH(json(json::value_t::number_integer).get<json::array_t>(),
                              "type must be array, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_unsigned).get<json::array_t>(),
                              "type must be array, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_float).get<json::array_t>(),
                              "type must be array, but is number");
        }
    }

    SECTION("get an array (implicit)")
    {
        json::array_t a_reference {json(1), json(1u), json(2.2), json(false), json("string"), json()};
        json j(a_reference);

        SECTION("json::array_t")
        {
            json::array_t a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::list<json>")
        {
            std::list<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a = j;
            CHECK(json(a) == j);
        }
    }

    SECTION("get a string (explicit)")
    {
        json::string_t s_reference {"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            json::string_t s = j.get<json::string_t>();
            CHECK(json(s) == j);
        }

        SECTION("std::string")
        {
            std::string s = j.get<std::string>();
            CHECK(json(s) == j);
        }

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_unsigned).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::string_t>(), std::logic_error);

            CHECK_THROWS_WITH(json(json::value_t::null).get<json::string_t>(),
                              "type must be string, but is null");
            CHECK_THROWS_WITH(json(json::value_t::object).get<json::string_t>(),
                              "type must be string, but is object");
            CHECK_THROWS_WITH(json(json::value_t::array).get<json::string_t>(),
                              "type must be string, but is array");
            CHECK_THROWS_WITH(json(json::value_t::boolean).get<json::string_t>(),
                              "type must be string, but is boolean");
            CHECK_THROWS_WITH(json(json::value_t::number_integer).get<json::string_t>(),
                              "type must be string, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_unsigned).get<json::string_t>(),
                              "type must be string, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_float).get<json::string_t>(),
                              "type must be string, but is number");
        }
    }

    SECTION("get a string (implicit)")
    {
        json::string_t s_reference {"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            json::string_t s = j;
            CHECK(json(s) == j);
        }

        SECTION("std::string")
        {
            std::string s = j;
            CHECK(json(s) == j);
        }
    }

    SECTION("get a boolean (explicit)")
    {
        json::boolean_t b_reference {true};
        json j(b_reference);

        SECTION("boolean_t")
        {
            json::boolean_t b = j.get<json::boolean_t>();
            CHECK(json(b) == j);
        }

        SECTION("bool")
        {
            bool b = j.get<bool>();
            CHECK(json(b) == j);
        }

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_unsigned).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::boolean_t>(), std::logic_error);

            CHECK_THROWS_WITH(json(json::value_t::null).get<json::boolean_t>(),
                              "type must be boolean, but is null");
            CHECK_THROWS_WITH(json(json::value_t::object).get<json::boolean_t>(),
                              "type must be boolean, but is object");
            CHECK_THROWS_WITH(json(json::value_t::array).get<json::boolean_t>(),
                              "type must be boolean, but is array");
            CHECK_THROWS_WITH(json(json::value_t::string).get<json::boolean_t>(),
                              "type must be boolean, but is string");
            CHECK_THROWS_WITH(json(json::value_t::number_integer).get<json::boolean_t>(),
                              "type must be boolean, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_unsigned).get<json::boolean_t>(),
                              "type must be boolean, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_float).get<json::boolean_t>(),
                              "type must be boolean, but is number");
        }
    }

    SECTION("get a boolean (implicit)")
    {
        json::boolean_t b_reference {true};
        json j(b_reference);

        SECTION("boolean_t")
        {
            json::boolean_t b = j;
            CHECK(json(b) == j);
        }

        SECTION("bool")
        {
            bool b = j;
            CHECK(json(b) == j);
        }
    }

    SECTION("get an integer number (explicit)")
    {
        json::number_integer_t n_reference {42};
        json j(n_reference);
        json::number_unsigned_t n_unsigned_reference {42u};
        json j_unsigned(n_unsigned_reference);

        SECTION("number_integer_t")
        {
            json::number_integer_t n = j.get<json::number_integer_t>();
            CHECK(json(n) == j);
        }

        SECTION("number_unsigned_t")
        {
            json::number_unsigned_t n = j_unsigned.get<json::number_unsigned_t>();
            CHECK(json(n) == j_unsigned);
        }

        SECTION("short")
        {
            short n = j.get<short>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned short")
        {
            unsigned short n = j.get<unsigned short>();
            CHECK(json(n) == j);
        }

        SECTION("int")
        {
            int n = j.get<int>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned int")
        {
            unsigned int n = j.get<unsigned int>();
            CHECK(json(n) == j);
        }

        SECTION("long")
        {
            long n = j.get<long>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned long")
        {
            unsigned long n = j.get<unsigned long>();
            CHECK(json(n) == j);
        }

        SECTION("long long")
        {
            long long n = j.get<long long>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned long long")
        {
            unsigned long long n = j.get<unsigned long long>();
            CHECK(json(n) == j);
        }

        SECTION("int8_t")
        {
            int8_t n = j.get<int8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_t")
        {
            int16_t n = j.get<int16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_t")
        {
            int32_t n = j.get<int32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_t")
        {
            int64_t n = j.get<int64_t>();
            CHECK(json(n) == j);
        }

        SECTION("int8_fast_t")
        {
            int_fast8_t n = j.get<int_fast8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_fast_t")
        {
            int_fast16_t n = j.get<int_fast16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_fast_t")
        {
            int_fast32_t n = j.get<int_fast32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_fast_t")
        {
            int_fast64_t n = j.get<int_fast64_t>();
            CHECK(json(n) == j);
        }

        SECTION("int8_least_t")
        {
            int_least8_t n = j.get<int_least8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_least_t")
        {
            int_least16_t n = j.get<int_least16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_least_t")
        {
            int_least32_t n = j.get<int_least32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_least_t")
        {
            int_least64_t n = j.get<int_least64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_t")
        {
            uint8_t n = j.get<uint8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_t")
        {
            uint16_t n = j.get<uint16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_t")
        {
            uint32_t n = j.get<uint32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_t")
        {
            uint64_t n = j.get<uint64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_fast_t")
        {
            uint_fast8_t n = j.get<uint_fast8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_fast_t")
        {
            uint_fast16_t n = j.get<uint_fast16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_fast_t")
        {
            uint_fast32_t n = j.get<uint_fast32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_fast_t")
        {
            uint_fast64_t n = j.get<uint_fast64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_least_t")
        {
            uint_least8_t n = j.get<uint_least8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_least_t")
        {
            uint_least16_t n = j.get<uint_least16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_least_t")
        {
            uint_least32_t n = j.get<uint_least32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_least_t")
        {
            uint_least64_t n = j.get<uint_least64_t>();
            CHECK(json(n) == j);
        }

        SECTION("exception in case of a non-number type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::number_integer_t>(), std::logic_error);

            CHECK_THROWS_WITH(json(json::value_t::null).get<json::number_integer_t>(),
                              "type must be number, but is null");
            CHECK_THROWS_WITH(json(json::value_t::object).get<json::number_integer_t>(),
                              "type must be number, but is object");
            CHECK_THROWS_WITH(json(json::value_t::array).get<json::number_integer_t>(),
                              "type must be number, but is array");
            CHECK_THROWS_WITH(json(json::value_t::string).get<json::number_integer_t>(),
                              "type must be number, but is string");
            CHECK_THROWS_WITH(json(json::value_t::boolean).get<json::number_integer_t>(),
                              "type must be number, but is boolean");

            CHECK_NOTHROW(json(json::value_t::number_float).get<json::number_integer_t>());
            CHECK_NOTHROW(json(json::value_t::number_float).get<json::number_unsigned_t>());
        }
    }

    SECTION("get an integer number (implicit)")
    {
        json::number_integer_t n_reference {42};
        json j(n_reference);
        json::number_unsigned_t n_unsigned_reference {42u};
        json j_unsigned(n_unsigned_reference);

        SECTION("number_integer_t")
        {
            json::number_integer_t n = j.get<json::number_integer_t>();
            CHECK(json(n) == j);
        }

        SECTION("number_unsigned_t")
        {
            json::number_unsigned_t n = j_unsigned.get<json::number_unsigned_t>();
            CHECK(json(n) == j_unsigned);
        }

        SECTION("short")
        {
            short n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned short")
        {
            unsigned short n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("int")
        {
            int n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned int")
        {
            unsigned int n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("long")
        {
            long n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned long")
        {
            unsigned long n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("long long")
        {
            long long n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned long long")
        {
            unsigned long long n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("int8_t")
        {
            int8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_t")
        {
            int16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_t")
        {
            int32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_t")
        {
            int64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int8_fast_t")
        {
            int_fast8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_fast_t")
        {
            int_fast16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_fast_t")
        {
            int_fast32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_fast_t")
        {
            int_fast64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int8_least_t")
        {
            int_least8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_least_t")
        {
            int_least16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_least_t")
        {
            int_least32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_least_t")
        {
            int_least64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint8_t")
        {
            uint8_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint16_t")
        {
            uint16_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint32_t")
        {
            uint32_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint64_t")
        {
            uint64_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint8_fast_t")
        {
            uint_fast8_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint16_fast_t")
        {
            uint_fast16_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint32_fast_t")
        {
            uint_fast32_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint64_fast_t")
        {
            uint_fast64_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint8_least_t")
        {
            uint_least8_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint16_least_t")
        {
            uint_least16_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint32_least_t")
        {
            uint_least32_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint64_least_t")
        {
            uint_least64_t n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }
    }

    SECTION("get a floating-point number (explicit)")
    {
        json::number_float_t n_reference {42.23};
        json j(n_reference);

        SECTION("number_float_t")
        {
            json::number_float_t n = j.get<json::number_float_t>();
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("float")
        {
            float n = j.get<float>();
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("double")
        {
            double n = j.get<double>();
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::number_float_t>(), std::logic_error);

            CHECK_THROWS_WITH(json(json::value_t::null).get<json::number_float_t>(),
                              "type must be number, but is null");
            CHECK_THROWS_WITH(json(json::value_t::object).get<json::number_float_t>(),
                              "type must be number, but is object");
            CHECK_THROWS_WITH(json(json::value_t::array).get<json::number_float_t>(),
                              "type must be number, but is array");
            CHECK_THROWS_WITH(json(json::value_t::string).get<json::number_float_t>(),
                              "type must be number, but is string");
            CHECK_THROWS_WITH(json(json::value_t::boolean).get<json::number_float_t>(),
                              "type must be number, but is boolean");

            CHECK_NOTHROW(json(json::value_t::number_integer).get<json::number_float_t>());
            CHECK_NOTHROW(json(json::value_t::number_unsigned).get<json::number_float_t>());
        }
    }

    SECTION("get a floating-point number (implicit)")
    {
        json::number_float_t n_reference {42.23};
        json j(n_reference);

        SECTION("number_float_t")
        {
            json::number_float_t n = j;
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("float")
        {
            float n = j;
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("double")
        {
            double n = j;
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }
    }

    SECTION("more involved conversions")
    {
        SECTION("object-like STL containers")
        {
            json j1 = {{"one", 1}, {"two", 2}, {"three", 3}};
            json j2 = {{"one", 1u}, {"two", 2u}, {"three", 3u}};
            json j3 = {{"one", 1.1}, {"two", 2.2}, {"three", 3.3}};
            json j4 = {{"one", true}, {"two", false}, {"three", true}};
            json j5 = {{"one", "eins"}, {"two", "zwei"}, {"three", "drei"}};

            SECTION("std::map")
            {
                auto m1 = j1.get<std::map<std::string, int>>();
                auto m2 = j2.get<std::map<std::string, unsigned int>>();
                auto m3 = j3.get<std::map<std::string, double>>();
                auto m4 = j4.get<std::map<std::string, bool>>();
                //auto m5 = j5.get<std::map<std::string, std::string>>();
            }

            SECTION("std::unordered_map")
            {
                auto m1 = j1.get<std::unordered_map<std::string, int>>();
                auto m2 = j2.get<std::unordered_map<std::string, unsigned int>>();
                auto m3 = j3.get<std::unordered_map<std::string, double>>();
                auto m4 = j4.get<std::unordered_map<std::string, bool>>();
                //auto m5 = j5.get<std::unordered_map<std::string, std::string>>();
                //CHECK(m5["one"] == "eins");
            }

            SECTION("std::multimap")
            {
                auto m1 = j1.get<std::multimap<std::string, int>>();
                auto m2 = j2.get<std::multimap<std::string, unsigned int>>();
                auto m3 = j3.get<std::multimap<std::string, double>>();
                auto m4 = j4.get<std::multimap<std::string, bool>>();
                //auto m5 = j5.get<std::multimap<std::string, std::string>>();
                //CHECK(m5["one"] == "eins");
            }

            SECTION("std::unordered_multimap")
            {
                auto m1 = j1.get<std::unordered_multimap<std::string, int>>();
                auto m2 = j2.get<std::unordered_multimap<std::string, unsigned int>>();
                auto m3 = j3.get<std::unordered_multimap<std::string, double>>();
                auto m4 = j4.get<std::unordered_multimap<std::string, bool>>();
                //auto m5 = j5.get<std::unordered_multimap<std::string, std::string>>();
                //CHECK(m5["one"] == "eins");
            }

            SECTION("exception in case of a non-object type")
            {
                CHECK_THROWS_AS((json().get<std::map<std::string, int>>()), std::logic_error);
                CHECK_THROWS_WITH((json().get<std::map<std::string, int>>()), "type must be object, but is null");
            }
        }

        SECTION("array-like STL containers")
        {
            json j1 = {1, 2, 3, 4};
            json j2 = {1u, 2u, 3u, 4u};
            json j3 = {1.2, 2.3, 3.4, 4.5};
            json j4 = {true, false, true};
            json j5 = {"one", "two", "three"};

            SECTION("std::list")
            {
                auto m1 = j1.get<std::list<int>>();
                auto m2 = j2.get<std::list<unsigned int>>();
                auto m3 = j3.get<std::list<double>>();
                auto m4 = j4.get<std::list<bool>>();
                auto m5 = j5.get<std::list<std::string>>();
            }

            //SECTION("std::forward_list")
            //{
            //    auto m1 = j1.get<std::forward_list<int>>();
            //    auto m2 = j2.get<std::forward_list<unsigned int>>();
            //    auto m3 = j3.get<std::forward_list<double>>();
            //    auto m4 = j4.get<std::forward_list<bool>>();
            //    auto m5 = j5.get<std::forward_list<std::string>>();
            //}

            SECTION("std::vector")
            {
                auto m1 = j1.get<std::vector<int>>();
                auto m2 = j2.get<std::vector<unsigned int>>();
                auto m3 = j3.get<std::vector<double>>();
                auto m4 = j4.get<std::vector<bool>>();
                auto m5 = j5.get<std::vector<std::string>>();
            }

            SECTION("std::deque")
            {
                auto m1 = j1.get<std::deque<int>>();
                auto m2 = j2.get<std::deque<unsigned int>>();
                auto m3 = j2.get<std::deque<double>>();
                auto m4 = j4.get<std::deque<bool>>();
                auto m5 = j5.get<std::deque<std::string>>();
            }

            SECTION("std::set")
            {
                auto m1 = j1.get<std::set<int>>();
                auto m2 = j2.get<std::set<unsigned int>>();
                auto m3 = j3.get<std::set<double>>();
                auto m4 = j4.get<std::set<bool>>();
                auto m5 = j5.get<std::set<std::string>>();
            }

            SECTION("std::unordered_set")
            {
                auto m1 = j1.get<std::unordered_set<int>>();
                auto m2 = j2.get<std::unordered_set<unsigned int>>();
                auto m3 = j3.get<std::unordered_set<double>>();
                auto m4 = j4.get<std::unordered_set<bool>>();
                auto m5 = j5.get<std::unordered_set<std::string>>();
            }

            SECTION("exception in case of a non-object type")
            {
                CHECK_THROWS_AS((json().get<std::list<int>>()), std::logic_error);
                CHECK_THROWS_AS((json().get<std::vector<int>>()), std::logic_error);
                CHECK_THROWS_AS((json().get<std::vector<json>>()), std::logic_error);
                CHECK_THROWS_AS((json().get<std::list<json>>()), std::logic_error);

                CHECK_THROWS_WITH((json().get<std::list<int>>()), "type must be array, but is null");
                CHECK_THROWS_WITH((json().get<std::vector<int>>()), "type must be array, but is null");
                CHECK_THROWS_WITH((json().get<std::vector<json>>()), "type must be array, but is null");
                CHECK_THROWS_WITH((json().get<std::list<json>>()), "type must be array, but is null");
            }
        }
    }
}
