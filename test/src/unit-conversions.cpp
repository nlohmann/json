/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.7.3
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

#define private public
#include <nlohmann/json.hpp>
using nlohmann::json;
#undef private

#include <deque>
#include <forward_list>
#include <list>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <valarray>

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_HAS_CXX17) && _HAS_CXX17 == 1) // fix for issue #464
    #define JSON_HAS_CPP_17
    #define JSON_HAS_CPP_14
#elif (defined(__cplusplus) && __cplusplus >= 201402L) || (defined(_HAS_CXX14) && _HAS_CXX14 == 1)
    #define JSON_HAS_CPP_14
#endif

#if defined(JSON_HAS_CPP_17)
    #include <string_view>
#endif

TEST_CASE("value conversion")
{
    SECTION("get an object (explicit)")
    {
        json::object_t o_reference = {{"object", json::object()},
            {"array", {1, 2, 3, 4}},
            {"number", 42},
            {"boolean", false},
            {"null", nullptr},
            {"string", "Hello world"}
        };
        json j(o_reference);

        SECTION("json::object_t")
        {
            json::object_t o = j.get<json::object_t>();
            CHECK(json(o) == j);
        }

        SECTION("std::map<json::string_t, json>")
        {
            std::map<json::string_t, json> o =
                j.get<std::map<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            std::multimap<json::string_t, json> o =
                j.get<std::multimap<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            std::unordered_map<json::string_t, json> o =
                j.get<std::unordered_map<json::string_t, json>>();
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
            CHECK_THROWS_AS(json(json::value_t::null).get<json::object_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::object_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::object_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::object_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::object_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(
                json(json::value_t::number_unsigned).get<json::object_t>(),
                json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::object_t>(),
                            json::type_error&);

            CHECK_THROWS_WITH(
                json(json::value_t::null).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is null");
            CHECK_THROWS_WITH(
                json(json::value_t::array).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is array");
            CHECK_THROWS_WITH(
                json(json::value_t::string).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is string");
            CHECK_THROWS_WITH(json(json::value_t::boolean).get<json::object_t>(),
                              "[json.exception.type_error.302] type must be object, "
                              "but is boolean");
            CHECK_THROWS_WITH(
                json(json::value_t::number_integer).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is number");
            CHECK_THROWS_WITH(
                json(json::value_t::number_unsigned).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is number");
            CHECK_THROWS_WITH(
                json(json::value_t::number_float).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is number");
        }
    }

    SECTION("get an object (explicit, get_to)")
    {
        json::object_t o_reference = {{"object", json::object()},
            {"array", {1, 2, 3, 4}},
            {"number", 42},
            {"boolean", false},
            {"null", nullptr},
            {"string", "Hello world"}
        };
        json j(o_reference);

        SECTION("json::object_t")
        {
            json::object_t o = {{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }

        SECTION("std::map<json::string_t, json>")
        {
            std::map<json::string_t, json> o{{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            std::multimap<json::string_t, json> o{{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            std::unordered_map<json::string_t, json> o{{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            std::unordered_multimap<json::string_t, json> o{{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }
    }


    SECTION("get an object (implicit)")
    {
        json::object_t o_reference = {{"object", json::object()},
            {"array", {1, 2, 3, 4}},
            {"number", 42},
            {"boolean", false},
            {"null", nullptr},
            {"string", "Hello world"}
        };
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
        json::array_t a_reference{json(1),     json(1u),       json(2.2),
                                  json(false), json("string"), json()};
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

            CHECK_THROWS_AS(json(json::value_t::null).get<std::forward_list<json>>(),
                            json::type_error&);
            CHECK_THROWS_WITH(
                json(json::value_t::null).get<std::forward_list<json>>(),
                "[json.exception.type_error.302] type must be array, but is null");
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a = j.get<std::vector<json>>();
            CHECK(json(a) == j);

            CHECK_THROWS_AS(json(json::value_t::null).get<std::vector<json>>(),
                            json::type_error&);
            CHECK_THROWS_WITH(
                json(json::value_t::null).get<std::vector<json>>(),
                "[json.exception.type_error.302] type must be array, but is null");

#if not defined(JSON_NOEXCEPTION)
            SECTION("reserve is called on containers that supports it")
            {
                // make sure all values are properly copied
                std::vector<int> v2 = json({1, 2, 3, 4, 5, 6, 7, 8, 9, 10});
                CHECK(v2.size() == 10);
            }
#endif
        }

        SECTION("built-in arrays")
        {
            const char str[] = "a string";
            const int nbs[] = {0, 1, 2};

            json j2 = nbs;
            json j3 = str;

            auto v = j2.get<std::vector<int>>();
            auto s = j3.get<std::string>();
            CHECK(std::equal(v.begin(), v.end(), std::begin(nbs)));
            CHECK(s == str);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a = j.get<std::deque<json>>();
            CHECK(json(a) == j);
        }

        SECTION("exception in case of a non-array type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::array_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::array_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::array_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::array_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::array_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_unsigned).get<json::array_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::array_t>(),
                            json::type_error&);

            CHECK_THROWS_WITH(
                json(json::value_t::object).get<std::vector<int>>(),
                "[json.exception.type_error.302] type must be array, but is object");
            CHECK_THROWS_WITH(
                json(json::value_t::null).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is null");
            CHECK_THROWS_WITH(
                json(json::value_t::object).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is object");
            CHECK_THROWS_WITH(
                json(json::value_t::string).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is string");
            CHECK_THROWS_WITH(
                json(json::value_t::boolean).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is boolean");
            CHECK_THROWS_WITH(
                json(json::value_t::number_integer).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is number");
            CHECK_THROWS_WITH(
                json(json::value_t::number_unsigned).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is number");
            CHECK_THROWS_WITH(
                json(json::value_t::number_float).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is number");
        }
    }

    SECTION("get an array (explicit, get_to)")
    {
        json::array_t a_reference{json(1),     json(1u),       json(2.2),
                                  json(false), json("string"), json()};
        json j(a_reference);

        SECTION("json::array_t")
        {
            json::array_t a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("std::valarray<json>")
        {
            std::valarray<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("std::list<json>")
        {
            std::list<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("built-in arrays")
        {
            const int nbs[] = {0, 1, 2};
            int nbs2[] = {0, 0, 0};

            json j2 = nbs;
            j2.get_to(nbs2);
            CHECK(std::equal(std::begin(nbs), std::end(nbs), std::begin(nbs2)));
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }
    }

    SECTION("get an array (implicit)")
    {
        json::array_t a_reference{json(1),     json(1u),       json(2.2),
                                  json(false), json("string"), json()};
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
        json::string_t s_reference{"Hello world"};
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
#if defined(JSON_HAS_CPP_17)
        SECTION("std::string_view")
        {
            std::string_view s = j.get<std::string_view>();
            CHECK(json(s) == j);
        }
#endif

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::string_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::string_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::string_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::string_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::string_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(
                json(json::value_t::number_unsigned).get<json::string_t>(),
                json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::string_t>(),
                            json::type_error&);

            CHECK_THROWS_WITH(
                json(json::value_t::null).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is null");
            CHECK_THROWS_WITH(
                json(json::value_t::object).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is object");
            CHECK_THROWS_WITH(
                json(json::value_t::array).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is array");
            CHECK_THROWS_WITH(json(json::value_t::boolean).get<json::string_t>(),
                              "[json.exception.type_error.302] type must be string, "
                              "but is boolean");
            CHECK_THROWS_WITH(
                json(json::value_t::number_integer).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is number");
            CHECK_THROWS_WITH(
                json(json::value_t::number_unsigned).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is number");
            CHECK_THROWS_WITH(
                json(json::value_t::number_float).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is number");
        }

#if defined(JSON_HAS_CPP_17)
        SECTION("exception in case of a non-string type using string_view")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<std::string_view>(), json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::object).get<std::string_view>(), json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::array).get<std::string_view>(), json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<std::string_view>(), json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<std::string_view>(), json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_unsigned).get<std::string_view>(), json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<std::string_view>(), json::type_error&);

            CHECK_THROWS_WITH(json(json::value_t::null).get<std::string_view>(),
                              "[json.exception.type_error.302] type must be string, but is null");
            CHECK_THROWS_WITH(json(json::value_t::object).get<std::string_view>(),
                              "[json.exception.type_error.302] type must be string, but is object");
            CHECK_THROWS_WITH(json(json::value_t::array).get<std::string_view>(),
                              "[json.exception.type_error.302] type must be string, but is array");
            CHECK_THROWS_WITH(json(json::value_t::boolean).get<std::string_view>(),
                              "[json.exception.type_error.302] type must be string, but is boolean");
            CHECK_THROWS_WITH(json(json::value_t::number_integer).get<std::string_view>(),
                              "[json.exception.type_error.302] type must be string, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_unsigned).get<std::string_view>(),
                              "[json.exception.type_error.302] type must be string, but is number");
            CHECK_THROWS_WITH(json(json::value_t::number_float).get<std::string_view>(),
                              "[json.exception.type_error.302] type must be string, but is number");
        }
#endif
    }

    SECTION("get a string (explicit, get_to)")
    {
        json::string_t s_reference{"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            json::string_t s = "previous value";
            j.get_to(s);
            CHECK(json(s) == j);
        }

        SECTION("std::string")
        {
            std::string s = "previous value";
            j.get_to(s);
            CHECK(json(s) == j);
        }
#if defined(JSON_HAS_CPP_17)
        SECTION("std::string_view")
        {
            std::string s = "previous value";
            std::string_view sv = s;
            j.get_to(sv);
            CHECK(json(sv) == j);
        }
#endif
    }

    SECTION("get null (explicit)")
    {
        std::nullptr_t n = nullptr;
        json j(n);

        auto n2 = j.get<std::nullptr_t>();
        CHECK(n2 == n);

        CHECK_THROWS_AS(json(json::value_t::string).get<std::nullptr_t>(), json::type_error&);
        CHECK_THROWS_AS(json(json::value_t::object).get<std::nullptr_t>(), json::type_error&);
        CHECK_THROWS_AS(json(json::value_t::array).get<std::nullptr_t>(), json::type_error&);
        CHECK_THROWS_AS(json(json::value_t::boolean).get<std::nullptr_t>(), json::type_error&);
        CHECK_THROWS_AS(json(json::value_t::number_integer).get<std::nullptr_t>(), json::type_error&);
        CHECK_THROWS_AS(json(json::value_t::number_unsigned).get<std::nullptr_t>(), json::type_error&);
        CHECK_THROWS_AS(json(json::value_t::number_float).get<std::nullptr_t>(), json::type_error&);

        CHECK_THROWS_WITH(json(json::value_t::string).get<std::nullptr_t>(),
                          "[json.exception.type_error.302] type must be null, but is string");
        CHECK_THROWS_WITH(json(json::value_t::object).get<std::nullptr_t>(),
                          "[json.exception.type_error.302] type must be null, but is object");
        CHECK_THROWS_WITH(json(json::value_t::array).get<std::nullptr_t>(),
                          "[json.exception.type_error.302] type must be null, but is array");
        CHECK_THROWS_WITH(json(json::value_t::boolean).get<std::nullptr_t>(),
                          "[json.exception.type_error.302] type must be null, but is boolean");
        CHECK_THROWS_WITH(json(json::value_t::number_integer).get<std::nullptr_t>(),
                          "[json.exception.type_error.302] type must be null, but is number");
        CHECK_THROWS_WITH(json(json::value_t::number_unsigned).get<std::nullptr_t>(),
                          "[json.exception.type_error.302] type must be null, but is number");
        CHECK_THROWS_WITH(json(json::value_t::number_float).get<std::nullptr_t>(),
                          "[json.exception.type_error.302] type must be null, but is number");

    }

    SECTION("get a string (implicit)")
    {
        json::string_t s_reference{"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            json::string_t s = j;
            CHECK(json(s) == j);
        }

#if defined(JSON_HAS_CPP_17)
        SECTION("std::string_view")
        {
            std::string_view s = j.get<std::string_view>();
            CHECK(json(s) == j);
        }
#endif

        SECTION("std::string")
        {
            std::string s = j;
            CHECK(json(s) == j);
        }
    }

    SECTION("get a boolean (explicit)")
    {
        json::boolean_t b_reference{true};
        json j(b_reference);

        SECTION("boolean_t")
        {
            json::boolean_t b = j.get<json::boolean_t>();
            CHECK(json(b) == j);
        }

        SECTION("uint8_t")
        {
            auto n = j.get<uint8_t>();
            CHECK(n == 1);
        }

        SECTION("bool")
        {
            bool b = j.get<bool>();
            CHECK(json(b) == j);
        }

        SECTION("exception in case of a non-number type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::boolean_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::boolean_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::boolean_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::boolean_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::string).get<uint8_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(
                json(json::value_t::number_integer).get<json::boolean_t>(),
                json::type_error&);
            CHECK_THROWS_AS(
                json(json::value_t::number_unsigned).get<json::boolean_t>(),
                json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::boolean_t>(),
                            json::type_error&);

            CHECK_THROWS_WITH(
                json(json::value_t::null).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is null");
            CHECK_THROWS_WITH(json(json::value_t::object).get<json::boolean_t>(),
                              "[json.exception.type_error.302] type must be boolean, "
                              "but is object");
            CHECK_THROWS_WITH(
                json(json::value_t::array).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is array");
            CHECK_THROWS_WITH(json(json::value_t::string).get<json::boolean_t>(),
                              "[json.exception.type_error.302] type must be boolean, "
                              "but is string");
            CHECK_THROWS_WITH(
                json(json::value_t::number_integer).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is "
                "number");
            CHECK_THROWS_WITH(
                json(json::value_t::number_unsigned).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is "
                "number");
            CHECK_THROWS_WITH(
                json(json::value_t::number_float).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is "
                "number");
        }
    }

    SECTION("get a boolean (implicit)")
    {
        json::boolean_t b_reference{true};
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
        json::number_integer_t n_reference{42};
        json j(n_reference);
        json::number_unsigned_t n_unsigned_reference{42u};
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
            CHECK_THROWS_AS(json(json::value_t::null).get<json::number_integer_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::number_integer_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::number_integer_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::number_integer_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(
                json(json::value_t::boolean).get<json::number_integer_t>(),
                json::type_error&);

            CHECK_THROWS_WITH(
                json(json::value_t::null).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is null");
            CHECK_THROWS_WITH(
                json(json::value_t::object).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is object");
            CHECK_THROWS_WITH(
                json(json::value_t::array).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is array");
            CHECK_THROWS_WITH(
                json(json::value_t::string).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is string");
            CHECK_THROWS_WITH(
                json(json::value_t::boolean).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is "
                "boolean");

            CHECK_NOTHROW(
                json(json::value_t::number_float).get<json::number_integer_t>());
            CHECK_NOTHROW(
                json(json::value_t::number_float).get<json::number_unsigned_t>());
        }
    }

    SECTION("get an integer number (implicit)")
    {
        json::number_integer_t n_reference{42};
        json j(n_reference);
        json::number_unsigned_t n_unsigned_reference{42u};
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
        json::number_float_t n_reference{42.23};
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
            CHECK_THROWS_AS(json(json::value_t::null).get<json::number_float_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::number_float_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::number_float_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::number_float_t>(),
                            json::type_error&);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::number_float_t>(),
                            json::type_error&);

            CHECK_THROWS_WITH(
                json(json::value_t::null).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is null");
            CHECK_THROWS_WITH(
                json(json::value_t::object).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is object");
            CHECK_THROWS_WITH(
                json(json::value_t::array).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is array");
            CHECK_THROWS_WITH(
                json(json::value_t::string).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is string");
            CHECK_THROWS_WITH(
                json(json::value_t::boolean).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is "
                "boolean");

            CHECK_NOTHROW(
                json(json::value_t::number_integer).get<json::number_float_t>());
            CHECK_NOTHROW(
                json(json::value_t::number_unsigned).get<json::number_float_t>());
        }
    }

    SECTION("get a floating-point number (implicit)")
    {
        json::number_float_t n_reference{42.23};
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

    SECTION("get an enum")
    {
        enum c_enum { value_1, value_2 };
        enum class cpp_enum { value_1, value_2 };

        CHECK(json(value_1).get<c_enum>() == value_1);
        CHECK(json(cpp_enum::value_1).get<cpp_enum>() == cpp_enum::value_1);
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
                j1.get<std::map<std::string, int>>();
                j2.get<std::map<std::string, unsigned int>>();
                j3.get<std::map<std::string, double>>();
                j4.get<std::map<std::string, bool>>();
                j5.get<std::map<std::string, std::string>>();
            }

            SECTION("std::unordered_map")
            {
                j1.get<std::unordered_map<std::string, int>>();
                j2.get<std::unordered_map<std::string, unsigned int>>();
                j3.get<std::unordered_map<std::string, double>>();
                j4.get<std::unordered_map<std::string, bool>>();
                j5.get<std::unordered_map<std::string, std::string>>();
                // CHECK(m5["one"] == "eins");
            }

            SECTION("std::multimap")
            {
                j1.get<std::multimap<std::string, int>>();
                j2.get<std::multimap<std::string, unsigned int>>();
                j3.get<std::multimap<std::string, double>>();
                j4.get<std::multimap<std::string, bool>>();
                j5.get<std::multimap<std::string, std::string>>();
                // CHECK(m5["one"] == "eins");
            }

            SECTION("std::unordered_multimap")
            {
                j1.get<std::unordered_multimap<std::string, int>>();
                j2.get<std::unordered_multimap<std::string, unsigned int>>();
                j3.get<std::unordered_multimap<std::string, double>>();
                j4.get<std::unordered_multimap<std::string, bool>>();
                j5.get<std::unordered_multimap<std::string, std::string>>();
                // CHECK(m5["one"] == "eins");
            }

            SECTION("exception in case of a non-object type")
            {
                CHECK_THROWS_AS((json().get<std::map<std::string, int>>()),
                                json::type_error&);
                CHECK_THROWS_WITH(
                    (json().get<std::map<std::string, int>>()),
                    "[json.exception.type_error.302] type must be object, but is null");
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
                j1.get<std::list<int>>();
                j2.get<std::list<unsigned int>>();
                j3.get<std::list<double>>();
                j4.get<std::list<bool>>();
                j5.get<std::list<std::string>>();
            }

            SECTION("std::forward_list")
            {
                j1.get<std::forward_list<int>>();
                j2.get<std::forward_list<unsigned int>>();
                j3.get<std::forward_list<double>>();
                j4.get<std::forward_list<bool>>();
                j5.get<std::forward_list<std::string>>();
            }

            SECTION("std::array")
            {
                j1.get<std::array<int, 4>>();
                j2.get<std::array<unsigned int, 3>>();
                j3.get<std::array<double, 4>>();
                j4.get<std::array<bool, 3>>();
                j5.get<std::array<std::string, 3>>();

                SECTION("std::array is larger than JSON")
                {
                    std::array<int, 6> arr6 = {{1, 2, 3, 4, 5, 6}};
                    CHECK_THROWS_AS(arr6 = j1, json::out_of_range&);
                    CHECK_THROWS_WITH(arr6 = j1, "[json.exception.out_of_range.401] "
                                      "array index 4 is out of range");
                }

                SECTION("std::array is smaller than JSON")
                {
                    std::array<int, 2> arr2 = {{8, 9}};
                    arr2 = j1;
                    CHECK(arr2[0] == 1);
                    CHECK(arr2[1] == 2);
                }
            }

            SECTION("std::valarray")
            {
                j1.get<std::valarray<int>>();
                j2.get<std::valarray<unsigned int>>();
                j3.get<std::valarray<double>>();
                j4.get<std::valarray<bool>>();
                j5.get<std::valarray<std::string>>();
            }

            SECTION("std::vector")
            {
                j1.get<std::vector<int>>();
                j2.get<std::vector<unsigned int>>();
                j3.get<std::vector<double>>();
                j4.get<std::vector<bool>>();
                j5.get<std::vector<std::string>>();
            }

            SECTION("std::deque")
            {
                j1.get<std::deque<int>>();
                j2.get<std::deque<unsigned int>>();
                j2.get<std::deque<double>>();
                j4.get<std::deque<bool>>();
                j5.get<std::deque<std::string>>();
            }

            SECTION("std::set")
            {
                j1.get<std::set<int>>();
                j2.get<std::set<unsigned int>>();
                j3.get<std::set<double>>();
                j4.get<std::set<bool>>();
                j5.get<std::set<std::string>>();
            }

            SECTION("std::unordered_set")
            {
                j1.get<std::unordered_set<int>>();
                j2.get<std::unordered_set<unsigned int>>();
                j3.get<std::unordered_set<double>>();
                j4.get<std::unordered_set<bool>>();
                j5.get<std::unordered_set<std::string>>();
            }

            SECTION("std::map (array of pairs)")
            {
                std::map<int, int> m{{0, 1}, {1, 2}, {2, 3}};
                json j6 = m;

                auto m2 = j6.get<std::map<int, int>>();
                CHECK(m == m2);

                json j7 = {0, 1, 2, 3};
                json j8 = 2;
                CHECK_THROWS_AS((j7.get<std::map<int, int>>()), json::type_error&);
                CHECK_THROWS_AS((j8.get<std::map<int, int>>()), json::type_error&);
                CHECK_THROWS_WITH((j7.get<std::map<int, int>>()),
                                  "[json.exception.type_error.302] type must be array, "
                                  "but is number");
                CHECK_THROWS_WITH((j8.get<std::map<int, int>>()),
                                  "[json.exception.type_error.302] type must be array, "
                                  "but is number");

                SECTION("superfluous entries")
                {
                    json j9 = {{0, 1, 2}, {1, 2, 3}, {2, 3, 4}};
                    m2 = j9.get<std::map<int, int>>();
                    CHECK(m == m2);
                }
            }

            SECTION("std::unordered_map (array of pairs)")
            {
                std::unordered_map<int, int> m{{0, 1}, {1, 2}, {2, 3}};
                json j6 = m;

                auto m2 = j6.get<std::unordered_map<int, int>>();
                CHECK(m == m2);

                json j7 = {0, 1, 2, 3};
                json j8 = 2;
                CHECK_THROWS_AS((j7.get<std::unordered_map<int, int>>()), json::type_error&);
                CHECK_THROWS_AS((j8.get<std::unordered_map<int, int>>()), json::type_error&);
                CHECK_THROWS_WITH((j7.get<std::unordered_map<int, int>>()),
                                  "[json.exception.type_error.302] type must be array, "
                                  "but is number");
                CHECK_THROWS_WITH((j8.get<std::unordered_map<int, int>>()),
                                  "[json.exception.type_error.302] type must be array, "
                                  "but is number");

                SECTION("superfluous entries")
                {
                    json j9{{0, 1, 2}, {1, 2, 3}, {2, 3, 4}};
                    m2 = j9.get<std::unordered_map<int, int>>();
                    CHECK(m == m2);
                }
            }

            SECTION("exception in case of a non-object type")
            {
                CHECK_THROWS_AS((json().get<std::list<int>>()), json::type_error&);
                CHECK_THROWS_AS((json().get<std::vector<int>>()), json::type_error&);
                CHECK_THROWS_AS((json().get<std::vector<json>>()), json::type_error&);
                CHECK_THROWS_AS((json().get<std::list<json>>()), json::type_error&);
                CHECK_THROWS_AS((json().get<std::valarray<int>>()), json::type_error&);

                // does type really must be an array? or it rather must not be null?
                // that's what I thought when other test like this one broke
                CHECK_THROWS_WITH(
                    (json().get<std::list<int>>()),
                    "[json.exception.type_error.302] type must be array, but is null");
                CHECK_THROWS_WITH(
                    (json().get<std::vector<int>>()),
                    "[json.exception.type_error.302] type must be array, but is null");
                CHECK_THROWS_WITH(
                    (json().get<std::vector<json>>()),
                    "[json.exception.type_error.302] type must be array, but is null");
                CHECK_THROWS_WITH(
                    (json().get<std::list<json>>()),
                    "[json.exception.type_error.302] type must be array, but is null");
                CHECK_THROWS_WITH(
                    (json().get<std::valarray<int>>()),
                    "[json.exception.type_error.302] type must be array, but is null");
                CHECK_THROWS_WITH(
                    (json().get<std::map<int, int>>()),
                    "[json.exception.type_error.302] type must be array, but is null");
            }
        }
    }
}

enum class cards {kreuz, pik, herz, karo};

NLOHMANN_JSON_SERIALIZE_ENUM(cards,
{
    {cards::kreuz, "kreuz"},
    {cards::pik, "pik"},
    {cards::pik, "puk"},  // second entry for cards::puk; will not be used
    {cards::herz, "herz"},
    {cards::karo, "karo"}
})

enum TaskState
{
    TS_STOPPED,
    TS_RUNNING,
    TS_COMPLETED,
    TS_INVALID = -1,
};

NLOHMANN_JSON_SERIALIZE_ENUM(TaskState,
{
    {TS_INVALID, nullptr},
    {TS_STOPPED, "stopped"},
    {TS_RUNNING, "running"},
    {TS_COMPLETED, "completed"},
})

TEST_CASE("JSON to enum mapping")
{
    SECTION("enum class")
    {
        // enum -> json
        CHECK(json(cards::kreuz) == "kreuz");
        CHECK(json(cards::pik) == "pik");
        CHECK(json(cards::herz) == "herz");
        CHECK(json(cards::karo) == "karo");

        // json -> enum
        CHECK(cards::kreuz == json("kreuz"));
        CHECK(cards::pik == json("pik"));
        CHECK(cards::herz == json("herz"));
        CHECK(cards::karo == json("karo"));

        // invalid json -> first enum
        CHECK(cards::kreuz == json("what?").get<cards>());
    }

    SECTION("traditional enum")
    {
        // enum -> json
        CHECK(json(TS_STOPPED) == "stopped");
        CHECK(json(TS_RUNNING) == "running");
        CHECK(json(TS_COMPLETED) == "completed");
        CHECK(json(TS_INVALID) == json());

        // json -> enum
        CHECK(TS_STOPPED == json("stopped"));
        CHECK(TS_RUNNING == json("running"));
        CHECK(TS_COMPLETED == json("completed"));
        CHECK(TS_INVALID == json());

        // invalid json -> first enum
        CHECK(TS_INVALID == json("what?").get<TaskState>());
    }
}
