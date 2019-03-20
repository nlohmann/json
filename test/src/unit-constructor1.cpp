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

#include "catch.hpp"

#define private public
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <deque>
#include <forward_list>
#include <fstream>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <valarray>

TEST_CASE("constructors")
{
    SECTION("create an empty value with a given type")
    {
        SECTION("null")
        {
            auto t = json::value_t::null;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("discarded")
        {
            auto t = json::value_t::discarded;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("object")
        {
            auto t = json::value_t::object;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("array")
        {
            auto t = json::value_t::array;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("boolean")
        {
            auto t = json::value_t::boolean;
            json j(t);
            CHECK(j.type() == t);
            CHECK(j == false);
        }

        SECTION("string")
        {
            auto t = json::value_t::string;
            json j(t);
            CHECK(j.type() == t);
            CHECK(j == "");
        }

        SECTION("number_integer")
        {
            auto t = json::value_t::number_integer;
            json j(t);
            CHECK(j.type() == t);
            CHECK(j == 0);
        }

        SECTION("number_unsigned")
        {
            auto t = json::value_t::number_unsigned;
            json j(t);
            CHECK(j.type() == t);
            CHECK(j == 0);
        }

        SECTION("number_float")
        {
            auto t = json::value_t::number_float;
            json j(t);
            CHECK(j.type() == t);
            CHECK(j == 0.0);
        }
    }

    SECTION("create a null object (implicitly)")
    {
        SECTION("no parameter")
        {
            json j{};
            CHECK(j.type() == json::value_t::null);
        }
    }

    SECTION("create a null object (explicitly)")
    {
        SECTION("parameter")
        {
            json j(nullptr);
            CHECK(j.type() == json::value_t::null);
        }
    }

    SECTION("create an object (explicit)")
    {
        SECTION("empty object")
        {
            json::object_t o;
            json j(o);
            CHECK(j.type() == json::value_t::object);
        }

        SECTION("filled object")
        {
            json::object_t o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
        }
    }

    SECTION("create an object (implicit)")
    {
        // reference object
        json::object_t o_reference {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
        json j_reference(o_reference);

        SECTION("std::map<json::string_t, json>")
        {
            std::map<json::string_t, json> o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::map<std::string, std::string> #600")
        {
            std::map<std::string, std::string> m;
            m["a"] = "b";
            m["c"] = "d";
            m["e"] = "f";

            json j(m);
            CHECK((j.get<decltype(m)>() == m));
        }

        SECTION("std::map<const char*, json>")
        {
            std::map<const char*, json> o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }


        SECTION("std::multimap<json::string_t, json>")
        {
            std::multimap<json::string_t, json> o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            std::unordered_map<json::string_t, json> o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            std::unordered_multimap<json::string_t, json> o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("associative container literal")
        {
            json j({{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}});
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }
    }

    SECTION("create an array (explicit)")
    {
        SECTION("empty array")
        {
            json::array_t a;
            json j(a);
            CHECK(j.type() == json::value_t::array);
        }

        SECTION("filled array")
        {
            json::array_t a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
        }
    }

    SECTION("create an array (implicit)")
    {
        // reference array
        json::array_t a_reference {json(1), json(1u), json(2.2), json(false), json("string"), json()};
        json j_reference(a_reference);

        SECTION("std::list<json>")
        {
            std::list<json> a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::pair")
        {
            std::pair<float, std::string> p{1.0f, "string"};
            json j(p);

            CHECK(j.type() == json::value_t::array);
            CHECK(j.get<decltype(p)>() == p);
            REQUIRE(j.size() == 2);
            CHECK(j[0] == std::get<0>(p));
            CHECK(j[1] == std::get<1>(p));
        }

        SECTION("std::pair with discarded values")
        {
            json j{1, 2.0, "string"};

            const auto p = j.get<std::pair<int, float>>();
            CHECK(p.first == j[0]);
            CHECK(p.second == j[1]);
        }

        SECTION("std::tuple")
        {
            const auto t = std::make_tuple(1.0, std::string{"string"}, 42, std::vector<int> {0, 1});
            json j(t);

            CHECK(j.type() == json::value_t::array);
            REQUIRE(j.size() == 4);
            CHECK(j.get<decltype(t)>() == t);
            CHECK(j[0] == std::get<0>(t));
            CHECK(j[1] == std::get<1>(t));
            CHECK(j[2] == std::get<2>(t));
            CHECK(j[3][0] == 0);
            CHECK(j[3][1] == 1);
        }

        SECTION("std::tuple with discarded values")
        {
            json j{1, 2.0, "string", 42};

            const auto t = j.get<std::tuple<int, float, std::string>>();
            CHECK(std::get<0>(t) == j[0]);
            CHECK(std::get<1>(t) == j[1]);
            CHECK(std::get<2>(t) == j[2]);
        }

        SECTION("std::pair/tuple/array failures")
        {
            json j{1};

            CHECK_THROWS_AS((j.get<std::pair<int, int>>()), json::out_of_range&);
            CHECK_THROWS_WITH((j.get<std::pair<int, int>>()), "[json.exception.out_of_range.401] array index 1 is out of range");
            CHECK_THROWS_AS((j.get<std::tuple<int, int>>()), json::out_of_range&);
            CHECK_THROWS_WITH((j.get<std::tuple<int, int>>()), "[json.exception.out_of_range.401] array index 1 is out of range");
            CHECK_THROWS_AS((j.get<std::array<int, 3>>()), json::out_of_range&);
            CHECK_THROWS_WITH((j.get<std::array<int, 3>>()), "[json.exception.out_of_range.401] array index 1 is out of range");
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::array<json, 6>")
        {
            std::array<json, 6> a {{json(1), json(1u), json(2.2), json(false), json("string"), json()}};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);

            const auto a2 = j.get<std::array<json, 6>>();
            CHECK(a2 == a);
        }

        SECTION("std::valarray<int>")
        {
            std::valarray<int> va = {1, 2, 3, 4, 5};
            json j(va);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == json({1, 2, 3, 4, 5}));

            std::valarray<int> jva = j;
            CHECK(jva.size() == va.size());
            for (size_t i = 0; i < jva.size(); ++i)
            {
                CHECK(va[i] == jva[i]);
            }
        }

        SECTION("std::valarray<double>")
        {
            std::valarray<double> va = {1.2, 2.3, 3.4, 4.5, 5.6};
            json j(va);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == json({1.2, 2.3, 3.4, 4.5, 5.6}));

            std::valarray<double> jva = j;
            CHECK(jva.size() == va.size());
            for (size_t i = 0; i < jva.size(); ++i)
            {
                CHECK(va[i] == jva[i]);
            }
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::set<json>")
        {
            std::set<json> a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            // we cannot really check for equality here
        }

        SECTION("std::unordered_set<json>")
        {
            std::unordered_set<json> a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            // we cannot really check for equality here
        }

        SECTION("sequence container literal")
        {
            json j({json(1), json(1u), json(2.2), json(false), json("string"), json()});
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }
    }

    SECTION("create a string (explicit)")
    {
        SECTION("empty string")
        {
            json::string_t s;
            json j(s);
            CHECK(j.type() == json::value_t::string);
        }

        SECTION("filled string")
        {
            json::string_t s {"Hello world"};
            json j(s);
            CHECK(j.type() == json::value_t::string);
        }
    }

    SECTION("create a string (implicit)")
    {
        // reference string
        json::string_t s_reference {"Hello world"};
        json j_reference(s_reference);

        SECTION("std::string")
        {
            std::string s {"Hello world"};
            json j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("char[]")
        {
            char s[] {"Hello world"};
            json j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("const char*")
        {
            const char* s {"Hello world"};
            json j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("string literal")
        {
            json j("Hello world");
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }
    }

    SECTION("create a boolean (explicit)")
    {
        SECTION("empty boolean")
        {
            json::boolean_t b{};
            json j(b);
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("filled boolean (true)")
        {
            json j(true);
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("filled boolean (false)")
        {
            json j(false);
            CHECK(j.type() == json::value_t::boolean);
        }
    }

    SECTION("create an integer number (explicit)")
    {
        SECTION("uninitialized value")
        {
            json::number_integer_t n{};
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
        }

        SECTION("initialized value")
        {
            json::number_integer_t n(42);
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
        }
    }

    SECTION("create an integer number (implicit)")
    {
        // reference objects
        json::number_integer_t n_reference = 42;
        json j_reference(n_reference);
        json::number_unsigned_t n_unsigned_reference = 42;
        json j_unsigned_reference(n_unsigned_reference);

        SECTION("short")
        {
            short n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned short")
        {
            unsigned short n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("int")
        {
            int n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned int")
        {
            unsigned int n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("long")
        {
            long n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned long")
        {
            unsigned long n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("long long")
        {
            long long n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned long long")
        {
            unsigned long long n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("int8_t")
        {
            int8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int16_t")
        {
            int16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int32_t")
        {
            int32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int64_t")
        {
            int64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast8_t")
        {
            int_fast8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast16_t")
        {
            int_fast16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast32_t")
        {
            int_fast32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast64_t")
        {
            int_fast64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least8_t")
        {
            int_least8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least16_t")
        {
            int_least16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least32_t")
        {
            int_least32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least64_t")
        {
            int_least64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint8_t")
        {
            uint8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint16_t")
        {
            uint16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint32_t")
        {
            uint32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint64_t")
        {
            uint64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_fast8_t")
        {
            uint_fast8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_fast16_t")
        {
            uint_fast16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_fast32_t")
        {
            uint_fast32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_fast64_t")
        {
            uint_fast64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_least8_t")
        {
            uint_least8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_least16_t")
        {
            uint_least16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_least32_t")
        {
            uint_least32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_least64_t")
        {
            uint_least64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("integer literal without suffix")
        {
            json j(42);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal with u suffix")
        {
            json j(42u);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("integer literal with l suffix")
        {
            json j(42l);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal with ul suffix")
        {
            json j(42ul);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("integer literal with ll suffix")
        {
            json j(42ll);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal with ull suffix")
        {
            json j(42ull);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }
    }

    SECTION("create a floating-point number (explicit)")
    {
        SECTION("uninitialized value")
        {
            json::number_float_t n{};
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
        }

        SECTION("initialized value")
        {
            json::number_float_t n(42.23);
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
        }

        SECTION("infinity")
        {
            // infinity is stored properly, but serialized to null
            json::number_float_t n(std::numeric_limits<json::number_float_t>::infinity());
            json j(n);
            CHECK(j.type() == json::value_t::number_float);

            // check round trip of infinity
            json::number_float_t d = j;
            CHECK(d == n);

            // check that inf is serialized to null
            CHECK(j.dump() == "null");
        }
    }

    SECTION("create a floating-point number (implicit)")
    {
        // reference object
        json::number_float_t n_reference = 42.23;
        json j_reference(n_reference);

        SECTION("float")
        {
            float n = 42.23f;
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("double")
        {
            double n = 42.23;
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("long double")
        {
            long double n = 42.23l;
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("floating-point literal without suffix")
        {
            json j(42.23);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("integer literal with f suffix")
        {
            json j(42.23f);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("integer literal with l suffix")
        {
            json j(42.23l);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }
    }

    SECTION("create a container (array or object) from an initializer list")
    {
        SECTION("empty initializer list")
        {
            SECTION("explicit")
            {
                json j(json::initializer_list_t {});
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("implicit")
            {
                json j {};
                CHECK(j.type() == json::value_t::null);
            }
        }

        SECTION("one element")
        {
            SECTION("array")
            {
                SECTION("explicit")
                {
                    json j(json::initializer_list_t {json(json::array_t())});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {json::array_t()};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("object")
            {
                SECTION("explicit")
                {
                    json j(json::initializer_list_t {json(json::object_t())});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {json::object_t()};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("string")
            {
                SECTION("explicit")
                {
                    json j(json::initializer_list_t {json("Hello world")});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {"Hello world"};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("boolean")
            {
                SECTION("explicit")
                {
                    json j(json::initializer_list_t {json(true)});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {true};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("number (integer)")
            {
                SECTION("explicit")
                {
                    json j(json::initializer_list_t {json(1)});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {1};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("number (unsigned)")
            {
                SECTION("explicit")
                {
                    json j(json::initializer_list_t {json(1u)});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {1u};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("number (floating-point)")
            {
                SECTION("explicit")
                {
                    json j(json::initializer_list_t {json(42.23)});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {42.23};
                    CHECK(j.type() == json::value_t::array);
                }
            }
        }

        SECTION("more elements")
        {
            SECTION("explicit")
            {
                json j(json::initializer_list_t {1, 1u, 42.23, true, nullptr, json::object_t(), json::array_t()});
                CHECK(j.type() == json::value_t::array);
            }

            SECTION("implicit")
            {
                json j {1, 1u, 42.23, true, nullptr, json::object_t(), json::array_t()};
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("implicit type deduction")
        {
            SECTION("object")
            {
                json j { {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false} };
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("array")
            {
                json j { {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false}, 13 };
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("explicit type deduction")
        {
            SECTION("empty object")
            {
                json j = json::object();
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("object")
            {
                json j = json::object({ {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false} });
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("object with error")
            {
                CHECK_THROWS_AS(json::object({ {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false}, 13 }),
                json::type_error&);
                CHECK_THROWS_WITH(json::object({ {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false}, 13 }),
                "[json.exception.type_error.301] cannot create object from initializer list");
            }

            SECTION("empty array")
            {
                json j = json::array();
                CHECK(j.type() == json::value_t::array);
            }

            SECTION("array")
            {
                json j = json::array({ {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false} });
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("move from initializer_list")
        {
            SECTION("string")
            {
                // This should break through any short string optimization in std::string
                std::string source(1024, '!');
                const char* source_addr = source.data();

                SECTION("constructor with implicit types (array)")
                {
                    json j = {std::move(source)};
                    CHECK(j[0].get_ref<std::string const&>().data() == source_addr);
                }

                SECTION("constructor with implicit types (object)")
                {
                    json j = {{"key", std::move(source)}};
                    CHECK(j["key"].get_ref<std::string const&>().data() == source_addr);
                }

                SECTION("constructor with implicit types (object key)")
                {
                    json j = {{std::move(source), 42}};
                    CHECK(j.get_ref<json::object_t&>().begin()->first.data() == source_addr);
                }
            }

            SECTION("array")
            {
                json::array_t source = {1, 2, 3};
                const json* source_addr = source.data();

                SECTION("constructor with implicit types (array)")
                {
                    json j {std::move(source)};
                    CHECK(j[0].get_ref<json::array_t const&>().data() == source_addr);
                }

                SECTION("constructor with implicit types (object)")
                {
                    json j {{"key", std::move(source)}};
                    CHECK(j["key"].get_ref<json::array_t const&>().data() == source_addr);
                }

                SECTION("assignment with implicit types (array)")
                {
                    json j = {std::move(source)};
                    CHECK(j[0].get_ref<json::array_t const&>().data() == source_addr);
                }

                SECTION("assignment with implicit types (object)")
                {
                    json j = {{"key", std::move(source)}};
                    CHECK(j["key"].get_ref<json::array_t const&>().data() == source_addr);
                }
            }

            SECTION("object")
            {
                json::object_t source = {{"hello", "world"}};
                const json* source_addr = &source.at("hello");

                SECTION("constructor with implicit types (array)")
                {
                    json j {std::move(source)};
                    CHECK(&(j[0].get_ref<json::object_t const&>().at("hello")) == source_addr);
                }

                SECTION("constructor with implicit types (object)")
                {
                    json j {{"key", std::move(source)}};
                    CHECK(&(j["key"].get_ref<json::object_t const&>().at("hello")) == source_addr);
                }

                SECTION("assignment with implicit types (array)")
                {
                    json j = {std::move(source)};
                    CHECK(&(j[0].get_ref<json::object_t const&>().at("hello")) == source_addr);
                }

                SECTION("assignment with implicit types (object)")
                {
                    json j = {{"key", std::move(source)}};
                    CHECK(&(j["key"].get_ref<json::object_t const&>().at("hello")) == source_addr);
                }
            }

            SECTION("json")
            {
                json source {1, 2, 3};
                const json* source_addr = &source[0];

                SECTION("constructor with implicit types (array)")
                {
                    json j {std::move(source), {}};
                    CHECK(&j[0][0] == source_addr);
                }

                SECTION("constructor with implicit types (object)")
                {
                    json j {{"key", std::move(source)}};
                    CHECK(&j["key"][0] == source_addr);
                }

                SECTION("assignment with implicit types (array)")
                {
                    json j = {std::move(source), {}};
                    CHECK(&j[0][0] == source_addr);
                }

                SECTION("assignment with implicit types (object)")
                {
                    json j = {{"key", std::move(source)}};
                    CHECK(&j["key"][0] == source_addr);
                }
            }

        }
    }

    SECTION("create an array of n copies of a given value")
    {
        SECTION("cnt = 0")
        {
            json v = {1, "foo", 34.23, {1, 2, 3}, {{"A", 1}, {"B", 2u}}};
            json arr(0, v);
            CHECK(arr.size() == 0);
        }

        SECTION("cnt = 1")
        {
            json v = {1, "foo", 34.23, {1, 2, 3}, {{"A", 1}, {"B", 2u}}};
            json arr(1, v);
            CHECK(arr.size() == 1);
            for (auto& x : arr)
            {
                CHECK(x == v);
            }
        }

        SECTION("cnt = 3")
        {
            json v = {1, "foo", 34.23, {1, 2, 3}, {{"A", 1}, {"B", 2u}}};
            json arr(3, v);
            CHECK(arr.size() == 3);
            for (auto& x : arr)
            {
                CHECK(x == v);
            }
        }
    }

    SECTION("create a JSON container from an iterator range")
    {
        SECTION("object")
        {
            SECTION("json(begin(), end())")
            {
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    json j_new(jobject.begin(), jobject.end());
                    CHECK(j_new == jobject);
                }
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    json j_new(jobject.cbegin(), jobject.cend());
                    CHECK(j_new == jobject);
                }
            }

            SECTION("json(begin(), begin())")
            {
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    json j_new(jobject.begin(), jobject.begin());
                    CHECK(j_new == json::object());
                }
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    json j_new(jobject.cbegin(), jobject.cbegin());
                    CHECK(j_new == json::object());
                }
            }

            SECTION("construct from subrange")
            {
                json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                json j_new(jobject.find("b"), jobject.find("e"));
                CHECK(j_new == json({{"b", 1}, {"c", 17u}, {"d", false}}));
            }

            SECTION("incompatible iterators")
            {
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                    json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    CHECK_THROWS_AS(json(jobject.begin(), jobject2.end()), json::invalid_iterator&);
                    CHECK_THROWS_AS(json(jobject2.begin(), jobject.end()), json::invalid_iterator&);
                    CHECK_THROWS_WITH(json(jobject.begin(), jobject2.end()), "[json.exception.invalid_iterator.201] iterators are not compatible");
                    CHECK_THROWS_WITH(json(jobject2.begin(), jobject.end()), "[json.exception.invalid_iterator.201] iterators are not compatible");
                }
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                    json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    CHECK_THROWS_AS(json(jobject.cbegin(), jobject2.cend()), json::invalid_iterator&);
                    CHECK_THROWS_AS(json(jobject2.cbegin(), jobject.cend()), json::invalid_iterator&);
                    CHECK_THROWS_WITH(json(jobject.cbegin(), jobject2.cend()), "[json.exception.invalid_iterator.201] iterators are not compatible");
                    CHECK_THROWS_WITH(json(jobject2.cbegin(), jobject.cend()), "[json.exception.invalid_iterator.201] iterators are not compatible");
                }
            }
        }

        SECTION("array")
        {
            SECTION("json(begin(), end())")
            {
                {
                    json jarray = {1, 2, 3, 4, 5};
                    json j_new(jarray.begin(), jarray.end());
                    CHECK(j_new == jarray);
                }
                {
                    json jarray = {1, 2, 3, 4, 5};
                    json j_new(jarray.cbegin(), jarray.cend());
                    CHECK(j_new == jarray);
                }
            }

            SECTION("json(begin(), begin())")
            {
                {
                    json jarray = {1, 2, 3, 4, 5};
                    json j_new(jarray.begin(), jarray.begin());
                    CHECK(j_new == json::array());
                }
                {
                    json jarray = {1, 2, 3, 4, 5};
                    json j_new(jarray.cbegin(), jarray.cbegin());
                    CHECK(j_new == json::array());
                }
            }

            SECTION("construct from subrange")
            {
                {
                    json jarray = {1, 2, 3, 4, 5};
                    json j_new(jarray.begin() + 1, jarray.begin() + 3);
                    CHECK(j_new == json({2, 3}));
                }
                {
                    json jarray = {1, 2, 3, 4, 5};
                    json j_new(jarray.cbegin() + 1, jarray.cbegin() + 3);
                    CHECK(j_new == json({2, 3}));
                }
            }

            SECTION("incompatible iterators")
            {
                {
                    json jarray = {1, 2, 3, 4};
                    json jarray2 = {2, 3, 4, 5};
                    CHECK_THROWS_AS(json(jarray.begin(), jarray2.end()), json::invalid_iterator&);
                    CHECK_THROWS_AS(json(jarray2.begin(), jarray.end()), json::invalid_iterator&);
                    CHECK_THROWS_WITH(json(jarray.begin(), jarray2.end()), "[json.exception.invalid_iterator.201] iterators are not compatible");
                    CHECK_THROWS_WITH(json(jarray2.begin(), jarray.end()), "[json.exception.invalid_iterator.201] iterators are not compatible");
                }
                {
                    json jarray = {1, 2, 3, 4};
                    json jarray2 = {2, 3, 4, 5};
                    CHECK_THROWS_AS(json(jarray.cbegin(), jarray2.cend()), json::invalid_iterator&);
                    CHECK_THROWS_AS(json(jarray2.cbegin(), jarray.cend()), json::invalid_iterator&);
                    CHECK_THROWS_WITH(json(jarray.cbegin(), jarray2.cend()), "[json.exception.invalid_iterator.201] iterators are not compatible");
                    CHECK_THROWS_WITH(json(jarray2.cbegin(), jarray.cend()), "[json.exception.invalid_iterator.201] iterators are not compatible");
                }
            }
        }

        SECTION("other values")
        {
            SECTION("construct with two valid iterators")
            {
                SECTION("null")
                {
                    {
                        json j;
                        CHECK_THROWS_AS(json(j.begin(), j.end()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.begin(), j.end()),
                                          "[json.exception.invalid_iterator.206] cannot construct with iterators from null");
                    }
                    {
                        json j;
                        CHECK_THROWS_AS(json(j.cbegin(), j.cend()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cend()),
                                          "[json.exception.invalid_iterator.206] cannot construct with iterators from null");
                    }
                }

                SECTION("string")
                {
                    {
                        json j = "foo";
                        json j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json j = "bar";
                        json j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("number (boolean)")
                {
                    {
                        json j = false;
                        json j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json j = true;
                        json j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17;
                        json j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json j = 17;
                        json j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("number (unsigned)")
                {
                    {
                        json j = 17u;
                        json j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json j = 17u;
                        json j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("number (floating point)")
                {
                    {
                        json j = 23.42;
                        json j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json j = 23.42;
                        json j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }
            }

            SECTION("construct with two invalid iterators")
            {
                SECTION("string")
                {
                    {
                        json j = "foo";
                        CHECK_THROWS_AS(json(j.end(), j.end()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                    {
                        json j = "bar";
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                }

                SECTION("number (boolean)")
                {
                    {
                        json j = false;
                        CHECK_THROWS_AS(json(j.end(), j.end()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                    {
                        json j = true;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17;
                        CHECK_THROWS_AS(json(j.end(), j.end()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                    {
                        json j = 17;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17u;
                        CHECK_THROWS_AS(json(j.end(), j.end()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                    {
                        json j = 17u;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                }

                SECTION("number (floating point)")
                {
                    {
                        json j = 23.42;
                        CHECK_THROWS_AS(json(j.end(), j.end()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                    {
                        json j = 23.42;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), json::invalid_iterator&);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range");
                    }
                }
            }
        }
    }
}
