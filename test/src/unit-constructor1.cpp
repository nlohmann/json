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
#include <fstream>
#include <list>
#include <unordered_map>
#include <unordered_set>

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
        }

        SECTION("string")
        {
            auto t = json::value_t::string;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("number_integer")
        {
            auto t = json::value_t::number_integer;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("number_unsigned")
        {
            auto t = json::value_t::number_unsigned;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("number_float")
        {
            auto t = json::value_t::number_float;
            json j(t);
            CHECK(j.type() == t);
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

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::array<json, 5>")
        {
            std::array<json, 6> a {{json(1), json(1u), json(2.2), json(false), json("string"), json()}};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
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
            long double n = 42.23;
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
                std::initializer_list<json> l;
                json j(l);
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
                    std::initializer_list<json> l = {json(json::array_t())};
                    json j(l);
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
                    std::initializer_list<json> l = {json(json::object_t())};
                    json j(l);
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
                    std::initializer_list<json> l = {json("Hello world")};
                    json j(l);
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
                    std::initializer_list<json> l = {json(true)};
                    json j(l);
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
                    std::initializer_list<json> l = {json(1)};
                    json j(l);
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
                    std::initializer_list<json> l = {json(1u)};
                    json j(l);
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
                    std::initializer_list<json> l = {json(42.23)};
                    json j(l);
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
                std::initializer_list<json> l = {1, 1u, 42.23, true, nullptr, json::object_t(), json::array_t()};
                json j(l);
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
                std::logic_error);
                CHECK_THROWS_WITH(json::object({ {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false}, 13 }),
                "cannot create object from initializer list");
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
    }

    SECTION("create an array of n copies of a given value")
    {
        json v = {1, "foo", 34.23, {1, 2, 3}, {{"A", 1}, {"B", 2u}}};
        json arr(3, v);
        CHECK(arr.size() == 3);
        for (auto& x : arr)
        {
            CHECK(x == v);
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
                    CHECK_THROWS_AS(json(jobject.begin(), jobject2.end()), std::domain_error);
                    CHECK_THROWS_AS(json(jobject2.begin(), jobject.end()), std::domain_error);
                    CHECK_THROWS_WITH(json(jobject.begin(), jobject2.end()), "iterators are not compatible");
                    CHECK_THROWS_WITH(json(jobject2.begin(), jobject.end()), "iterators are not compatible");
                }
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                    json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    CHECK_THROWS_AS(json(jobject.cbegin(), jobject2.cend()), std::domain_error);
                    CHECK_THROWS_AS(json(jobject2.cbegin(), jobject.cend()), std::domain_error);
                    CHECK_THROWS_WITH(json(jobject.cbegin(), jobject2.cend()), "iterators are not compatible");
                    CHECK_THROWS_WITH(json(jobject2.cbegin(), jobject.cend()), "iterators are not compatible");
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
                    CHECK_THROWS_AS(json(jarray.begin(), jarray2.end()), std::domain_error);
                    CHECK_THROWS_AS(json(jarray2.begin(), jarray.end()), std::domain_error);
                    CHECK_THROWS_WITH(json(jarray.begin(), jarray2.end()), "iterators are not compatible");
                    CHECK_THROWS_WITH(json(jarray2.begin(), jarray.end()), "iterators are not compatible");
                }
                {
                    json jarray = {1, 2, 3, 4};
                    json jarray2 = {2, 3, 4, 5};
                    CHECK_THROWS_AS(json(jarray.cbegin(), jarray2.cend()), std::domain_error);
                    CHECK_THROWS_AS(json(jarray2.cbegin(), jarray.cend()), std::domain_error);
                    CHECK_THROWS_WITH(json(jarray.cbegin(), jarray2.cend()), "iterators are not compatible");
                    CHECK_THROWS_WITH(json(jarray2.cbegin(), jarray.cend()), "iterators are not compatible");
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
                        CHECK_THROWS_AS(json(j.begin(), j.end()), std::domain_error);
                        CHECK_THROWS_WITH(json(j.begin(), j.end()), "cannot use construct with iterators from null");
                    }
                    {
                        json j;
                        CHECK_THROWS_AS(json(j.cbegin(), j.cend()), std::domain_error);
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cend()), "cannot use construct with iterators from null");
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
                        CHECK_THROWS_AS(json(j.end(), j.end()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "iterators out of range");
                    }
                    {
                        json j = "bar";
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "iterators out of range");
                    }
                }

                SECTION("number (boolean)")
                {
                    {
                        json j = false;
                        CHECK_THROWS_AS(json(j.end(), j.end()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "iterators out of range");
                    }
                    {
                        json j = true;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "iterators out of range");
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17;
                        CHECK_THROWS_AS(json(j.end(), j.end()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "iterators out of range");
                    }
                    {
                        json j = 17;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "iterators out of range");
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17u;
                        CHECK_THROWS_AS(json(j.end(), j.end()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "iterators out of range");
                    }
                    {
                        json j = 17u;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "iterators out of range");
                    }
                }

                SECTION("number (floating point)")
                {
                    {
                        json j = 23.42;
                        CHECK_THROWS_AS(json(j.end(), j.end()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.end(), j.end()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.begin(), j.begin()), "iterators out of range");
                    }
                    {
                        json j = 23.42;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                        CHECK_THROWS_WITH(json(j.cend(), j.cend()), "iterators out of range");
                        CHECK_THROWS_WITH(json(j.cbegin(), j.cbegin()), "iterators out of range");
                    }
                }
            }
        }
    }

    SECTION("create a JSON value from an input stream")
    {
        SECTION("std::stringstream")
        {
            std::stringstream ss;
            ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j(ss);
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }

        SECTION("with callback function")
        {
            std::stringstream ss;
            ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j(ss, [](int, json::parse_event_t, const json & val)
            {
                // filter all number(2) elements
                if (val == json(2))
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });
            CHECK(j == json({"foo", 1, 3, false, {{"one", 1}}}));
        }

        SECTION("std::ifstream")
        {
            std::ifstream f("test/data/json_tests/pass1.json");
            json j(f);
        }
    }
}
