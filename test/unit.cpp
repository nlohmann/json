/*!
@file
@copyright The code is licensed under the MIT License
           <http://opensource.org/licenses/MIT>,
           Copyright (c) 2013-2015 Niels Lohmann.
@author Niels Lohmann <http://nlohmann.me>
@see https://github.com/nlohmann/json
*/

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <array>
#include <deque>
#include <forward_list>
#include <list>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define private public
#include "json.hpp"
using nlohmann::json;

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
            json::object_t o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
        }
    }

    SECTION("create an object (implicit)")
    {
        // reference object
        json::object_t o_reference {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
        json j_reference(o_reference);

        SECTION("std::map<json::string_t, json>")
        {
            std::map<json::string_t, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::map<const char*, json>")
        {
            std::map<const char*, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            std::multimap<json::string_t, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            std::unordered_map<json::string_t, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            std::unordered_multimap<json::string_t, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("associative container literal")
        {
            json j({{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}});
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
            json::array_t a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
        }
    }

    SECTION("create an array (implicit)")
    {
        // reference array
        json::array_t a_reference {json(1), json(2.2), json(false), json("string"), json()};
        json j_reference(a_reference);

        SECTION("std::list<json>")
        {
            std::list<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::array<json, 5>")
        {
            std::array<json, 5> a {{json(1), json(2.2), json(false), json("string"), json()}};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::set<json>")
        {
            std::set<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            // we cannot really check for equality here
        }

        SECTION("std::unordered_set<json>")
        {
            std::unordered_set<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            // we cannot really check for equality here
        }

        SECTION("sequence container literal")
        {
            json j({json(1), json(2.2), json(false), json("string"), json()});
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
        // reference object
        json::number_integer_t n_reference = 42;
        json j_reference(n_reference);

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
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
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
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
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
            short n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
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
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
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
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint16_t")
        {
            uint16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint32_t")
        {
            uint32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint64_t")
        {
            uint64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_fast8_t")
        {
            uint_fast8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_fast16_t")
        {
            uint_fast16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_fast32_t")
        {
            uint_fast32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_fast64_t")
        {
            uint_fast64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_least8_t")
        {
            uint_least8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_least16_t")
        {
            uint_least16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_least32_t")
        {
            uint_least32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_least64_t")
        {
            uint_least64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
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
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
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
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
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
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
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
            float n = 42.23;
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
                std::initializer_list<json> l = {1, 42.23, true, nullptr, json::object_t(), json::array_t()};
                json j(l);
                CHECK(j.type() == json::value_t::array);
            }

            SECTION("implicit")
            {
                json j {1, 42.23, true, nullptr, json::object_t(), json::array_t()};
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("implicit type deduction")
        {
            SECTION("object")
            {
                json j { {"one", 1}, {"two", 2.2}, {"three", false} };
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("array")
            {
                json j { {"one", 1}, {"two", 2.2}, {"three", false}, 13 };
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
                json j = json::object({ {"one", 1}, {"two", 2.2}, {"three", false} });
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("object with error")
            {
                CHECK_THROWS_AS(json::object({ {"one", 1}, {"two", 2.2}, {"three", false}, 13 }), std::logic_error);
            }

            SECTION("empty array")
            {
                json j = json::array();
                CHECK(j.type() == json::value_t::array);
            }

            SECTION("array")
            {
                json j = json::array({ {"one", 1}, {"two", 2.2}, {"three", false} });
                CHECK(j.type() == json::value_t::array);
            }
        }
    }

    SECTION("create an array of n copies of a given value")
    {
        json v = {1, "foo", 34.23, {1, 2, 3}, {{"A", 1}, {"B", 2}}};
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
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                    json j_new(jobject.begin(), jobject.end());
                    CHECK(j_new == jobject);
                }
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                    json j_new(jobject.cbegin(), jobject.cend());
                    CHECK(j_new == jobject);
                }
            }

            SECTION("json(begin(), begin())")
            {
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                    json j_new(jobject.begin(), jobject.begin());
                    CHECK(j_new == json::object());
                }
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                    json j_new(jobject.cbegin(), jobject.cbegin());
                    CHECK(j_new == json::object());
                }
            }

            SECTION("construct from subrange")
            {
                json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}, {"d", false}, {"e", true}};
                json j_new(jobject.find("b"), jobject.find("e"));
                CHECK(j_new == json({{"b", 1}, {"c", 17}, {"d", false}}));
            }

            SECTION("incompatible iterators")
            {
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}, {"d", false}, {"e", true}};
                    json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17}};
                    CHECK_THROWS_AS(json(jobject.begin(), jobject2.end()), std::domain_error);
                    CHECK_THROWS_AS(json(jobject2.begin(), jobject.end()), std::domain_error);
                }
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}, {"d", false}, {"e", true}};
                    json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17}};
                    CHECK_THROWS_AS(json(jobject.cbegin(), jobject2.cend()), std::domain_error);
                    CHECK_THROWS_AS(json(jobject2.cbegin(), jobject.cend()), std::domain_error);
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
                }
                {
                    json jarray = {1, 2, 3, 4};
                    json jarray2 = {2, 3, 4, 5};
                    CHECK_THROWS_AS(json(jarray.cbegin(), jarray2.cend()), std::domain_error);
                    CHECK_THROWS_AS(json(jarray2.cbegin(), jarray.cend()), std::domain_error);
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
                    }
                    {
                        json j;
                        CHECK_THROWS_AS(json(j.cbegin(), j.cend()), std::domain_error);
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
                    }
                    {
                        json j = "bar";
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                    }
                }

                SECTION("number (boolean)")
                {
                    {
                        json j = false;
                        CHECK_THROWS_AS(json(j.end(), j.end()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), std::out_of_range);
                    }
                    {
                        json j = true;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17;
                        CHECK_THROWS_AS(json(j.end(), j.end()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), std::out_of_range);
                    }
                    {
                        json j = 17;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                    }
                }

                SECTION("number (floating point)")
                {
                    {
                        json j = 23.42;
                        CHECK_THROWS_AS(json(j.end(), j.end()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.begin(), j.begin()), std::out_of_range);
                    }
                    {
                        json j = 23.42;
                        CHECK_THROWS_AS(json(j.cend(), j.cend()), std::out_of_range);
                        CHECK_THROWS_AS(json(j.cbegin(), j.cbegin()), std::out_of_range);
                    }
                }
            }
        }
    }
}

TEST_CASE("other constructors and destructor")
{
    SECTION("copy constructor")
    {
        SECTION("object")
        {
            json j {{"foo", 1}, {"bar", false}};
            json k(j);
            CHECK(j == k);
        }

        SECTION("array")
        {
            json j {"foo", 1, 42.23, false};
            json k(j);
            CHECK(j == k);
        }

        SECTION("null")
        {
            json j(nullptr);
            json k(j);
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            json j(true);
            json k(j);
            CHECK(j == k);
        }

        SECTION("string")
        {
            json j("Hello world");
            json k(j);
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            json j(42);
            json k(j);
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            json j(42.23);
            json k(j);
            CHECK(j == k);
        }
    }

    SECTION("move constructor")
    {
        json j {{"foo", "bar"}, {"baz", {1, 2, 3, 4}}, {"a", 42.23}, {"b", nullptr}};
        CHECK(j.type() == json::value_t::object);
        json k(std::move(j));
        CHECK(k.type() == json::value_t::object);
        CHECK(j.type() == json::value_t::null);
    }

    SECTION("copy assignment")
    {
        SECTION("object")
        {
            json j {{"foo", 1}, {"bar", false}};
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("array")
        {
            json j {"foo", 1, 42.23, false};
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("null")
        {
            json j(nullptr);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            json j(true);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("string")
        {
            json j("Hello world");
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            json j(42);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            json j(42.23);
            json k;
            k = j;
            CHECK(j == k);
        }
    }

    SECTION("destructor")
    {
        SECTION("object")
        {
            auto j = new json {{"foo", 1}, {"bar", false}};
            delete j;
        }

        SECTION("array")
        {
            auto j = new json {"foo", 1, false, 23.42};
            delete j;
        }

        SECTION("string")
        {
            auto j = new json("Hello world");
            delete j;
        }
    }
}

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
            json j {"foo", 1, 42.23, false};
            CHECK(not j.is_null());
            CHECK(not j.is_boolean());
            CHECK(not j.is_number());
            CHECK(not j.is_number_integer());
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

        SECTION("number (floating-point)")
        {
            json j = 42.23;
            json::value_t t = j;
            CHECK(t == j.type());
        }
    }
}

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
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::object_t>(), std::logic_error);
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
        json::array_t a_reference {json(1), json(2.2), json(false), json("string"), json()};
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
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::array_t>(), std::logic_error);
        }
    }

    SECTION("get an array (implicit)")
    {
        json::array_t a_reference {json(1), json(2.2), json(false), json("string"), json()};
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
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::string_t>(), std::logic_error);
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
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::boolean_t>(), std::logic_error);
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

        SECTION("number_integer_t")
        {
            json::number_integer_t n = j.get<json::number_integer_t>();
            CHECK(json(n) == j);
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
            CHECK_NOTHROW(json(json::value_t::number_float).get<json::number_integer_t>());
        }
    }

    SECTION("get an integer number (implicit)")
    {
        json::number_integer_t n_reference {42};
        json j(n_reference);

        SECTION("number_integer_t")
        {
            json::number_integer_t n = j.get<json::number_integer_t>();
            CHECK(json(n) == j);
        }

        SECTION("short")
        {
            short n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned short")
        {
            unsigned short n = j;
            CHECK(json(n) == j);
        }

        SECTION("int")
        {
            int n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned int")
        {
            unsigned int n = j;
            CHECK(json(n) == j);
        }

        SECTION("long")
        {
            long n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned long")
        {
            unsigned long n = j;
            CHECK(json(n) == j);
        }

        SECTION("long long")
        {
            long long n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned long long")
        {
            unsigned long long n = j;
            CHECK(json(n) == j);
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
            uint8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint16_t")
        {
            uint16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint32_t")
        {
            uint32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint64_t")
        {
            uint64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint8_fast_t")
        {
            uint_fast8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint16_fast_t")
        {
            uint_fast16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint32_fast_t")
        {
            uint_fast32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint64_fast_t")
        {
            uint_fast64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint8_least_t")
        {
            uint_least8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint16_least_t")
        {
            uint_least16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint32_least_t")
        {
            uint_least32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint64_least_t")
        {
            uint_least64_t n = j;
            CHECK(json(n) == j);
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
            CHECK_NOTHROW(json(json::value_t::number_integer).get<json::number_float_t>());
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
            json j2 = {{"one", 1.1}, {"two", 2.2}, {"three", 3.3}};
            json j3 = {{"one", true}, {"two", false}, {"three", true}};
            json j4 = {{"one", "eins"}, {"two", "zwei"}, {"three", "drei"}};

            SECTION("std::map")
            {
                auto m1 = j1.get<std::map<std::string, int>>();
                auto m2 = j2.get<std::map<std::string, double>>();
                auto m3 = j3.get<std::map<std::string, bool>>();
                //auto m4 = j4.get<std::map<std::string, std::string>>();
            }

            SECTION("std::unordered_map")
            {
                auto m1 = j1.get<std::unordered_map<std::string, int>>();
                auto m2 = j2.get<std::unordered_map<std::string, double>>();
                auto m3 = j3.get<std::unordered_map<std::string, bool>>();
                //auto m4 = j4.get<std::unordered_map<std::string, std::string>>();
                //CHECK(m4["one"] == "eins");
            }

            SECTION("std::multimap")
            {
                auto m1 = j1.get<std::multimap<std::string, int>>();
                auto m2 = j2.get<std::multimap<std::string, double>>();
                auto m3 = j3.get<std::multimap<std::string, bool>>();
                //auto m4 = j4.get<std::multimap<std::string, std::string>>();
                //CHECK(m4["one"] == "eins");
            }

            SECTION("std::unordered_multimap")
            {
                auto m1 = j1.get<std::unordered_multimap<std::string, int>>();
                auto m2 = j2.get<std::unordered_multimap<std::string, double>>();
                auto m3 = j3.get<std::unordered_multimap<std::string, bool>>();
                //auto m4 = j4.get<std::unordered_multimap<std::string, std::string>>();
                //CHECK(m4["one"] == "eins");
            }

            SECTION("exception in case of a non-object type")
            {
                CHECK_THROWS_AS((json().get<std::map<std::string, int>>()), std::logic_error);
            }
        }

        SECTION("array-like STL containers")
        {
            json j1 = {1, 2, 3, 4};
            json j2 = {1.2, 2.3, 3.4, 4.5};
            json j3 = {true, false, true};
            json j4 = {"one", "two", "three"};

            SECTION("std::list")
            {
                auto m1 = j1.get<std::list<int>>();
                auto m2 = j2.get<std::list<double>>();
                auto m3 = j3.get<std::list<bool>>();
                auto m4 = j4.get<std::list<std::string>>();
            }

            //SECTION("std::forward_list")
            //{
            //    auto m1 = j1.get<std::forward_list<int>>();
            //    auto m2 = j2.get<std::forward_list<double>>();
            //    auto m3 = j3.get<std::forward_list<bool>>();
            //    auto m4 = j4.get<std::forward_list<std::string>>();
            //}

            SECTION("std::vector")
            {
                auto m1 = j1.get<std::vector<int>>();
                auto m2 = j2.get<std::vector<double>>();
                auto m3 = j3.get<std::vector<bool>>();
                auto m4 = j4.get<std::vector<std::string>>();
            }

            SECTION("std::deque")
            {
                auto m1 = j1.get<std::deque<int>>();
                auto m2 = j2.get<std::deque<double>>();
                auto m3 = j3.get<std::deque<bool>>();
                auto m4 = j4.get<std::deque<std::string>>();
            }

            SECTION("std::set")
            {
                auto m1 = j1.get<std::set<int>>();
                auto m2 = j2.get<std::set<double>>();
                auto m3 = j3.get<std::set<bool>>();
                auto m4 = j4.get<std::set<std::string>>();
            }

            SECTION("std::unordered_set")
            {
                auto m1 = j1.get<std::unordered_set<int>>();
                auto m2 = j2.get<std::unordered_set<double>>();
                auto m3 = j3.get<std::unordered_set<bool>>();
                auto m4 = j4.get<std::unordered_set<std::string>>();
            }

            SECTION("exception in case of a non-object type")
            {
                CHECK_THROWS_AS((json().get<std::list<int>>()), std::logic_error);
                CHECK_THROWS_AS((json().get<std::vector<int>>()), std::logic_error);
                CHECK_THROWS_AS((json().get<std::vector<json>>()), std::logic_error);
                CHECK_THROWS_AS((json().get<std::list<json>>()), std::logic_error);
            }
        }
    }
}

TEST_CASE("pointer access")
{
    // create a JSON value with different types
    json json_types =
    {
        {"boolean", true},
        {
            "number", {
                {"integer", 42},
                {"floating-point", 17.23}
            }
        },
        {"string", "Hello, world!"},
        {"array", {1, 2, 3, 4, 5}},
        {"null", nullptr}
    };

    SECTION("pointer access to object_t")
    {
        using test_type = json::object_t;
        json value = {{"one", 1}, {"two", 2}};

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() != nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to array_t")
    {
        using test_type = json::array_t;
        json value = {1, 2, 3, 4};

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() != nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to string_t")
    {
        using test_type = json::string_t;
        json value = "hello";

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() != nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to boolean_t")
    {
        using test_type = json::boolean_t;
        json value = false;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to number_integer_t")
    {
        using test_type = json::number_integer_t;
        json value = 23;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to number_float_t")
    {
        using test_type = json::number_float_t;
        json value = 42.23;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == Approx(value.get<test_type>()));

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == Approx(value.get<test_type>()));

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == Approx(value.get<test_type>()));

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() != nullptr);
    }
}

TEST_CASE("element access")
{
    SECTION("array")
    {
        json j = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
        const json j_const = j;

        SECTION("access specified element with bounds checking")
        {
            SECTION("access within bounds")
            {
                CHECK(j.at(0) == json(1));
                CHECK(j.at(1) == json(true));
                CHECK(j.at(2) == json(nullptr));
                CHECK(j.at(3) == json("string"));
                CHECK(j.at(4) == json(42.23));
                CHECK(j.at(5) == json(json::object()));
                CHECK(j.at(6) == json({1, 2, 3}));

                CHECK(j_const.at(0) == json(1));
                CHECK(j_const.at(1) == json(true));
                CHECK(j_const.at(2) == json(nullptr));
                CHECK(j_const.at(3) == json("string"));
                CHECK(j_const.at(4) == json(42.23));
                CHECK(j_const.at(5) == json(json::object()));
                CHECK(j_const.at(6) == json({1, 2, 3}));
            }

            SECTION("access outside bounds")
            {
                CHECK_THROWS_AS(j.at(7), std::out_of_range);
                CHECK_THROWS_AS(j_const.at(7), std::out_of_range);
            }

            SECTION("access on non-array type")
            {
                SECTION("null")
                {
                    json j_nonarray(json::value_t::null);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);
                }
            }
        }

        SECTION("front and back")
        {
            CHECK(j.front() == json(1));
            CHECK(j_const.front() == json(1));
            CHECK(j.back() == json({1, 2, 3}));
            CHECK(j_const.back() == json({1, 2, 3}));
        }

        SECTION("access specified element")
        {
            SECTION("access within bounds")
            {
                CHECK(j[0] == json(1));
                CHECK(j[1] == json(true));
                CHECK(j[2] == json(nullptr));
                CHECK(j[3] == json("string"));
                CHECK(j[4] == json(42.23));
                CHECK(j[5] == json(json::object()));
                CHECK(j[6] == json({1, 2, 3}));

                CHECK(j_const[0] == json(1));
                CHECK(j_const[1] == json(true));
                CHECK(j_const[2] == json(nullptr));
                CHECK(j_const[3] == json("string"));
                CHECK(j_const[4] == json(42.23));
                CHECK(j_const[5] == json(json::object()));
                CHECK(j_const[6] == json({1, 2, 3}));
            }

            SECTION("access on non-array type")
            {
                SECTION("null")
                {
                    SECTION("standard tests")
                    {
                        json j_nonarray(json::value_t::null);
                        const json j_nonarray_const(j_nonarray);
                        CHECK_NOTHROW(j_nonarray[0]);
                        CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                    }

                    SECTION("implicit transformation to properly filled array")
                    {
                        json j_nonarray;
                        j_nonarray[3] = 42;
                        CHECK(j_nonarray == json({nullptr, nullptr, nullptr, 42}));
                    }
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                }
            }
        }

        SECTION("remove specified element")
        {
            SECTION("remove element by index")
            {
                {
                    json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(0);
                    CHECK(jarray == json({true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(1);
                    CHECK(jarray == json({1, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(2);
                    CHECK(jarray == json({1, true, "string", 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(3);
                    CHECK(jarray == json({1, true, nullptr, 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(4);
                    CHECK(jarray == json({1, true, nullptr, "string", json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(5);
                    CHECK(jarray == json({1, true, nullptr, "string", 42.23, {1, 2, 3}}));
                }
                {
                    json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(6);
                    CHECK(jarray == json({1, true, nullptr, "string", 42.23, json::object()}));
                }
                {
                    json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    CHECK_THROWS_AS(jarray.erase(7), std::out_of_range);
                }
            }

            SECTION("remove element by iterator")
            {
                SECTION("erase(begin())")
                {
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it2 = jarray.erase(jarray.begin());
                        CHECK(jarray == json({true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(true));
                    }
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it2 = jarray.erase(jarray.cbegin());
                        CHECK(jarray == json({true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(true));
                    }
                }

                SECTION("erase(begin(), end())")
                {
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it2 = jarray.erase(jarray.begin(), jarray.end());
                        CHECK(jarray == json::array());
                        CHECK(it2 == jarray.end());
                    }
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it2 = jarray.erase(jarray.cbegin(), jarray.cend());
                        CHECK(jarray == json::array());
                        CHECK(it2 == jarray.cend());
                    }
                }

                SECTION("erase(begin(), begin())")
                {
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it2 = jarray.erase(jarray.begin(), jarray.begin());
                        CHECK(jarray == json({1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(1));
                    }
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it2 = jarray.erase(jarray.cbegin(), jarray.cbegin());
                        CHECK(jarray == json({1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(1));
                    }
                }

                SECTION("erase at offset")
                {
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it = jarray.begin() + 3;
                        json::iterator it2 = jarray.erase(it);
                        CHECK(jarray == json({1, true, nullptr, 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(42.23));
                    }
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it = jarray.cbegin() + 3;
                        json::const_iterator it2 = jarray.erase(it);
                        CHECK(jarray == json({1, true, nullptr, 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(42.23));
                    }
                }

                SECTION("erase subrange")
                {
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it2 = jarray.erase(jarray.begin() + 2, jarray.begin() + 5);
                        CHECK(jarray == json({1, true, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json::object());
                    }
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it2 = jarray.erase(jarray.cbegin() + 2, jarray.cbegin() + 5);
                        CHECK(jarray == json({1, true, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json::object());
                    }
                }

                SECTION("different arrays")
                {
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json jarray2 = {"foo", "bar"};
                        CHECK_THROWS_AS(jarray.erase(jarray2.begin()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray.begin(), jarray2.end()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray2.begin(), jarray.end()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray2.begin(), jarray2.end()), std::domain_error);
                    }
                    {
                        json jarray = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json jarray2 = {"foo", "bar"};
                        CHECK_THROWS_AS(jarray.erase(jarray2.cbegin()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray.cbegin(), jarray2.cend()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray2.cbegin(), jarray.cend()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray2.cbegin(), jarray2.cend()), std::domain_error);
                    }
                }
            }

            SECTION("remove element by index in non-array type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                }

                SECTION("object")
                {
                    json j_nonobject(json::value_t::object);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                }
            }
        }
    }

    SECTION("object")
    {
        json j = {{"integer", 1}, {"floating", 42.23}, {"null", nullptr}, {"string", "hello world"}, {"boolean", true}, {"object", json::object()}, {"array", {1, 2, 3}}};
        const json j_const = j;

        SECTION("access specified element with bounds checking")
        {
            SECTION("access within bounds")
            {
                CHECK(j.at("integer") == json(1));
                CHECK(j.at("boolean") == json(true));
                CHECK(j.at("null") == json(nullptr));
                CHECK(j.at("string") == json("hello world"));
                CHECK(j.at("floating") == json(42.23));
                CHECK(j.at("object") == json(json::object()));
                CHECK(j.at("array") == json({1, 2, 3}));

                CHECK(j_const.at("integer") == json(1));
                CHECK(j_const.at("boolean") == json(true));
                CHECK(j_const.at("null") == json(nullptr));
                CHECK(j_const.at("string") == json("hello world"));
                CHECK(j_const.at("floating") == json(42.23));
                CHECK(j_const.at("object") == json(json::object()));
                CHECK(j_const.at("array") == json({1, 2, 3}));
            }

            SECTION("access outside bounds")
            {
                CHECK_THROWS_AS(j.at("foo"), std::out_of_range);
                CHECK_THROWS_AS(j_const.at("foo"), std::out_of_range);
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                }
            }
        }

        SECTION("front and back")
        {
            // "array" is the smallest key
            CHECK(j.front() == json({1, 2, 3}));
            CHECK(j_const.front() == json({1, 2, 3}));
            // "string" is the largest key
            CHECK(j.back() == json("hello world"));
            CHECK(j_const.back() == json("hello world"));
        }

        SECTION("access specified element")
        {
            SECTION("access within bounds")
            {
                CHECK(j["integer"] == json(1));
                CHECK(j[json::object_t::key_type("integer")] == j["integer"]);
                CHECK(j_const["integer"] == json(1));
                CHECK(j_const[json::object_t::key_type("integer")] == j["integer"]);

                CHECK(j["boolean"] == json(true));
                CHECK(j[json::object_t::key_type("boolean")] == j["boolean"]);
                CHECK(j_const["boolean"] == json(true));
                CHECK(j_const[json::object_t::key_type("boolean")] == j["boolean"]);

                CHECK(j["null"] == json(nullptr));
                CHECK(j[json::object_t::key_type("null")] == j["null"]);
                CHECK(j_const["null"] == json(nullptr));
                CHECK(j_const[json::object_t::key_type("null")] == j["null"]);

                CHECK(j["string"] == json("hello world"));
                CHECK(j[json::object_t::key_type("string")] == j["string"]);
                CHECK(j_const["string"] == json("hello world"));
                CHECK(j_const[json::object_t::key_type("string")] == j["string"]);

                CHECK(j["floating"] == json(42.23));
                CHECK(j[json::object_t::key_type("floating")] == j["floating"]);
                CHECK(j_const["floating"] == json(42.23));
                CHECK(j_const[json::object_t::key_type("floating")] == j["floating"]);

                CHECK(j["object"] == json(json::object()));
                CHECK(j[json::object_t::key_type("object")] == j["object"]);
                CHECK(j_const["object"] == json(json::object()));
                CHECK(j_const[json::object_t::key_type("object")] == j["object"]);

                CHECK(j["array"] == json({1, 2, 3}));
                CHECK(j[json::object_t::key_type("array")] == j["array"]);
                CHECK(j_const["array"] == json({1, 2, 3}));
                CHECK(j_const[json::object_t::key_type("array")] == j["array"]);
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    json j_nonobject2(json::value_t::null);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_NOTHROW(j_nonobject["foo"]);
                    CHECK_NOTHROW(j_nonobject2[json::object_t::key_type("foo")]);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                }
            }
        }

        SECTION("remove specified element")
        {
            SECTION("remove element by key")
            {
                CHECK(j.find("integer") != j.end());
                CHECK(j.erase("integer") == 1);
                CHECK(j.find("integer") == j.end());
                CHECK(j.erase("integer") == 0);

                CHECK(j.find("boolean") != j.end());
                CHECK(j.erase("boolean") == 1);
                CHECK(j.find("boolean") == j.end());
                CHECK(j.erase("boolean") == 0);

                CHECK(j.find("null") != j.end());
                CHECK(j.erase("null") == 1);
                CHECK(j.find("null") == j.end());
                CHECK(j.erase("null") == 0);

                CHECK(j.find("string") != j.end());
                CHECK(j.erase("string") == 1);
                CHECK(j.find("string") == j.end());
                CHECK(j.erase("string") == 0);

                CHECK(j.find("floating") != j.end());
                CHECK(j.erase("floating") == 1);
                CHECK(j.find("floating") == j.end());
                CHECK(j.erase("floating") == 0);

                CHECK(j.find("object") != j.end());
                CHECK(j.erase("object") == 1);
                CHECK(j.find("object") == j.end());
                CHECK(j.erase("object") == 0);

                CHECK(j.find("array") != j.end());
                CHECK(j.erase("array") == 1);
                CHECK(j.find("array") == j.end());
                CHECK(j.erase("array") == 0);
            }

            SECTION("remove element by iterator")
            {
                SECTION("erase(begin())")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        json::iterator it2 = jobject.erase(jobject.begin());
                        CHECK(jobject == json({{"b", 1}, {"c", 17}}));
                        CHECK(*it2 == json(1));
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        json::const_iterator it2 = jobject.erase(jobject.cbegin());
                        CHECK(jobject == json({{"b", 1}, {"c", 17}}));
                        CHECK(*it2 == json(1));
                    }
                }

                SECTION("erase(begin(), end())")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        json::iterator it2 = jobject.erase(jobject.begin(), jobject.end());
                        CHECK(jobject == json::object());
                        CHECK(it2 == jobject.end());
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        json::const_iterator it2 = jobject.erase(jobject.cbegin(), jobject.cend());
                        CHECK(jobject == json::object());
                        CHECK(it2 == jobject.cend());
                    }
                }

                SECTION("erase(begin(), begin())")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        json::iterator it2 = jobject.erase(jobject.begin(), jobject.begin());
                        CHECK(jobject == json({{"a", "a"}, {"b", 1}, {"c", 17}}));
                        CHECK(*it2 == json("a"));
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        json::const_iterator it2 = jobject.erase(jobject.cbegin(), jobject.cbegin());
                        CHECK(jobject == json({{"a", "a"}, {"b", 1}, {"c", 17}}));
                        CHECK(*it2 == json("a"));
                    }
                }

                SECTION("erase at offset")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        json::iterator it = jobject.find("b");
                        json::iterator it2 = jobject.erase(it);
                        CHECK(jobject == json({{"a", "a"}, {"c", 17}}));
                        CHECK(*it2 == json(17));
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        json::const_iterator it = jobject.find("b");
                        json::const_iterator it2 = jobject.erase(it);
                        CHECK(jobject == json({{"a", "a"}, {"c", 17}}));
                        CHECK(*it2 == json(17));
                    }
                }

                SECTION("erase subrange")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}, {"d", false}, {"e", true}};
                        json::iterator it2 = jobject.erase(jobject.find("b"), jobject.find("e"));
                        CHECK(jobject == json({{"a", "a"}, {"e", true}}));
                        CHECK(*it2 == json(true));
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}, {"d", false}, {"e", true}};
                        json::const_iterator it2 = jobject.erase(jobject.find("b"), jobject.find("e"));
                        CHECK(jobject == json({{"a", "a"}, {"e", true}}));
                        CHECK(*it2 == json(true));
                    }
                }

                SECTION("different objects")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}, {"d", false}, {"e", true}};
                        json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject.begin(), jobject2.end()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin(), jobject.end()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin(), jobject2.end()), std::domain_error);
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17}, {"d", false}, {"e", true}};
                        json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17}};
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject.cbegin(), jobject2.cend()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin(), jobject.cend()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin(), jobject2.cend()), std::domain_error);
                    }
                }
            }

            SECTION("remove element by key in non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                }
            }
        }

        SECTION("find an element in an object")
        {
            SECTION("existing element")
            {
                for (auto key :
                        {"integer", "floating", "null", "string", "boolean", "object", "array"
                        })
                {
                    CHECK(j.find(key) != j.end());
                    CHECK(*j.find(key) == j.at(key));
                    CHECK(j_const.find(key) != j_const.end());
                    CHECK(*j_const.find(key) == j_const.at(key));
                }
            }

            SECTION("nonexisting element")
            {
                CHECK(j.find("foo") == j.end());
                CHECK(j_const.find("foo") == j_const.end());
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    json j_nonarray(json::value_t::null);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("array")
                {
                    json j_nonarray(json::value_t::array);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }
            }
        }

        SECTION("count keys in an object")
        {
            SECTION("existing element")
            {
                for (auto key :
                        {"integer", "floating", "null", "string", "boolean", "object", "array"
                        })
                {
                    CHECK(j.count(key) == 1);
                    CHECK(j_const.count(key) == 1);
                }
            }

            SECTION("nonexisting element")
            {
                CHECK(j.count("foo") == 0);
                CHECK(j_const.count("foo") == 0);
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("object")
                {
                    json j_nonobject(json::value_t::object);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }
            }
        }
    }

    SECTION("other values")
    {
        SECTION("front and back")
        {
            SECTION("null")
            {
                {
                    json j;
                    CHECK_THROWS_AS(j.front(), std::out_of_range);
                    CHECK_THROWS_AS(j.back(), std::out_of_range);
                }
                {
                    const json j{};
                    CHECK_THROWS_AS(j.front(), std::out_of_range);
                    CHECK_THROWS_AS(j.back(), std::out_of_range);
                }
            }

            SECTION("string")
            {
                {
                    json j = "foo";
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = "bar";
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = true;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = 17;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = 23.42;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }
        }

        SECTION("erase with one valid iterator")
        {
            SECTION("null")
            {
                {
                    json j;
                    CHECK_THROWS_AS(j.erase(j.begin()), std::domain_error);
                }
                {
                    json j;
                    CHECK_THROWS_AS(j.erase(j.cbegin()), std::domain_error);
                }
            }

            SECTION("string")
            {
                {
                    json j = "foo";
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = "bar";
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = true;
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 17;
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 23.42;
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }
        }

        SECTION("erase with one invalid iterator")
        {
            SECTION("string")
            {
                {
                    json j = "foo";
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                }
                {
                    json j = "bar";
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                }
                {
                    json j = true;
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                }
                {
                    json j = 17;
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                }
                {
                    json j = 23.42;
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                }
            }
        }

        SECTION("erase with two valid iterators")
        {
            SECTION("null")
            {
                {
                    json j;
                    CHECK_THROWS_AS(j.erase(j.begin(), j.end()), std::domain_error);
                }
                {
                    json j;
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cend()), std::domain_error);
                }
            }

            SECTION("string")
            {
                {
                    json j = "foo";
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = "bar";
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = true;
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 17;
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 23.42;
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }
        }

        SECTION("erase with two invalid iterators")
        {
            SECTION("string")
            {
                {
                    json j = "foo";
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                }
                {
                    json j = "bar";
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                }
                {
                    json j = true;
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                }
                {
                    json j = 17;
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                }
                {
                    json j = 23.42;
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                }
            }
        }
    }
}

TEST_CASE("iterators")
{
    SECTION("basic behavior")
    {
        SECTION("uninitialized")
        {
            json::iterator it;
            CHECK(it.m_object == nullptr);

            json::const_iterator cit;
            CHECK(cit.m_object == nullptr);
        }

        SECTION("boolean")
        {
            json j = true;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_AS(it.key(), std::domain_error);
                CHECK(it.value() == json(true));
                CHECK_THROWS_AS(cit.key(), std::domain_error);
                CHECK(cit.value() == json(true));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_AS(rit.key(), std::domain_error);
                CHECK_THROWS_AS(rit.value(), std::out_of_range);
                CHECK_THROWS_AS(crit.key(), std::domain_error);
                CHECK_THROWS_AS(crit.value(), std::out_of_range);
            }
        }

        SECTION("string")
        {
            json j = "hello world";
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_AS(it.key(), std::domain_error);
                CHECK(it.value() == json("hello world"));
                CHECK_THROWS_AS(cit.key(), std::domain_error);
                CHECK(cit.value() == json("hello world"));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_AS(rit.key(), std::domain_error);
                CHECK_THROWS_AS(rit.value(), std::out_of_range);
                CHECK_THROWS_AS(crit.key(), std::domain_error);
                CHECK_THROWS_AS(crit.value(), std::out_of_range);
            }
        }

        SECTION("array")
        {
            json j = {1, 2, 3};
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it_begin = j.begin();
                json::iterator it_end = j.end();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it_begin = j_const.begin();
                json::const_iterator it_end = j_const.end();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j_const[0]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const[2]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it_begin = j.cbegin();
                json::const_iterator it_end = j.cend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it_begin = j_const.cbegin();
                json::const_iterator it_end = j_const.cend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it_begin = j.rbegin();
                json::reverse_iterator it_end = j.rend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it_begin = j.crbegin();
                json::const_reverse_iterator it_end = j.crend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it_begin = j_const.crbegin();
                json::const_reverse_iterator it_end = j_const.crend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_AS(it.key(), std::domain_error);
                CHECK(it.value() == json(1));
                CHECK_THROWS_AS(cit.key(), std::domain_error);
                CHECK(cit.value() == json(1));
            }
        }

        SECTION("object")
        {
            json j = {{"A", 1}, {"B", 2}, {"C", 3}};
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it_begin = j.begin();
                json::iterator it_end = j.end();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it_begin = j_const.begin();
                json::const_iterator it_end = j_const.end();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j_const["A"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const["C"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it_begin = j.cbegin();
                json::const_iterator it_end = j.cend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it_begin = j_const.cbegin();
                json::const_iterator it_end = j_const.cend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j_const["A"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const["C"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it_begin = j.rbegin();
                json::reverse_iterator it_end = j.rend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it_begin = j.crbegin();
                json::const_reverse_iterator it_end = j.crend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it_begin = j_const.crbegin();
                json::const_reverse_iterator it_end = j_const.crend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK(it.key() == "A");
                CHECK(it.value() == json(1));
                CHECK(cit.key() == "A");
                CHECK(cit.value() == json(1));
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_AS(it.key(), std::domain_error);
                CHECK(it.value() == json(23));
                CHECK_THROWS_AS(cit.key(), std::domain_error);
                CHECK(cit.value() == json(23));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_AS(rit.key(), std::domain_error);
                CHECK_THROWS_AS(rit.value(), std::out_of_range);
                CHECK_THROWS_AS(crit.key(), std::domain_error);
                CHECK_THROWS_AS(crit.value(), std::out_of_range);
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_AS(it.key(), std::domain_error);
                CHECK(it.value() == json(23.42));
                CHECK_THROWS_AS(cit.key(), std::domain_error);
                CHECK(cit.value() == json(23.42));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_AS(rit.key(), std::domain_error);
                CHECK_THROWS_AS(rit.value(), std::out_of_range);
                CHECK_THROWS_AS(crit.key(), std::domain_error);
                CHECK_THROWS_AS(crit.value(), std::out_of_range);
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it == j.end());
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it_begin = j_const.begin();
                json::const_iterator it_end = j_const.end();
                CHECK(it_begin == it_end);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it_begin = j.cbegin();
                json::const_iterator it_end = j.cend();
                CHECK(it_begin == it_end);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it_begin = j_const.cbegin();
                json::const_iterator it_end = j_const.cend();
                CHECK(it_begin == it_end);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it == j.rend());
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it == j.crend());
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it == j_const.crend());
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_AS(it.key(), std::domain_error);
                CHECK_THROWS_AS(it.value(), std::out_of_range);
                CHECK_THROWS_AS(cit.key(), std::domain_error);
                CHECK_THROWS_AS(cit.value(), std::out_of_range);

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_AS(rit.key(), std::domain_error);
                CHECK_THROWS_AS(rit.value(), std::out_of_range);
                CHECK_THROWS_AS(crit.key(), std::domain_error);
                CHECK_THROWS_AS(crit.value(), std::out_of_range);
            }
        }
    }

    SECTION("iterator comparisons")
    {
        json j_values = {nullptr, true, 42, 23.23, {{"one", 1}, {"two", 2}}, {1, 2, 3, 4, 5}, "Hello, world"};

        for (json& j : j_values)
        {
            auto it1 = j.begin();
            auto it2 = j.begin();
            auto it3 = j.begin();
            ++it2;
            ++it3;
            ++it3;
            auto it1_c = j.cbegin();
            auto it2_c = j.cbegin();
            auto it3_c = j.cbegin();
            ++it2_c;
            ++it3_c;
            ++it3_c;

            // comparison: equal
            {
                CHECK(it1 == it1);
                CHECK(not (it1 == it2));
                CHECK(not (it1 == it3));
                CHECK(not (it2 == it3));
                CHECK(it1_c == it1_c);
                CHECK(not (it1_c == it2_c));
                CHECK(not (it1_c == it3_c));
                CHECK(not (it2_c == it3_c));
            }

            // comparison: not equal
            {
                // check definition
                CHECK( (it1 != it1) == not(it1 == it1) );
                CHECK( (it1 != it2) == not(it1 == it2) );
                CHECK( (it1 != it3) == not(it1 == it3) );
                CHECK( (it2 != it3) == not(it2 == it3) );
                CHECK( (it1_c != it1_c) == not(it1_c == it1_c) );
                CHECK( (it1_c != it2_c) == not(it1_c == it2_c) );
                CHECK( (it1_c != it3_c) == not(it1_c == it3_c) );
                CHECK( (it2_c != it3_c) == not(it2_c == it3_c) );
            }

            // comparison: smaller
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 < it1, std::domain_error);
                    CHECK_THROWS_AS(it1 < it2, std::domain_error);
                    CHECK_THROWS_AS(it2 < it3, std::domain_error);
                    CHECK_THROWS_AS(it1 < it3, std::domain_error);
                    CHECK_THROWS_AS(it1_c < it1_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c < it2_c, std::domain_error);
                    CHECK_THROWS_AS(it2_c < it3_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c < it3_c, std::domain_error);
                }
                else
                {
                    CHECK(not (it1 < it1));
                    CHECK(it1 < it2);
                    CHECK(it1 < it3);
                    CHECK(it2 < it3);
                    CHECK(not (it1_c < it1_c));
                    CHECK(it1_c < it2_c);
                    CHECK(it1_c < it3_c);
                    CHECK(it2_c < it3_c);
                }
            }

            // comparison: less than or equal
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 <= it1, std::domain_error);
                    CHECK_THROWS_AS(it1 <= it2, std::domain_error);
                    CHECK_THROWS_AS(it2 <= it3, std::domain_error);
                    CHECK_THROWS_AS(it1 <= it3, std::domain_error);
                    CHECK_THROWS_AS(it1_c <= it1_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c <= it2_c, std::domain_error);
                    CHECK_THROWS_AS(it2_c <= it3_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c <= it3_c, std::domain_error);
                }
                else
                {
                    // check definition
                    CHECK( (it1 <= it1) == not(it1 < it1) );
                    CHECK( (it1 <= it2) == not(it2 < it1) );
                    CHECK( (it1 <= it3) == not(it3 < it1) );
                    CHECK( (it2 <= it3) == not(it3 < it2) );
                    CHECK( (it1_c <= it1_c) == not(it1_c < it1_c) );
                    CHECK( (it1_c <= it2_c) == not(it2_c < it1_c) );
                    CHECK( (it1_c <= it3_c) == not(it3_c < it1_c) );
                    CHECK( (it2_c <= it3_c) == not(it3_c < it2_c) );
                }
            }

            // comparison: greater than
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 > it1, std::domain_error);
                    CHECK_THROWS_AS(it1 > it2, std::domain_error);
                    CHECK_THROWS_AS(it2 > it3, std::domain_error);
                    CHECK_THROWS_AS(it1 > it3, std::domain_error);
                    CHECK_THROWS_AS(it1_c > it1_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c > it2_c, std::domain_error);
                    CHECK_THROWS_AS(it2_c > it3_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c > it3_c, std::domain_error);
                }
                else
                {
                    // check definition
                    CHECK( (it1 > it1) == (it1 < it1) );
                    CHECK( (it1 > it2) == (it2 < it1) );
                    CHECK( (it1 > it3) == (it3 < it1) );
                    CHECK( (it2 > it3) == (it3 < it2) );
                    CHECK( (it1_c > it1_c) == (it1_c < it1_c) );
                    CHECK( (it1_c > it2_c) == (it2_c < it1_c) );
                    CHECK( (it1_c > it3_c) == (it3_c < it1_c) );
                    CHECK( (it2_c > it3_c) == (it3_c < it2_c) );
                }
            }

            // comparison: greater than or equal
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 >= it1, std::domain_error);
                    CHECK_THROWS_AS(it1 >= it2, std::domain_error);
                    CHECK_THROWS_AS(it2 >= it3, std::domain_error);
                    CHECK_THROWS_AS(it1 >= it3, std::domain_error);
                    CHECK_THROWS_AS(it1_c >= it1_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c >= it2_c, std::domain_error);
                    CHECK_THROWS_AS(it2_c >= it3_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c >= it3_c, std::domain_error);
                }
                else
                {
                    // check definition
                    CHECK( (it1 >= it1) == not(it1 < it1) );
                    CHECK( (it1 >= it2) == not(it1 < it2) );
                    CHECK( (it1 >= it3) == not(it1 < it3) );
                    CHECK( (it2 >= it3) == not(it2 < it3) );
                    CHECK( (it1_c >= it1_c) == not(it1_c < it1_c) );
                    CHECK( (it1_c >= it2_c) == not(it1_c < it2_c) );
                    CHECK( (it1_c >= it3_c) == not(it1_c < it3_c) );
                    CHECK( (it2_c >= it3_c) == not(it2_c < it3_c) );
                }
            }
        }

        // check exceptions if different objects are compared
        for (auto j : j_values)
        {
            for (auto k : j_values)
            {
                if (j != k)
                {
                    CHECK_THROWS_AS(j.begin() == k.begin(), std::domain_error);
                    CHECK_THROWS_AS(j.cbegin() == k.cbegin(), std::domain_error);

                    CHECK_THROWS_AS(j.begin() < k.begin(), std::domain_error);
                    CHECK_THROWS_AS(j.cbegin() < k.cbegin(), std::domain_error);
                }
            }
        }
    }

    SECTION("iterator arithmetic")
    {
        json j_object = {{"one", 1}, {"two", 2}, {"three", 3}};
        json j_array = {1, 2, 3, 4, 5, 6};
        json j_null = nullptr;
        json j_value = 42;

        SECTION("addition and subtraction")
        {
            SECTION("object")
            {
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it += 1, std::domain_error);
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it += 1, std::domain_error);
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it + 1, std::domain_error);
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it + 1, std::domain_error);
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it -= 1, std::domain_error);
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it -= 1, std::domain_error);
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it - 1, std::domain_error);
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it - 1, std::domain_error);
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it - it, std::domain_error);
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it - it, std::domain_error);
                }
            }

            SECTION("array")
            {
                {
                    auto it = j_array.begin();
                    it += 3;
                    CHECK((j_array.begin() + 3) == it);
                    CHECK((it - 3) == j_array.begin());
                    CHECK((it - j_array.begin()) == 3);
                    CHECK(*it == json(4));
                    it -= 2;
                    CHECK(*it == json(2));
                }
                {
                    auto it = j_array.cbegin();
                    it += 3;
                    CHECK((j_array.cbegin() + 3) == it);
                    CHECK((it - 3) == j_array.cbegin());
                    CHECK((it - j_array.cbegin()) == 3);
                    CHECK(*it == json(4));
                    it -= 2;
                    CHECK(*it == json(2));
                }
            }

            SECTION("null")
            {
                {
                    auto it = j_null.begin();
                    it += 3;
                    CHECK((j_null.begin() + 3) == it);
                    CHECK((it - 3) == j_null.begin());
                    CHECK((it - j_null.begin()) == 3);
                    CHECK(it != j_null.end());
                    it -= 3;
                    CHECK(it == j_null.end());
                }
                {
                    auto it = j_null.cbegin();
                    it += 3;
                    CHECK((j_null.cbegin() + 3) == it);
                    CHECK((it - 3) == j_null.cbegin());
                    CHECK((it - j_null.cbegin()) == 3);
                    CHECK(it != j_null.cend());
                    it -= 3;
                    CHECK(it == j_null.cend());
                }
            }

            SECTION("value")
            {
                {
                    auto it = j_value.begin();
                    it += 3;
                    CHECK((j_value.begin() + 3) == it);
                    CHECK((it - 3) == j_value.begin());
                    CHECK((it - j_value.begin()) == 3);
                    CHECK(it != j_value.end());
                    it -= 3;
                    CHECK(*it == json(42));
                }
                {
                    auto it = j_value.cbegin();
                    it += 3;
                    CHECK((j_value.cbegin() + 3) == it);
                    CHECK((it - 3) == j_value.cbegin());
                    CHECK((it - j_value.cbegin()) == 3);
                    CHECK(it != j_value.cend());
                    it -= 3;
                    CHECK(*it == json(42));
                }
            }
        }

        SECTION("subscript operator")
        {
            SECTION("object")
            {
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it[0], std::domain_error);
                    CHECK_THROWS_AS(it[1], std::domain_error);
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it[0], std::domain_error);
                    CHECK_THROWS_AS(it[1], std::domain_error);
                }
            }

            SECTION("array")
            {
                {
                    auto it = j_array.begin();
                    CHECK(it[0] == json(1));
                    CHECK(it[1] == json(2));
                    CHECK(it[2] == json(3));
                    CHECK(it[3] == json(4));
                    CHECK(it[4] == json(5));
                    CHECK(it[5] == json(6));
                }
                {
                    auto it = j_array.cbegin();
                    CHECK(it[0] == json(1));
                    CHECK(it[1] == json(2));
                    CHECK(it[2] == json(3));
                    CHECK(it[3] == json(4));
                    CHECK(it[4] == json(5));
                    CHECK(it[5] == json(6));
                }
            }

            SECTION("null")
            {
                {
                    auto it = j_null.begin();
                    CHECK_THROWS_AS(it[0], std::out_of_range);
                    CHECK_THROWS_AS(it[1], std::out_of_range);
                }
                {
                    auto it = j_null.cbegin();
                    CHECK_THROWS_AS(it[0], std::out_of_range);
                    CHECK_THROWS_AS(it[1], std::out_of_range);
                }
            }

            SECTION("value")
            {
                {
                    auto it = j_value.begin();
                    CHECK(it[0] == json(42));
                    CHECK_THROWS_AS(it[1], std::out_of_range);
                }
                {
                    auto it = j_value.cbegin();
                    CHECK(it[0] == json(42));
                    CHECK_THROWS_AS(it[1], std::out_of_range);
                }
            }
        }
    }

    SECTION("reverse iterator comparisons")
    {
        json j_values = {nullptr, true, 42, 23.23, {{"one", 1}, {"two", 2}}, {1, 2, 3, 4, 5}, "Hello, world"};

        for (json& j : j_values)
        {
            auto it1 = j.rbegin();
            auto it2 = j.rbegin();
            auto it3 = j.rbegin();
            ++it2;
            ++it3;
            ++it3;
            auto it1_c = j.crbegin();
            auto it2_c = j.crbegin();
            auto it3_c = j.crbegin();
            ++it2_c;
            ++it3_c;
            ++it3_c;

            // comparison: equal
            {
                CHECK(it1 == it1);
                CHECK(not (it1 == it2));
                CHECK(not (it1 == it3));
                CHECK(not (it2 == it3));
                CHECK(it1_c == it1_c);
                CHECK(not (it1_c == it2_c));
                CHECK(not (it1_c == it3_c));
                CHECK(not (it2_c == it3_c));
            }

            // comparison: not equal
            {
                // check definition
                CHECK( (it1 != it1) == not(it1 == it1) );
                CHECK( (it1 != it2) == not(it1 == it2) );
                CHECK( (it1 != it3) == not(it1 == it3) );
                CHECK( (it2 != it3) == not(it2 == it3) );
                CHECK( (it1_c != it1_c) == not(it1_c == it1_c) );
                CHECK( (it1_c != it2_c) == not(it1_c == it2_c) );
                CHECK( (it1_c != it3_c) == not(it1_c == it3_c) );
                CHECK( (it2_c != it3_c) == not(it2_c == it3_c) );
            }

            // comparison: smaller
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 < it1, std::domain_error);
                    CHECK_THROWS_AS(it1 < it2, std::domain_error);
                    CHECK_THROWS_AS(it2 < it3, std::domain_error);
                    CHECK_THROWS_AS(it1 < it3, std::domain_error);
                    CHECK_THROWS_AS(it1_c < it1_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c < it2_c, std::domain_error);
                    CHECK_THROWS_AS(it2_c < it3_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c < it3_c, std::domain_error);
                }
                else
                {
                    CHECK(not (it1 < it1));
                    CHECK(it1 < it2);
                    CHECK(it1 < it3);
                    CHECK(it2 < it3);
                    CHECK(not (it1_c < it1_c));
                    CHECK(it1_c < it2_c);
                    CHECK(it1_c < it3_c);
                    CHECK(it2_c < it3_c);
                }
            }

            // comparison: less than or equal
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 <= it1, std::domain_error);
                    CHECK_THROWS_AS(it1 <= it2, std::domain_error);
                    CHECK_THROWS_AS(it2 <= it3, std::domain_error);
                    CHECK_THROWS_AS(it1 <= it3, std::domain_error);
                    CHECK_THROWS_AS(it1_c <= it1_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c <= it2_c, std::domain_error);
                    CHECK_THROWS_AS(it2_c <= it3_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c <= it3_c, std::domain_error);
                }
                else
                {
                    // check definition
                    CHECK( (it1 <= it1) == not(it1 < it1) );
                    CHECK( (it1 <= it2) == not(it2 < it1) );
                    CHECK( (it1 <= it3) == not(it3 < it1) );
                    CHECK( (it2 <= it3) == not(it3 < it2) );
                    CHECK( (it1_c <= it1_c) == not(it1_c < it1_c) );
                    CHECK( (it1_c <= it2_c) == not(it2_c < it1_c) );
                    CHECK( (it1_c <= it3_c) == not(it3_c < it1_c) );
                    CHECK( (it2_c <= it3_c) == not(it3_c < it2_c) );
                }
            }

            // comparison: greater than
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 > it1, std::domain_error);
                    CHECK_THROWS_AS(it1 > it2, std::domain_error);
                    CHECK_THROWS_AS(it2 > it3, std::domain_error);
                    CHECK_THROWS_AS(it1 > it3, std::domain_error);
                    CHECK_THROWS_AS(it1_c > it1_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c > it2_c, std::domain_error);
                    CHECK_THROWS_AS(it2_c > it3_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c > it3_c, std::domain_error);
                }
                else
                {
                    // check definition
                    CHECK( (it1 > it1) == (it1 < it1) );
                    CHECK( (it1 > it2) == (it2 < it1) );
                    CHECK( (it1 > it3) == (it3 < it1) );
                    CHECK( (it2 > it3) == (it3 < it2) );
                    CHECK( (it1_c > it1_c) == (it1_c < it1_c) );
                    CHECK( (it1_c > it2_c) == (it2_c < it1_c) );
                    CHECK( (it1_c > it3_c) == (it3_c < it1_c) );
                    CHECK( (it2_c > it3_c) == (it3_c < it2_c) );
                }
            }

            // comparison: greater than or equal
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 >= it1, std::domain_error);
                    CHECK_THROWS_AS(it1 >= it2, std::domain_error);
                    CHECK_THROWS_AS(it2 >= it3, std::domain_error);
                    CHECK_THROWS_AS(it1 >= it3, std::domain_error);
                    CHECK_THROWS_AS(it1_c >= it1_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c >= it2_c, std::domain_error);
                    CHECK_THROWS_AS(it2_c >= it3_c, std::domain_error);
                    CHECK_THROWS_AS(it1_c >= it3_c, std::domain_error);
                }
                else
                {
                    // check definition
                    CHECK( (it1 >= it1) == not(it1 < it1) );
                    CHECK( (it1 >= it2) == not(it1 < it2) );
                    CHECK( (it1 >= it3) == not(it1 < it3) );
                    CHECK( (it2 >= it3) == not(it2 < it3) );
                    CHECK( (it1_c >= it1_c) == not(it1_c < it1_c) );
                    CHECK( (it1_c >= it2_c) == not(it1_c < it2_c) );
                    CHECK( (it1_c >= it3_c) == not(it1_c < it3_c) );
                    CHECK( (it2_c >= it3_c) == not(it2_c < it3_c) );
                }
            }
        }

        // check exceptions if different objects are compared
        for (auto j : j_values)
        {
            for (auto k : j_values)
            {
                if (j != k)
                {
                    CHECK_THROWS_AS(j.rbegin() == k.rbegin(), std::domain_error);
                    CHECK_THROWS_AS(j.crbegin() == k.crbegin(), std::domain_error);

                    CHECK_THROWS_AS(j.rbegin() < k.rbegin(), std::domain_error);
                    CHECK_THROWS_AS(j.crbegin() < k.crbegin(), std::domain_error);
                }
            }
        }
    }

    SECTION("reverse iterator arithmetic")
    {
        json j_object = {{"one", 1}, {"two", 2}, {"three", 3}};
        json j_array = {1, 2, 3, 4, 5, 6};
        json j_null = nullptr;
        json j_value = 42;

        SECTION("addition and subtraction")
        {
            SECTION("object")
            {
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it += 1, std::domain_error);
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it += 1, std::domain_error);
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it + 1, std::domain_error);
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it + 1, std::domain_error);
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it -= 1, std::domain_error);
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it -= 1, std::domain_error);
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it - 1, std::domain_error);
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it - 1, std::domain_error);
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it - it, std::domain_error);
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it - it, std::domain_error);
                }
            }

            SECTION("array")
            {
                {
                    auto it = j_array.rbegin();
                    it += 3;
                    CHECK((j_array.rbegin() + 3) == it);
                    CHECK((it - 3) == j_array.rbegin());
                    CHECK((j_array.rbegin() - it) == 3);
                    CHECK(*it == json(3));
                    it -= 2;
                    CHECK(*it == json(5));
                }
                {
                    auto it = j_array.crbegin();
                    it += 3;
                    CHECK((j_array.crbegin() + 3) == it);
                    CHECK((it - 3) == j_array.crbegin());
                    CHECK((j_array.crbegin() - it) == 3);
                    CHECK(*it == json(3));
                    it -= 2;
                    CHECK(*it == json(5));
                }
            }

            SECTION("null")
            {
                {
                    auto it = j_null.rbegin();
                    it += 3;
                    CHECK((j_null.rbegin() + 3) == it);
                    CHECK((it - 3) == j_null.rbegin());
                    CHECK((j_null.rbegin() - it) == 3);
                    CHECK(it != j_null.rend());
                    it -= 3;
                    CHECK(it == j_null.rend());
                }
                {
                    auto it = j_null.crbegin();
                    it += 3;
                    CHECK((j_null.crbegin() + 3) == it);
                    CHECK((it - 3) == j_null.crbegin());
                    CHECK((j_null.crbegin() - it) == 3);
                    CHECK(it != j_null.crend());
                    it -= 3;
                    CHECK(it == j_null.crend());
                }
            }

            SECTION("value")
            {
                {
                    auto it = j_value.rbegin();
                    it += 3;
                    CHECK((j_value.rbegin() + 3) == it);
                    CHECK((it - 3) == j_value.rbegin());
                    CHECK((j_value.rbegin() - it) == 3);
                    CHECK(it != j_value.rend());
                    it -= 3;
                    CHECK(*it == json(42));
                }
                {
                    auto it = j_value.crbegin();
                    it += 3;
                    CHECK((j_value.crbegin() + 3) == it);
                    CHECK((it - 3) == j_value.crbegin());
                    CHECK((j_value.crbegin() - it) == 3);
                    CHECK(it != j_value.crend());
                    it -= 3;
                    CHECK(*it == json(42));
                }
            }
        }

        SECTION("subscript operator")
        {
            SECTION("object")
            {
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it[0], std::domain_error);
                    CHECK_THROWS_AS(it[1], std::domain_error);
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it[0], std::domain_error);
                    CHECK_THROWS_AS(it[1], std::domain_error);
                }
            }

            SECTION("array")
            {
                {
                    auto it = j_array.rbegin();
                    CHECK(it[0] == json(6));
                    CHECK(it[1] == json(5));
                    CHECK(it[2] == json(4));
                    CHECK(it[3] == json(3));
                    CHECK(it[4] == json(2));
                    CHECK(it[5] == json(1));
                }
                {
                    auto it = j_array.crbegin();
                    CHECK(it[0] == json(6));
                    CHECK(it[1] == json(5));
                    CHECK(it[2] == json(4));
                    CHECK(it[3] == json(3));
                    CHECK(it[4] == json(2));
                    CHECK(it[5] == json(1));
                }
            }

            SECTION("null")
            {
                {
                    auto it = j_null.rbegin();
                    CHECK_THROWS_AS(it[0], std::out_of_range);
                    CHECK_THROWS_AS(it[1], std::out_of_range);
                }
                {
                    auto it = j_null.crbegin();
                    CHECK_THROWS_AS(it[0], std::out_of_range);
                    CHECK_THROWS_AS(it[1], std::out_of_range);
                }
            }

            SECTION("value")
            {
                {
                    auto it = j_value.rbegin();
                    CHECK(it[0] == json(42));
                    CHECK_THROWS_AS(it[1], std::out_of_range);
                }
                {
                    auto it = j_value.crbegin();
                    CHECK(it[0] == json(42));
                    CHECK_THROWS_AS(it[1], std::out_of_range);
                }
            }
        }
    }
}

TEST_CASE("capacity")
{
    SECTION("empty()")
    {
        SECTION("boolean")
        {
            json j = true;
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() != j.end());
                CHECK(j_const.begin() != j_const.end());
            }
        }

        SECTION("string")
        {
            json j = "hello world";
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() != j.end());
                CHECK(j_const.begin() != j_const.end());
            }
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array();
                json j_const(j);

                SECTION("result of empty")
                {
                    CHECK(j.empty() == true);
                    CHECK(j_const.empty() == true);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.begin() == j.end());
                    CHECK(j_const.begin() == j_const.end());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};
                json j_const(j);

                SECTION("result of empty")
                {
                    CHECK(j.empty() == false);
                    CHECK(j_const.empty() == false);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.begin() != j.end());
                    CHECK(j_const.begin() != j_const.end());
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object();
                json j_const(j);

                SECTION("result of empty")
                {
                    CHECK(j.empty() == true);
                    CHECK(j_const.empty() == true);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.begin() == j.end());
                    CHECK(j_const.begin() == j_const.end());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
                json j_const(j);

                SECTION("result of empty")
                {
                    CHECK(j.empty() == false);
                    CHECK(j_const.empty() == false);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.begin() != j.end());
                    CHECK(j_const.begin() != j_const.end());
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() != j.end());
                CHECK(j_const.begin() != j_const.end());
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() != j.end());
                CHECK(j_const.begin() != j_const.end());
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == true);
                CHECK(j_const.empty() == true);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() == j.end());
                CHECK(j_const.begin() == j_const.end());
            }
        }
    }

    SECTION("size()")
    {
        SECTION("boolean")
        {
            json j = true;
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("string")
        {
            json j = "hello world";
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array();
                json j_const(j);

                SECTION("result of size")
                {
                    CHECK(j.size() == 0);
                    CHECK(j_const.size() == 0);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                    CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                    CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};
                json j_const(j);

                SECTION("result of size")
                {
                    CHECK(j.size() == 3);
                    CHECK(j_const.size() == 3);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                    CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                    CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object();
                json j_const(j);

                SECTION("result of size")
                {
                    CHECK(j.size() == 0);
                    CHECK(j_const.size() == 0);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                    CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                    CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
                json j_const(j);

                SECTION("result of size")
                {
                    CHECK(j.size() == 3);
                    CHECK(j_const.size() == 3);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                    CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                    CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 0);
                CHECK(j_const.size() == 0);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }
    }

    SECTION("max_size()")
    {
        SECTION("boolean")
        {
            json j = true;
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("string")
        {
            json j = "hello world";
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array();
                json j_const(j);

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};
                json j_const(j);

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object();
                json j_const(j);

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
                json j_const(j);

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 0);
                CHECK(j_const.max_size() == 0);
            }
        }
    }
}

TEST_CASE("modifiers")
{
    SECTION("clear()")
    {
        SECTION("boolean")
        {
            json j = true;

            j.clear();
            CHECK(j == json(json::value_t::boolean));
        }

        SECTION("string")
        {
            json j = "hello world";

            j.clear();
            CHECK(j == json(json::value_t::string));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array();

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::array));
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::array));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object();

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::object));
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::object));
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;

            j.clear();
            CHECK(j == json(json::value_t::number_integer));
        }

        SECTION("number (float)")
        {
            json j = 23.42;

            j.clear();
            CHECK(j == json(json::value_t::number_float));
        }

        SECTION("null")
        {
            json j = nullptr;

            j.clear();
            CHECK(j == json(json::value_t::null));
        }
    }

    SECTION("push_back()")
    {
        SECTION("to array")
        {
            SECTION("json&&")
            {
                SECTION("null")
                {
                    json j;
                    j.push_back(1);
                    j.push_back(2);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    j.push_back("Hello");
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    CHECK_THROWS_AS(j.push_back("Hello"), std::domain_error);
                }
            }

            SECTION("const json&")
            {
                SECTION("null")
                {
                    json j;
                    json k(1);
                    j.push_back(k);
                    j.push_back(k);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 1}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    json k("Hello");
                    j.push_back(k);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    json k("Hello");
                    CHECK_THROWS_AS(j.push_back(k), std::domain_error);
                }
            }
        }

        SECTION("to object")
        {
            SECTION("null")
            {
                json j;
                j.push_back(json::object_t::value_type({"one", 1}));
                j.push_back(json::object_t::value_type({"two", 2}));
                CHECK(j.type() == json::value_t::object);
                CHECK(j.size() == 2);
                CHECK(j["one"] == json(1));
                CHECK(j["two"] == json(2));
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                j.push_back(json::object_t::value_type({"one", 1}));
                j.push_back(json::object_t::value_type({"two", 2}));
                CHECK(j.size() == 2);
                CHECK(j["one"] == json(1));
                CHECK(j["two"] == json(2));
            }

            SECTION("other type")
            {
                json j = 1;
                json k("Hello");
                CHECK_THROWS_AS(j.push_back(json::object_t::value_type({"one", 1})), std::domain_error);
            }
        }
    }

    SECTION("operator+=")
    {
        SECTION("to array")
        {
            SECTION("json&&")
            {
                SECTION("null")
                {
                    json j;
                    j += 1;
                    j += 2;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    j += "Hello";
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    CHECK_THROWS_AS(j += "Hello", std::domain_error);
                }
            }

            SECTION("const json&")
            {
                SECTION("null")
                {
                    json j;
                    json k(1);
                    j += k;
                    j += k;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 1}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    json k("Hello");
                    j += k;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    json k("Hello");
                    CHECK_THROWS_AS(j += k, std::domain_error);
                }
            }
        }

        SECTION("to object")
        {
            SECTION("null")
            {
                json j;
                j += json::object_t::value_type({"one", 1});
                j += json::object_t::value_type({"two", 2});
                CHECK(j.type() == json::value_t::object);
                CHECK(j.size() == 2);
                CHECK(j["one"] == json(1));
                CHECK(j["two"] == json(2));
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                j += json::object_t::value_type({"one", 1});
                j += json::object_t::value_type({"two", 2});
                CHECK(j.size() == 2);
                CHECK(j["one"] == json(1));
                CHECK(j["two"] == json(2));
            }

            SECTION("other type")
            {
                json j = 1;
                json k("Hello");
                CHECK_THROWS_AS(j += json::object_t::value_type({"one", 1}), std::domain_error);
            }
        }
    }

    SECTION("insert")
    {
        json j_array = {1, 2, 3, 4};
        json j_value = 5;

        SECTION("value at position")
        {
            SECTION("insert before begin()")
            {
                auto it = j_array.insert(j_array.begin(), j_value);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK(j_array.begin() == it);
                CHECK(j_array == json({5, 1, 2, 3, 4}));
            }

            SECTION("insert in the middle")
            {
                auto it = j_array.insert(j_array.begin() + 2, j_value);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK((it - j_array.begin()) == 2);
                CHECK(j_array == json({1, 2, 5, 3, 4}));
            }

            SECTION("insert before end()")
            {
                auto it = j_array.insert(j_array.end(), j_value);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK((j_array.end() - it) == 1);
                CHECK(j_array == json({1, 2, 3, 4, 5}));
            }
        }

        SECTION("rvalue at position")
        {
            SECTION("insert before begin()")
            {
                auto it = j_array.insert(j_array.begin(), 5);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK(j_array.begin() == it);
                CHECK(j_array == json({5, 1, 2, 3, 4}));
            }

            SECTION("insert in the middle")
            {
                auto it = j_array.insert(j_array.begin() + 2, 5);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK((it - j_array.begin()) == 2);
                CHECK(j_array == json({1, 2, 5, 3, 4}));
            }

            SECTION("insert before end()")
            {
                auto it = j_array.insert(j_array.end(), 5);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK((j_array.end() - it) == 1);
                CHECK(j_array == json({1, 2, 3, 4, 5}));
            }
        }

        SECTION("copies at position")
        {
            SECTION("insert before begin()")
            {
                auto it = j_array.insert(j_array.begin(), 3, 5);
                CHECK(j_array.size() == 7);
                CHECK(*it == j_value);
                CHECK(j_array.begin() == it);
                CHECK(j_array == json({5, 5, 5, 1, 2, 3, 4}));
            }

            SECTION("insert in the middle")
            {
                auto it = j_array.insert(j_array.begin() + 2, 3, 5);
                CHECK(j_array.size() == 7);
                CHECK(*it == j_value);
                CHECK((it - j_array.begin()) == 2);
                CHECK(j_array == json({1, 2, 5, 5, 5, 3, 4}));
            }

            SECTION("insert before end()")
            {
                auto it = j_array.insert(j_array.end(), 3, 5);
                CHECK(j_array.size() == 7);
                CHECK(*it == j_value);
                CHECK((j_array.end() - it) == 3);
                CHECK(j_array == json({1, 2, 3, 4, 5, 5, 5}));
            }

            SECTION("insert nothing (count = 0)")
            {
                auto pos = j_array.end();
                auto it = j_array.insert(j_array.end(), 0, 5);
                CHECK(j_array.size() == 4);
                CHECK(it == pos);
                CHECK(j_array == json({1, 2, 3, 4}));
            }
        }

        SECTION("range")
        {
            json j_other_array = {"first", "second"};

            SECTION("proper usage")
            {
                auto it = j_array.insert(j_array.end(), j_other_array.begin(), j_other_array.end());
                CHECK(j_array.size() == 6);
                CHECK(*it == *j_other_array.begin());
                CHECK((j_array.end() - it) == 2);
                CHECK(j_array == json({1, 2, 3, 4, "first", "second"}));
            }

            SECTION("empty range")
            {
                auto it = j_array.insert(j_array.end(), j_other_array.begin(), j_other_array.begin());
                CHECK(j_array.size() == 4);
                CHECK(it == j_array.end());
                CHECK(j_array == json({1, 2, 3, 4}));
            }

            SECTION("invalid iterators")
            {
                json j_other_array2 = {"first", "second"};

                CHECK_THROWS_AS(j_array.insert(j_array.end(), j_array.begin(), j_array.end()), std::domain_error);
                CHECK_THROWS_AS(j_array.insert(j_array.end(), j_other_array.begin(), j_other_array2.end()),
                                std::domain_error);
            }
        }

        SECTION("initializer list at position")
        {
            SECTION("insert before begin()")
            {
                auto it = j_array.insert(j_array.begin(), {7, 8, 9});
                CHECK(j_array.size() == 7);
                CHECK(*it == json(7));
                CHECK(j_array.begin() == it);
                CHECK(j_array == json({7, 8, 9, 1, 2, 3, 4}));
            }

            SECTION("insert in the middle")
            {
                auto it = j_array.insert(j_array.begin() + 2, {7, 8, 9});
                CHECK(j_array.size() == 7);
                CHECK(*it == json(7));
                CHECK((it - j_array.begin()) == 2);
                CHECK(j_array == json({1, 2, 7, 8, 9, 3, 4}));
            }

            SECTION("insert before end()")
            {
                auto it = j_array.insert(j_array.end(), {7, 8, 9});
                CHECK(j_array.size() == 7);
                CHECK(*it == json(7));
                CHECK((j_array.end() - it) == 3);
                CHECK(j_array == json({1, 2, 3, 4, 7, 8, 9}));
            }
        }

        SECTION("invalid iterator")
        {
            // pass iterator to a different array
            json j_another_array = {1, 2};
            json j_yet_another_array = {"first", "second"};
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), 10), std::domain_error);
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), j_value), std::domain_error);
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), 10, 11), std::domain_error);
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), j_yet_another_array.begin(),
                                           j_yet_another_array.end()), std::domain_error);
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), {1, 2, 3, 4}), std::domain_error);
        }

        SECTION("non-array type")
        {
            // call insert on a non-array type
            json j_nonarray = 3;
            json j_yet_another_array = {"first", "second"};
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), 10), std::domain_error);
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), j_value), std::domain_error);
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), 10, 11), std::domain_error);
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), j_yet_another_array.begin(),
                                              j_yet_another_array.end()), std::domain_error);
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), {1, 2, 3, 4}), std::domain_error);
        }
    }

    SECTION("swap()")
    {
        SECTION("json")
        {
            SECTION("member swap")
            {
                json j("hello world");
                json k(42.23);

                j.swap(k);

                CHECK(j == json(42.23));
                CHECK(k == json("hello world"));
            }

            SECTION("nonmember swap")
            {
                json j("hello world");
                json k(42.23);

                std::swap(j, k);

                CHECK(j == json(42.23));
                CHECK(k == json("hello world"));
            }
        }

        SECTION("array_t")
        {
            SECTION("array_t type")
            {
                json j = {1, 2, 3, 4};
                json::array_t a = {"foo", "bar", "baz"};

                j.swap(a);

                CHECK(j == json({"foo", "bar", "baz"}));

                j.swap(a);

                CHECK(j == json({1, 2, 3, 4}));
            }

            SECTION("non-array_t type")
            {
                json j = 17;
                json::array_t a = {"foo", "bar", "baz"};

                CHECK_THROWS_AS(j.swap(a), std::domain_error);
            }
        }

        SECTION("object_t")
        {
            SECTION("object_t type")
            {
                json j = {{"one", 1}, {"two", 2}};
                json::object_t o = {{"cow", "Kuh"}, {"chicken", "Huhn"}};

                j.swap(o);

                CHECK(j == json({{"cow", "Kuh"}, {"chicken", "Huhn"}}));

                j.swap(o);

                CHECK(j == json({{"one", 1}, {"two", 2}}));
            }

            SECTION("non-object_t type")
            {
                json j = 17;
                json::object_t o = {{"cow", "Kuh"}, {"chicken", "Huhn"}};

                CHECK_THROWS_AS(j.swap(o), std::domain_error);
            }
        }

        SECTION("string_t")
        {
            SECTION("string_t type")
            {
                json j = "Hello world";
                json::string_t s = "Hallo Welt";

                j.swap(s);

                CHECK(j == json("Hallo Welt"));

                j.swap(s);

                CHECK(j == json("Hello world"));
            }

            SECTION("non-string_t type")
            {
                json j = 17;
                json::string_t s = "Hallo Welt";

                CHECK_THROWS_AS(j.swap(s), std::domain_error);
            }
        }
    }
}

TEST_CASE("lexicographical comparison operators")
{
    SECTION("types")
    {
        std::vector<json::value_t> j_types =
        {
            json::value_t::null,
            json::value_t::boolean,
            json::value_t::number_integer,
            json::value_t::number_float,
            json::value_t::object,
            json::value_t::array,
            json::value_t::string
        };

        SECTION("comparison: less")
        {
            std::vector<std::vector<bool>> expected =
            {
                {false, true, true, true, true, true, true},
                {false, false, true, true, true, true, true},
                {false, false, false, false, true, true, true},
                {false, false, false, false, true, true, true},
                {false, false, false, false, false, true, true},
                {false, false, false, false, false, false, true},
                {false, false, false, false, false, false, false}
            };

            for (size_t i = 0; i < j_types.size(); ++i)
            {
                for (size_t j = 0; j < j_types.size(); ++j)
                {
                    CAPTURE(i);
                    CAPTURE(j);
                    // check precomputed values
                    CHECK(operator<(j_types[i], j_types[j]) == expected[i][j]);
                }
            }
        }
    }

    SECTION("values")
    {
        json j_values =
        {
            nullptr, nullptr,
            17, 42,
            3.14159, 23.42,
            "foo", "bar",
            true, false,
            {1, 2, 3}, {"one", "two", "three"},
            {{"first", 1}, {"second", 2}}, {{"a", "A"}, {"b", {"B"}}}
        };

        SECTION("comparison: equal")
        {
            std::vector<std::vector<bool>> expected =
            {
                {true, true, false, false, false, false, false, false, false, false, false, false, false, false},
                {true, true, false, false, false, false, false, false, false, false, false, false, false, false},
                {false, false, true, false, false, false, false, false, false, false, false, false, false, false},
                {false, false, false, true, false, false, false, false, false, false, false, false, false, false},
                {false, false, false, false, true, false, false, false, false, false, false, false, false, false},
                {false, false, false, false, false, true, false, false, false, false, false, false, false, false},
                {false, false, false, false, false, false, true, false, false, false, false, false, false, false},
                {false, false, false, false, false, false, false, true, false, false, false, false, false, false},
                {false, false, false, false, false, false, false, false, true, false, false, false, false, false},
                {false, false, false, false, false, false, false, false, false, true, false, false, false, false},
                {false, false, false, false, false, false, false, false, false, false, true, false, false, false},
                {false, false, false, false, false, false, false, false, false, false, false, true, false, false},
                {false, false, false, false, false, false, false, false, false, false, false, false, true, false},
                {false, false, false, false, false, false, false, false, false, false, false, false, false, true}
            };

            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    // check precomputed values
                    CHECK( (j_values[i] == j_values[j]) == expected[i][j] );
                }
            }

            // comparison with discarded elements
            json j_discarded(json::value_t::discarded);
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                CHECK( (j_values[i] == j_discarded) == false);
                CHECK( (j_discarded == j_values[i]) == false);
                CHECK( (j_discarded == j_discarded) == false);
            }

            // compare with null pointer
            json j_null;
            CHECK(j_null == nullptr);
            CHECK(nullptr == j_null);
        }

        SECTION("comparison: not equal")
        {
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    // check definition
                    CHECK( (j_values[i] != j_values[j]) == not(j_values[i] == j_values[j]) );
                }
            }

            // compare with null pointer
            json j_null;
            CHECK( (j_null != nullptr) == false);
            CHECK( (nullptr != j_null) == false);
            CHECK( (j_null != nullptr) == not(j_null == nullptr));
            CHECK( (nullptr != j_null) == not(nullptr == j_null));
        }

        SECTION("comparison: less")
        {
            std::vector<std::vector<bool>> expected =
            {
                {false, false, true, true, true, true, true, true, true, true, true, true, true, true},
                {false, false, true, true, true, true, true, true, true, true, true, true, true, true},
                {false, false, false, true, false, true, true, true, false, false, true, true, true, true},
                {false, false, false, false, false, false, true, true, false, false, true, true, true, true},
                {false, false, true, true, false, true, true, true, false, false, true, true, true, true},
                {false, false, false, true, false, false, true, true, false, false, true, true, true, true},
                {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
                {false, false, false, false, false, false, true, false, false, false, false, false, false, false},
                {false, false, true, true, true, true, true, true, false, false, true, true, true, true},
                {false, false, true, true, true, true, true, true, true, false, true, true, true, true},
                {false, false, false, false, false, false, true, true, false, false, false, true, false, false},
                {false, false, false, false, false, false, true, true, false, false, false, false, false, false},
                {false, false, false, false, false, false, true, true, false, false, true, true, false, false},
                {false, false, false, false, false, false, true, true, false, false, true, true, true, false}
            };

            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    // check precomputed values
                    CHECK( (j_values[i] < j_values[j]) == expected[i][j] );
                }
            }

            // comparison with discarded elements
            json j_discarded(json::value_t::discarded);
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                CHECK( (j_values[i] < j_discarded) == false);
                CHECK( (j_discarded < j_values[i]) == false);
                CHECK( (j_discarded < j_discarded) == false);
            }
        }

        SECTION("comparison: less than or equal equal")
        {
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    // check definition
                    CHECK( (j_values[i] <= j_values[j]) == not(j_values[j] < j_values[i]) );
                }
            }
        }

        SECTION("comparison: greater than")
        {
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    // check definition
                    CHECK( (j_values[i] > j_values[j]) == (j_values[j] < j_values[i]) );
                }
            }
        }

        SECTION("comparison: greater than or equal")
        {
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    // check definition
                    CHECK( (j_values[i] >= j_values[j]) == not(j_values[i] < j_values[j]) );
                }
            }
        }
    }
}

TEST_CASE("serialization")
{
    SECTION("operator<<")
    {
        SECTION("no given width")
        {
            std::stringstream ss;
            json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss << j;
            CHECK(ss.str() == "[\"foo\",1,2,3,false,{\"one\":1}]");
        }

        SECTION("given width")
        {
            std::stringstream ss;
            json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss << std::setw(4) << j;
            CHECK(ss.str() ==
                  "[\n    \"foo\",\n    1,\n    2,\n    3,\n    false,\n    {\n        \"one\": 1\n    }\n]");
        }
    }

    SECTION("operator>>")
    {
        SECTION("no given width")
        {
            std::stringstream ss;
            json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            j >> ss;
            CHECK(ss.str() == "[\"foo\",1,2,3,false,{\"one\":1}]");
        }

        SECTION("given width")
        {
            std::stringstream ss;
            json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss.width(4);
            j >> ss;
            CHECK(ss.str() ==
                  "[\n    \"foo\",\n    1,\n    2,\n    3,\n    false,\n    {\n        \"one\": 1\n    }\n]");
        }
    }
}

TEST_CASE("deserialization")
{
    SECTION("stream")
    {
        std::stringstream ss;
        ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
        json j = json::parse(ss);
        CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
    }

    SECTION("string")
    {
        auto s = "[\"foo\",1,2,3,false,{\"one\":1}]";
        json j = json::parse(s);
        CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
    }

    SECTION("operator<<")
    {
        std::stringstream ss;
        ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
        json j;
        j << ss;
        CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
    }

    SECTION("operator>>")
    {
        std::stringstream ss;
        ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
        json j;
        ss >> j;
        CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
    }

    SECTION("user-defined string literal")
    {
        CHECK("[\"foo\",1,2,3,false,{\"one\":1}]"_json == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
    }
}

TEST_CASE("iterator class")
{
    SECTION("construction")
    {
        SECTION("constructor")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it(&j);
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::iterator it(&j);
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::iterator it(&j);
            }
        }

        SECTION("copy assignment")
        {
            json j(json::value_t::null);
            json::iterator it(&j);
            json::iterator it2(&j);
            it2 = it;
        }
    }

    SECTION("initialization")
    {
        SECTION("set_begin")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it(&j);
                it.set_begin();
                CHECK(it == j.begin());
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::iterator it(&j);
                it.set_begin();
                CHECK(it == j.begin());
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::iterator it(&j);
                it.set_begin();
                CHECK(it == j.begin());
            }
        }

        SECTION("set_end")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it(&j);
                it.set_end();
                CHECK(it == j.end());
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::iterator it(&j);
                it.set_end();
                CHECK(it == j.end());
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::iterator it(&j);
                it.set_end();
                CHECK(it == j.end());
            }
        }
    }

    SECTION("element access")
    {
        SECTION("operator*")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it = j.begin();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.begin();
                CHECK(*it == json(17));
                it = j.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.begin();
                CHECK(*it == json("bar"));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.begin();
                CHECK(*it == json(1));
            }
        }

        SECTION("operator->")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it = j.begin();
                CHECK_THROWS_AS(it->type_name(), std::out_of_range);
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.begin();
                CHECK(it->type_name() == "number");
                it = j.end();
                CHECK_THROWS_AS(it->type_name(), std::out_of_range);
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.begin();
                CHECK(it->type_name() == "string");
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.begin();
                CHECK(it->type_name() == "number");
            }
        }
    }

    SECTION("increment/decrement")
    {
        SECTION("post-increment")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it = j.begin();
                CHECK(it.m_it.primitive_iterator == 1);
                it++;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.begin();
                CHECK(it.m_it.primitive_iterator == 0);
                it++;
                CHECK(it.m_it.primitive_iterator == 1);
                it++;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.begin();
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->begin());
                it++;
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->end());
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.begin();
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->begin());
                it++;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it++;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it++;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it++;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->end());
            }
        }

        SECTION("pre-increment")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it = j.begin();
                CHECK(it.m_it.primitive_iterator == 1);
                ++it;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.begin();
                CHECK(it.m_it.primitive_iterator == 0);
                ++it;
                CHECK(it.m_it.primitive_iterator == 1);
                ++it;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.begin();
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->begin());
                ++it;
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->end());
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.begin();
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->begin());
                ++it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                ++it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                ++it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                ++it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->end());
            }
        }

        SECTION("post-decrement")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it = j.end();
                CHECK(it.m_it.primitive_iterator == 1);
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.end();
                CHECK(it.m_it.primitive_iterator == 1);
                it--;
                CHECK(it.m_it.primitive_iterator == 0);
                it--;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.end();
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->end());
                it--;
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->begin());
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.end();
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->end());
                it--;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it--;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it--;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it--;
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
            }
        }

        SECTION("pre-decrement")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it = j.end();
                CHECK(it.m_it.primitive_iterator == 1);
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.end();
                CHECK(it.m_it.primitive_iterator == 1);
                --it;
                CHECK(it.m_it.primitive_iterator == 0);
                --it;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.end();
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->end());
                --it;
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->begin());
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.end();
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->end());
                --it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                --it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                --it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                --it;
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
            }
        }
    }
}

TEST_CASE("const_iterator class")
{
    SECTION("construction")
    {
        SECTION("constructor")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it(&j);
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::const_iterator it(&j);
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::const_iterator it(&j);
            }
        }

        SECTION("copy assignment")
        {
            json j(json::value_t::null);
            json::const_iterator it(&j);
            json::const_iterator it2(&j);
            it2 = it;
        }
    }

    SECTION("initialization")
    {
        SECTION("set_begin")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK(it == j.cbegin());
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK(it == j.cbegin());
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK(it == j.cbegin());
            }
        }

        SECTION("set_end")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it(&j);
                it.set_end();
                CHECK(it == j.cend());
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::const_iterator it(&j);
                it.set_end();
                CHECK(it == j.cend());
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::const_iterator it(&j);
                it.set_end();
                CHECK(it == j.cend());
            }
        }
    }

    SECTION("element access")
    {
        SECTION("operator*")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cbegin();
                CHECK(*it == json(17));
                it = j.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK(*it == json("bar"));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cbegin();
                CHECK(*it == json(1));
            }
        }

        SECTION("operator->")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK_THROWS_AS(it->type_name(), std::out_of_range);
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cbegin();
                CHECK(it->type_name() == "number");
                it = j.cend();
                CHECK_THROWS_AS(it->type_name(), std::out_of_range);
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK(it->type_name() == "string");
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cbegin();
                CHECK(it->type_name() == "number");
            }
        }
    }

    SECTION("increment/decrement")
    {
        SECTION("post-increment")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK(it.m_it.primitive_iterator == 1);
                it++;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cbegin();
                CHECK(it.m_it.primitive_iterator == 0);
                it++;
                CHECK(it.m_it.primitive_iterator == 1);
                it++;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->begin());
                it++;
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->end());
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cbegin();
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->begin());
                it++;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it++;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it++;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it++;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->end());
            }
        }

        SECTION("pre-increment")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK(it.m_it.primitive_iterator == 1);
                ++it;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cbegin();
                CHECK(it.m_it.primitive_iterator == 0);
                ++it;
                CHECK(it.m_it.primitive_iterator == 1);
                ++it;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->begin());
                ++it;
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->end());
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cbegin();
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->begin());
                ++it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                ++it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                ++it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                ++it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->end());
            }
        }

        SECTION("post-decrement")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cend();
                CHECK(it.m_it.primitive_iterator == 1);
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cend();
                CHECK(it.m_it.primitive_iterator == 1);
                it--;
                CHECK(it.m_it.primitive_iterator == 0);
                it--;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cend();
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->end());
                it--;
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->begin());
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cend();
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->end());
                it--;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it--;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it--;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                it--;
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
            }
        }

        SECTION("pre-decrement")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cend();
                CHECK(it.m_it.primitive_iterator == 1);
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cend();
                CHECK(it.m_it.primitive_iterator == 1);
                --it;
                CHECK(it.m_it.primitive_iterator == 0);
                --it;
                CHECK((it.m_it.primitive_iterator != 0 and it.m_it.primitive_iterator != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cend();
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->end());
                --it;
                CHECK(it.m_it.object_iterator == it.m_object->m_value.object->begin());
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cend();
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->end());
                --it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                --it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                --it;
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
                --it;
                CHECK(it.m_it.array_iterator == it.m_object->m_value.array->begin());
                CHECK(it.m_it.array_iterator != it.m_object->m_value.array->end());
            }
        }
    }
}

TEST_CASE("convenience functions")
{
    SECTION("type name as string")
    {
        CHECK(json(json::value_t::null).type_name() == "null");
        CHECK(json(json::value_t::object).type_name() == "object");
        CHECK(json(json::value_t::array).type_name() == "array");
        CHECK(json(json::value_t::number_integer).type_name() == "number");
        CHECK(json(json::value_t::number_float).type_name() == "number");
        CHECK(json(json::value_t::boolean).type_name() == "boolean");
        CHECK(json(json::value_t::string).type_name() == "string");
        CHECK(json(json::value_t::discarded).type_name() == "discarded");
    }

    SECTION("string escape")
    {
        CHECK(json::escape_string("\"") == "\\\"");
        CHECK(json::escape_string("\\") == "\\\\");
        CHECK(json::escape_string("\b") == "\\b");
        CHECK(json::escape_string("\f") == "\\f");
        CHECK(json::escape_string("\n") == "\\n");
        CHECK(json::escape_string("\r") == "\\r");
        CHECK(json::escape_string("\t") == "\\t");

        CHECK(json::escape_string("\x01") == "\\u0001");
        CHECK(json::escape_string("\x02") == "\\u0002");
        CHECK(json::escape_string("\x03") == "\\u0003");
        CHECK(json::escape_string("\x04") == "\\u0004");
        CHECK(json::escape_string("\x05") == "\\u0005");
        CHECK(json::escape_string("\x06") == "\\u0006");
        CHECK(json::escape_string("\x07") == "\\u0007");
        CHECK(json::escape_string("\x08") == "\\b");
        CHECK(json::escape_string("\x09") == "\\t");
        CHECK(json::escape_string("\x0a") == "\\n");
        CHECK(json::escape_string("\x0b") == "\\u000b");
        CHECK(json::escape_string("\x0c") == "\\f");
        CHECK(json::escape_string("\x0d") == "\\r");
        CHECK(json::escape_string("\x0e") == "\\u000e");
        CHECK(json::escape_string("\x0f") == "\\u000f");
        CHECK(json::escape_string("\x10") == "\\u0010");
        CHECK(json::escape_string("\x11") == "\\u0011");
        CHECK(json::escape_string("\x12") == "\\u0012");
        CHECK(json::escape_string("\x13") == "\\u0013");
        CHECK(json::escape_string("\x14") == "\\u0014");
        CHECK(json::escape_string("\x15") == "\\u0015");
        CHECK(json::escape_string("\x16") == "\\u0016");
        CHECK(json::escape_string("\x17") == "\\u0017");
        CHECK(json::escape_string("\x18") == "\\u0018");
        CHECK(json::escape_string("\x19") == "\\u0019");
        CHECK(json::escape_string("\x1a") == "\\u001a");
        CHECK(json::escape_string("\x1b") == "\\u001b");
        CHECK(json::escape_string("\x1c") == "\\u001c");
        CHECK(json::escape_string("\x1d") == "\\u001d");
        CHECK(json::escape_string("\x1e") == "\\u001e");
        CHECK(json::escape_string("\x1f") == "\\u001f");
    }
}

TEST_CASE("lexer class")
{
    SECTION("scan")
    {
        SECTION("structural characters")
        {
            CHECK(json::lexer("[").scan() == json::lexer::token_type::begin_array);
            CHECK(json::lexer("]").scan() == json::lexer::token_type::end_array);
            CHECK(json::lexer("{").scan() == json::lexer::token_type::begin_object);
            CHECK(json::lexer("}").scan() == json::lexer::token_type::end_object);
            CHECK(json::lexer(",").scan() == json::lexer::token_type::value_separator);
            CHECK(json::lexer(":").scan() == json::lexer::token_type::name_separator);
        }

        SECTION("literal names")
        {
            CHECK(json::lexer("null").scan() == json::lexer::token_type::literal_null);
            CHECK(json::lexer("true").scan() == json::lexer::token_type::literal_true);
            CHECK(json::lexer("false").scan() == json::lexer::token_type::literal_false);
        }

        SECTION("numbers")
        {
            CHECK(json::lexer("0").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("1").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("2").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("3").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("4").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("5").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("6").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("7").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("8").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("9").scan() == json::lexer::token_type::value_number);
        }

        SECTION("whitespace")
        {
            // result is end_of_input, because not token is following
            CHECK(json::lexer(" ").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\t").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\n").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\r").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer(" \t\n\r\n\t ").scan() == json::lexer::token_type::end_of_input);
        }
    }

    SECTION("token_type_name")
    {
        CHECK(json::lexer::token_type_name(json::lexer::token_type::uninitialized) == "<uninitialized>");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_true) == "true literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_false) == "false literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_null) == "null literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_string) == "string literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_number) == "number literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::begin_array) == "[");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::begin_object) == "{");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_array) == "]");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_object) == "}");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::name_separator) == ":");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_separator) == ",");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::parse_error) == "<parse error>");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_of_input) == "<end of input>");
    }

    SECTION("parse errors on first character")
    {
        for (int c = 1; c < 128; ++c)
        {
            auto s = std::string(1, c);

            switch (c)
            {
                // single characters that are valid tokens
                case ('['):
                case (']'):
                case ('{'):
                case ('}'):
                case (','):
                case (':'):
                case ('0'):
                case ('1'):
                case ('2'):
                case ('3'):
                case ('4'):
                case ('5'):
                case ('6'):
                case ('7'):
                case ('8'):
                case ('9'):
                {
                    CHECK(json::lexer(s.c_str()).scan() != json::lexer::token_type::parse_error);
                    break;
                }

                // whitespace
                case (' '):
                case ('\t'):
                case ('\n'):
                case ('\r'):
                {
                    CHECK(json::lexer(s.c_str()).scan() == json::lexer::token_type::end_of_input);
                    break;
                }

                // anything else is not expected
                default:
                {
                    CHECK(json::lexer(s.c_str()).scan() == json::lexer::token_type::parse_error);
                    break;
                }
            }
        }
    }

    SECTION("to_unicode")
    {
        CHECK(json::lexer::to_unicode(0x1F4A9) == "💩");
        CHECK_THROWS_AS(json::lexer::to_unicode(0x200000), std::out_of_range);
    }
}

TEST_CASE("parser class")
{
    SECTION("parse")
    {
        SECTION("null")
        {
            CHECK(json::parser("null").parse() == json(nullptr));
        }

        SECTION("true")
        {
            CHECK(json::parser("true").parse() == json(true));
        }

        SECTION("false")
        {
            CHECK(json::parser("false").parse() == json(false));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                CHECK(json::parser("[]").parse() == json(json::value_t::array));
                CHECK(json::parser("[ ]").parse() == json(json::value_t::array));
            }

            SECTION("nonempty array")
            {
                CHECK(json::parser("[true, false, null]").parse() == json({true, false, nullptr}));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                CHECK(json::parser("{}").parse() == json(json::value_t::object));
                CHECK(json::parser("{ }").parse() == json(json::value_t::object));
            }

            SECTION("nonempty object")
            {
                CHECK(json::parser("{\"\": true, \"one\": 1, \"two\": null}").parse() == json({{"", true}, {"one", 1}, {"two", nullptr}}));
            }
        }

        SECTION("string")
        {
            // empty string
            CHECK(json::parser("\"\"").parse() == json(json::value_t::string));

            SECTION("errors")
            {
                // error: tab in string
                CHECK_THROWS_AS(json::parser("\"\t\"").parse(), std::invalid_argument);
                // error: newline in string
                CHECK_THROWS_AS(json::parser("\"\n\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\r\"").parse(), std::invalid_argument);
                // error: backspace in string
                CHECK_THROWS_AS(json::parser("\"\b\"").parse(), std::invalid_argument);
            }

            SECTION("escaped")
            {
                // quotation mark "\""
                auto r1 = R"("\"")"_json;
                CHECK(json::parser("\"\\\"\"").parse() == r1);
                // reverse solidus "\\"
                auto r2 = R"("\\")"_json;
                CHECK(json::parser("\"\\\\\"").parse() == r2);
                // solidus
                CHECK(json::parser("\"\\/\"").parse() == R"("/")"_json);
                // backspace
                CHECK(json::parser("\"\\b\"").parse() == json("\b"));
                // formfeed
                CHECK(json::parser("\"\\f\"").parse() == json("\f"));
                // newline
                CHECK(json::parser("\"\\n\"").parse() == json("\n"));
                // carriage return
                CHECK(json::parser("\"\\r\"").parse() == json("\r"));
                // horizontal tab
                CHECK(json::parser("\"\\t\"").parse() == json("\t"));

                CHECK(json::parser("\"\\u0001\"").parse().get<json::string_t>() == "\x01");
                CHECK(json::parser("\"\\u000a\"").parse().get<json::string_t>() == "\n");
                CHECK(json::parser("\"\\u00b0\"").parse().get<json::string_t>() == "°");
                CHECK(json::parser("\"\\u0c00\"").parse().get<json::string_t>() == "ఀ");
                CHECK(json::parser("\"\\ud000\"").parse().get<json::string_t>() == "퀀");
                CHECK(json::parser("\"\\u000E\"").parse().get<json::string_t>() == "\x0E");
                CHECK(json::parser("\"\\u00F0\"").parse().get<json::string_t>() == "ð");
                CHECK(json::parser("\"\\u0100\"").parse().get<json::string_t>() == "Ā");
                CHECK(json::parser("\"\\u2000\"").parse().get<json::string_t>() == " ");
                CHECK(json::parser("\"\\uFFFF\"").parse().get<json::string_t>() == "￿");
                CHECK(json::parser("\"\\u20AC\"").parse().get<json::string_t>() == "€");
                CHECK(json::parser("\"€\"").parse().get<json::string_t>() == "€");
                CHECK(json::parser("\"🎈\"").parse().get<json::string_t>() == "🎈");

                CHECK(json::parse("\"\\ud80c\\udc60\"").get<json::string_t>() == u8"\U00013060");
                CHECK(json::parse("\"\\ud83c\\udf1e\"").get<json::string_t>() == "🌞");
            }
        }

        SECTION("number")
        {
            SECTION("integers")
            {
                SECTION("without exponent")
                {
                    CHECK(json::parser("-128").parse() == json(-128));
                    CHECK(json::parser("-0").parse() == json(-0));
                    CHECK(json::parser("0").parse() == json(0));
                    CHECK(json::parser("128").parse() == json(128));
                }

                SECTION("with exponent")
                {
                    CHECK(json::parser("0e1").parse() == json(0e1));
                    CHECK(json::parser("0E1").parse() == json(0e1));

                    CHECK(json::parser("10000E-4").parse() == json(10000e-4));
                    CHECK(json::parser("10000E-3").parse() == json(10000e-3));
                    CHECK(json::parser("10000E-2").parse() == json(10000e-2));
                    CHECK(json::parser("10000E-1").parse() == json(10000e-1));
                    CHECK(json::parser("10000E0").parse() == json(10000e0));
                    CHECK(json::parser("10000E1").parse() == json(10000e1));
                    CHECK(json::parser("10000E2").parse() == json(10000e2));
                    CHECK(json::parser("10000E3").parse() == json(10000e3));
                    CHECK(json::parser("10000E4").parse() == json(10000e4));

                    CHECK(json::parser("10000e-4").parse() == json(10000e-4));
                    CHECK(json::parser("10000e-3").parse() == json(10000e-3));
                    CHECK(json::parser("10000e-2").parse() == json(10000e-2));
                    CHECK(json::parser("10000e-1").parse() == json(10000e-1));
                    CHECK(json::parser("10000e0").parse() == json(10000e0));
                    CHECK(json::parser("10000e1").parse() == json(10000e1));
                    CHECK(json::parser("10000e2").parse() == json(10000e2));
                    CHECK(json::parser("10000e3").parse() == json(10000e3));
                    CHECK(json::parser("10000e4").parse() == json(10000e4));

                    CHECK(json::parser("-0e1").parse() == json(-0e1));
                    CHECK(json::parser("-0E1").parse() == json(-0e1));
                    CHECK(json::parser("-0E123").parse() == json(-0e123));
                }

                SECTION("edge cases")
                {
                    // From RFC7159, Section 6:
                    // Note that when such software is used, numbers that are
                    // integers and are in the range [-(2**53)+1, (2**53)-1]
                    // are interoperable in the sense that implementations will
                    // agree exactly on their numeric values.

                    // -(2**53)+1
                    CHECK(json::parser("-9007199254740991").parse().get<int64_t>() == -9007199254740991);
                    // (2**53)-1
                    CHECK(json::parser("9007199254740991").parse().get<int64_t>() == 9007199254740991);
                }
            }

            SECTION("floating-point")
            {
                SECTION("without exponent")
                {
                    CHECK(json::parser("-128.5").parse() == json(-128.5));
                    CHECK(json::parser("0.999").parse() == json(0.999));
                    CHECK(json::parser("128.5").parse() == json(128.5));
                    CHECK(json::parser("-0.0").parse() == json(-0.0));
                }

                SECTION("with exponent")
                {
                    CHECK(json::parser("-128.5E3").parse() == json(-128.5E3));
                    CHECK(json::parser("-128.5E-3").parse() == json(-128.5E-3));
                    CHECK(json::parser("-0.0e1").parse() == json(-0.0e1));
                    CHECK(json::parser("-0.0E1").parse() == json(-0.0e1));
                }
            }

            SECTION("invalid numbers")
            {
                CHECK_THROWS_AS(json::parser("01").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("--1").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("1.").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("1E").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("1E-").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("1.E1").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-1E").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0E#").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0E-#").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0#").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0.0:").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0.0Z").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0E123:").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0e0-:").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0e-:").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0f").parse(), std::invalid_argument);
            }
        }
    }

    SECTION("parse errors")
    {
        // unexpected end of number
        CHECK_THROWS_AS(json::parser("0.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("-").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("--").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("-0.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("-.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("-:").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("0.:").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("e.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1e.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1e/").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1e:").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1E.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1E/").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1E:").parse(), std::invalid_argument);

        // unexpected end of null
        CHECK_THROWS_AS(json::parser("n").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("n").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("nu").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("nul").parse(), std::invalid_argument);

        // unexpected end of true
        CHECK_THROWS_AS(json::parser("t").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("t").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("tr").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("tru").parse(), std::invalid_argument);

        // unexpected end of false
        CHECK_THROWS_AS(json::parser("f").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("fa").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("fal").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("fals").parse(), std::invalid_argument);

        // unexpected end of array
        CHECK_THROWS_AS(json::parser("[").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("[1").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("[1,").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("[1,]").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("]").parse(), std::invalid_argument);

        // unexpected end of object
        CHECK_THROWS_AS(json::parser("{").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("{\"foo\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("{\"foo\":").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("{\"foo\":}").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("{\"foo\":1,}").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("}").parse(), std::invalid_argument);

        // unexpected end of string
        CHECK_THROWS_AS(json::parser("\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u0\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u01\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u012\"").parse(), std::invalid_argument);

        // invalid escapes
        for (int c = 1; c < 128; ++c)
        {
            auto s = std::string("\"\\") + std::string(1, c) + "\"";

            switch (c)
            {
                // valid escapes
                case ('"'):
                case ('\\'):
                case ('/'):
                case ('b'):
                case ('f'):
                case ('n'):
                case ('r'):
                case ('t'):
                {
                    CHECK_NOTHROW(json::parser(s).parse());
                    break;
                }

                // \u must be followed with four numbers, so we skip it here
                case ('u'):
                {
                    break;
                }

                // any other combination of backslash and character is invalid
                default:
                {
                    CHECK_THROWS_AS(json::parser(s).parse(), std::invalid_argument);
                    break;
                }
            }
        }

        // invalid \uxxxx escapes
        {
            // check whether character is a valid hex character
            const auto valid = [](int c)
            {
                switch (c)
                {
                    case ('0'):
                    case ('1'):
                    case ('2'):
                    case ('3'):
                    case ('4'):
                    case ('5'):
                    case ('6'):
                    case ('7'):
                    case ('8'):
                    case ('9'):
                    case ('a'):
                    case ('b'):
                    case ('c'):
                    case ('d'):
                    case ('e'):
                    case ('f'):
                    case ('A'):
                    case ('B'):
                    case ('C'):
                    case ('D'):
                    case ('E'):
                    case ('F'):
                    {
                        return true;
                    }

                    default:
                    {
                        return false;
                    }
                }
            };

            for (int c = 1; c < 128; ++c)
            {
                std::string s = "\"\\u";

                // create a string with the iterated character at each position
                auto s1 = s + "000" + std::string(1, c) + "\"";
                auto s2 = s + "00" + std::string(1, c) + "0\"";
                auto s3 = s + "0" + std::string(1, c) + "00\"";
                auto s4 = s + std::string(1, c) + "000\"";

                if (valid(c))
                {
                    CHECK_NOTHROW(json::parser(s1).parse());
                    CHECK_NOTHROW(json::parser(s2).parse());
                    CHECK_NOTHROW(json::parser(s3).parse());
                    CHECK_NOTHROW(json::parser(s4).parse());
                }
                else
                {
                    CHECK_THROWS_AS(json::parser(s1).parse(), std::invalid_argument);
                    CHECK_THROWS_AS(json::parser(s2).parse(), std::invalid_argument);
                    CHECK_THROWS_AS(json::parser(s3).parse(), std::invalid_argument);
                    CHECK_THROWS_AS(json::parser(s4).parse(), std::invalid_argument);
                }
            }
        }

        // missing part of a surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\""), std::invalid_argument);
        // invalid surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uD80C\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\u0000\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uFFFF\""), std::invalid_argument);
    }

    SECTION("callback function")
    {
        auto s_object = R"(
            {
                "foo": 2,
                "bar": {
                    "baz": 1
                }
            }
        )";

        auto s_array = R"(
            [1,2,[3,4,5],4,5]
        )";

        SECTION("filter nothing")
        {
            json j_object = json::parse(s_object, [](int, json::parse_event_t, const json&)
            {
                return true;
            });

            CHECK (j_object == json({{"foo", 2}, {"bar", {{"baz", 1}}}}));

            json j_array = json::parse(s_array, [](int, json::parse_event_t, const json&)
            {
                return true;
            });

            CHECK (j_array == json({1, 2, {3, 4, 5}, 4, 5}));
        }

        SECTION("filter everything")
        {
            json j_object = json::parse(s_object, [](int, json::parse_event_t, const json&)
            {
                return false;
            });

            // the top-level object will be discarded, leaving a null
            CHECK (j_object.is_null());

            json j_array = json::parse(s_array, [](int, json::parse_event_t, const json&)
            {
                return false;
            });

            // the top-level array will be discarded, leaving a null
            CHECK (j_array.is_null());
        }

        SECTION("filter specific element")
        {
            json j_object = json::parse(s_object, [](int, json::parse_event_t, const json & j)
            {
                // filter all number(2) elements
                if (j == json(2))
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });

            CHECK (j_object == json({{"bar", {{"baz", 1}}}}));

            json j_array = json::parse(s_array, [](int, json::parse_event_t, const json & j)
            {
                if (j == json(2))
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });

            CHECK (j_array == json({1, {3, 4, 5}, 4, 5}));
        }

        SECTION("filter specific events")
        {
            SECTION("first closing event")
            {
                {
                    json j_object = json::parse(s_object, [](int, json::parse_event_t e, const json&)
                    {
                        static bool first = true;
                        if (e == json::parse_event_t::object_end and first)
                        {
                            first = false;
                            return false;
                        }
                        else
                        {
                            return true;
                        }
                    });

                    // the first completed object will be discarded
                    CHECK (j_object == json({{"foo", 2}}));
                }

                {
                    json j_array = json::parse(s_array, [](int, json::parse_event_t e, const json&)
                    {
                        static bool first = true;
                        if (e == json::parse_event_t::array_end and first)
                        {
                            first = false;
                            return false;
                        }
                        else
                        {
                            return true;
                        }
                    });

                    // the first completed array will be discarded
                    CHECK (j_array == json({1, 2, 4, 5}));
                }
            }
        }

        SECTION("special cases")
        {
            // the following test cases cover the situation in which an empty
            // object and array is discarded only after the closing character
            // has been read

            json j_empty_object = json::parse("{}", [](int, json::parse_event_t e, const json&)
            {
                if (e == json::parse_event_t::object_end)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });
            CHECK(j_empty_object == json());

            json j_empty_array = json::parse("[]", [](int, json::parse_event_t e, const json&)
            {
                if (e == json::parse_event_t::array_end)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });
            CHECK(j_empty_array == json());
        }
    }
}

TEST_CASE("README", "[hide]")
{
    {
        // create an empty structure (null)
        json j;

        // add a number that is stored as double (note the implicit conversion of j to an object)
        j["pi"] = 3.141;

        // add a Boolean that is stored as bool
        j["happy"] = true;

        // add a string that is stored as std::string
        j["name"] = "Niels";

        // add another null object by passing nullptr
        j["nothing"] = nullptr;

        // add an object inside the object
        j["answer"]["everything"] = 42;

        // add an array that is stored as std::vector (using an initializer list)
        j["list"] = { 1, 0, 2 };

        // add another object (using an initializer list of pairs)
        j["object"] = { {"currency", "USD"}, {"value", 42.99} };

        // instead, you could also write (which looks very similar to the JSON above)
        json j2 =
        {
            {"pi", 3.141},
            {"happy", true},
            {"name", "Niels"},
            {"nothing", nullptr},
            {
                "answer", {
                    {"everything", 42}
                }
            },
            {"list", {1, 0, 2}},
            {
                "object", {
                    {"currency", "USD"},
                    {"value", 42.99}
                }
            }
        };
    }

    {
        // ways to express the empty array []
        json empty_array_implicit = {{}};
        json empty_array_explicit = json::array();

        // a way to express the empty object {}
        json empty_object_explicit = json::object();

        // a way to express an _array_ of key/value pairs [["currency", "USD"], ["value", 42.99]]
        json array_not_object = { json::array({"currency", "USD"}), json::array({"value", 42.99}) };
    }

    {
        // create object from string literal
        json j = "{ \"happy\": true, \"pi\": 3.141 }"_json;

        // or even nicer (thanks http://isocpp.org/blog/2015/01/json-for-modern-cpp)
        auto j2 = R"(
          {
            "happy": true,
            "pi": 3.141
          }
        )"_json;

        // or explicitly
        auto j3 = json::parse("{ \"happy\": true, \"pi\": 3.141 }");

        // explicit conversion to string
        std::string s = j.dump();    // {\"happy\":true,\"pi\":3.141}

        // serialization with pretty printing
        // pass in the amount of spaces to indent
        std::cout << j.dump(4) << std::endl;
        // {
        //     "happy": true,
        //     "pi": 3.141
        // }

        std::cout << std::setw(2) << j << std::endl;
    }

    {
        // create an array using push_back
        json j;
        j.push_back("foo");
        j.push_back(1);
        j.push_back(true);

        // iterate the array
        for (json::iterator it = j.begin(); it != j.end(); ++it)
        {
            std::cout << *it << '\n';
        }

        // range-based for
        for (auto element : j)
        {
            std::cout << element << '\n';
        }

        // getter/setter
        const std::string tmp = j[0];
        j[1] = 42;
        bool foo = j.at(2);

        // other stuff
        j.size();     // 3 entries
        j.empty();    // false
        j.type();     // json::value_t::array
        j.clear();    // the array is empty again

        // comparison
        j == "[\"foo\", 1, true]"_json;  // true

        // create an object
        json o;
        o["foo"] = 23;
        o["bar"] = false;
        o["baz"] = 3.141;

        // find an entry
        if (o.find("foo") != o.end())
        {
            // there is an entry with key "foo"
        }
    }

    {
        std::vector<int> c_vector {1, 2, 3, 4};
        json j_vec(c_vector);
        // [1, 2, 3, 4]

        std::deque<float> c_deque {1.2f, 2.3f, 3.4f, 5.6f};
        json j_deque(c_deque);
        // [1.2, 2.3, 3.4, 5.6]

        std::list<bool> c_list {true, true, false, true};
        json j_list(c_list);
        // [true, true, false, true]

        std::forward_list<int64_t> c_flist {12345678909876, 23456789098765, 34567890987654, 45678909876543};
        json j_flist(c_flist);
        // [12345678909876, 23456789098765, 34567890987654, 45678909876543]

        std::array<unsigned long, 4> c_array {{1, 2, 3, 4}};
        json j_array(c_array);
        // [1, 2, 3, 4]

        std::set<std::string> c_set {"one", "two", "three", "four", "one"};
        json j_set(c_set); // only one entry for "one" is used
        // ["four", "one", "three", "two"]

        std::unordered_set<std::string> c_uset {"one", "two", "three", "four", "one"};
        json j_uset(c_uset); // only one entry for "one" is used
        // maybe ["two", "three", "four", "one"]

        std::multiset<std::string> c_mset {"one", "two", "one", "four"};
        json j_mset(c_mset); // only one entry for "one" is used
        // maybe ["one", "two", "four"]

        std::unordered_multiset<std::string> c_umset {"one", "two", "one", "four"};
        json j_umset(c_umset); // both entries for "one" are used
        // maybe ["one", "two", "one", "four"]
    }

    {
        std::map<std::string, int> c_map { {"one", 1}, {"two", 2}, {"three", 3} };
        json j_map(c_map);
        // {"one": 1, "two": 2, "three": 3}

        std::unordered_map<const char*, float> c_umap { {"one", 1.2f}, {"two", 2.3f}, {"three", 3.4f} };
        json j_umap(c_umap);
        // {"one": 1.2, "two": 2.3, "three": 3.4}

        std::multimap<std::string, bool> c_mmap { {"one", true}, {"two", true}, {"three", false}, {"three", true} };
        json j_mmap(c_mmap); // only one entry for key "three" is used
        // maybe {"one": true, "two": true, "three": true}

        std::unordered_multimap<std::string, bool> c_ummap { {"one", true}, {"two", true}, {"three", false}, {"three", true} };
        json j_ummap(c_ummap); // only one entry for key "three" is used
        // maybe {"one": true, "two": true, "three": true}
    }

    {
        /// strings
        std::string s1 = "Hello, world!";
        json js = s1;
        std::string s2 = js;

        // Booleans
        bool b1 = true;
        json jb = b1;
        bool b2 = jb;

        // numbers
        int i = 42;
        json jn = i;
        double f = jn;

        // etc.

        std::string vs = js.get<std::string>();
        bool vb = jb.get<bool>();
        int vi = jn.get<int>();

        // etc.
    }
}

TEST_CASE("algorithms")
{
    json j_array = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz"};
    json j_object = {{"one", 1}, {"two", 2}};

    SECTION("non-modifying sequence operations")
    {
        SECTION("std::all_of")
        {
            CHECK(std::all_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return value.size() > 0;
            }));
            CHECK(std::all_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.type() == json::value_t::number_integer;
            }));
        }

        SECTION("std::any_of")
        {
            CHECK(std::any_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return value.is_string() and value.get<std::string>() == "foo";
            }));
            CHECK(std::any_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.get<int>() > 1;
            }));
        }

        SECTION("std::none_of")
        {
            CHECK(std::none_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return value.size() == 0;
            }));
            CHECK(std::none_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.get<int>() <= 0;
            }));
        }

        SECTION("std::for_each")
        {
            SECTION("reading")
            {
                int sum = 0;

                std::for_each(j_array.cbegin(), j_array.cend(), [&sum](const json & value)
                {
                    if (value.is_number())
                    {
                        sum += static_cast<int>(value);
                    }
                });

                CHECK(sum == 45);
            }

            SECTION("writing")
            {
                auto add17 = [](json & value)
                {
                    if (value.is_array())
                    {
                        value.push_back(17);
                    }
                };

                std::for_each(j_array.begin(), j_array.end(), add17);

                CHECK(j_array[6] == json({1, 2, 3, 17}));
            }
        }

        SECTION("std::count")
        {
            CHECK(std::count(j_array.begin(), j_array.end(), json(true)) == 1);
        }

        SECTION("std::count_if")
        {
            CHECK(std::count_if(j_array.begin(), j_array.end(), [](const json & value)
            {
                return (value.is_number());
            }) == 3);
            CHECK(std::count_if(j_array.begin(), j_array.end(), [](const json&)
            {
                return true;
            }) == 9);
        }

        SECTION("std::mismatch")
        {
            json j_array2 = {13, 29, 3, {{"one", 1}, {"two", 2}, {"three", 3}}, true, false, {1, 2, 3}, "foo", "baz"};
            auto res = std::mismatch(j_array.begin(), j_array.end(), j_array2.begin());
            CHECK(*res.first == json({{"one", 1}, {"two", 2}}));
            CHECK(*res.second == json({{"one", 1}, {"two", 2}, {"three", 3}}));
        }

        SECTION("std::equal")
        {
            SECTION("using operator==")
            {
                CHECK(std::equal(j_array.begin(), j_array.end(), j_array.begin()));
                CHECK(std::equal(j_object.begin(), j_object.end(), j_object.begin()));
                CHECK(not std::equal(j_array.begin(), j_array.end(), j_object.begin()));
            }

            SECTION("using user-defined comparison")
            {
                // compare objects only by size of its elements
                json j_array2 = {13, 29, 3, {"Hello", "World"}, true, false, {{"one", 1}, {"two", 2}, {"three", 3}}, "foo", "baz"};
                CHECK(not std::equal(j_array.begin(), j_array.end(), j_array2.begin()));
                CHECK(std::equal(j_array.begin(), j_array.end(), j_array2.begin(),
                                 [](const json & a, const json & b)
                {
                    return (a.size() == b.size());
                }));
            }
        }

        SECTION("std::find")
        {
            auto it = std::find(j_array.begin(), j_array.end(), json(false));
            CHECK(std::distance(j_array.begin(), it) == 5);
        }

        SECTION("std::find_if")
        {
            auto it = std::find_if(j_array.begin(), j_array.end(),
                                   [](const json & value)
            {
                return value.is_boolean();
            });
            CHECK(std::distance(j_array.begin(), it) == 4);
        }

        SECTION("std::find_if_not")
        {
            auto it = std::find_if_not(j_array.begin(), j_array.end(),
                                       [](const json & value)
            {
                return value.is_number();
            });
            CHECK(std::distance(j_array.begin(), it) == 3);
        }

        SECTION("std::adjacent_find")
        {
            CHECK(std::adjacent_find(j_array.begin(), j_array.end()) == j_array.end());
            CHECK(std::adjacent_find(j_array.begin(), j_array.end(),
                                     [](const json & v1, const json & v2)
            {
                return v1.type() == v2.type();
            }) == j_array.begin());
        }
    }

    SECTION("modifying sequence operations")
    {
        SECTION("std::reverse")
        {
            std::reverse(j_array.begin(), j_array.end());
            CHECK(j_array == json({"baz", "foo", {1, 2, 3}, false, true, {{"one", 1}, {"two", 2}}, 3, 29, 13}));
        }

        SECTION("std::rotate")
        {
            std::rotate(j_array.begin(), j_array.begin() + 1, j_array.end());
            CHECK(j_array == json({29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", 13}));
        }

        SECTION("std::partition")
        {
            auto it = std::partition(j_array.begin(), j_array.end(), [](const json & v)
            {
                return v.is_string();
            });
            CHECK(std::distance(j_array.begin(), it) == 2);
            CHECK(not it[2].is_string());
        }
    }

    SECTION("sorting operations")
    {
        SECTION("std::sort")
        {
            SECTION("with standard comparison")
            {
                json j = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", nullptr};
                std::sort(j.begin(), j.end());
                CHECK(j == json({nullptr, false, true, 3, 13, 29, {{"one", 1}, {"two", 2}}, {1, 2, 3}, "baz", "foo"}));
            }

            SECTION("with user-defined comparison")
            {
                json j = {3, {{"one", 1}, {"two", 2}}, {1, 2, 3}, nullptr};
                std::sort(j.begin(), j.end(), [](const json & a, const json & b)
                {
                    return a.size() < b.size();
                });
                CHECK(j == json({nullptr, 3, {{"one", 1}, {"two", 2}}, {1, 2, 3}}));
            }

            SECTION("sorting an object")
            {
                json j({{"one", 1}, {"two", 2}});
                CHECK_THROWS_AS(std::sort(j.begin(), j.end()), std::domain_error);
            }
        }

        SECTION("std::partial_sort")
        {
            json j = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", nullptr};
            std::partial_sort(j.begin(), j.begin() + 4, j.end());
            CHECK(j == json({nullptr, false, true, 3, {{"one", 1}, {"two", 2}}, 29, {1, 2, 3}, "foo", "baz", 13}));
        }
    }

    SECTION("set operations")
    {
        SECTION("std::merge")
        {
            {
                json j1 = {2, 4, 6, 8};
                json j2 = {1, 2, 3, 5, 7};
                json j3;

                std::merge(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
                CHECK(j3 == json({1, 2, 2, 3, 4, 5, 6, 7, 8}));
            }
        }

        SECTION("std::set_difference")
        {
            json j1 = {1, 2, 3, 4, 5, 6, 7, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            std::set_difference(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
            CHECK(j3 == json({4, 6, 8}));
        }

        SECTION("std::set_intersection")
        {
            json j1 = {1, 2, 3, 4, 5, 6, 7, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            std::set_intersection(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
            CHECK(j3 == json({1, 2, 3, 5, 7}));
        }

        SECTION("std::set_union")
        {
            json j1 = {2, 4, 6, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            std::set_union(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
            CHECK(j3 == json({1, 2, 3, 4, 5, 6, 7, 8}));
        }

        SECTION("std::set_symmetric_difference")
        {
            json j1 = {2, 4, 6, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            std::set_symmetric_difference(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
            CHECK(j3 == json({1, 3, 4, 5, 6, 7, 8}));
        }
    }

    SECTION("heap operations")
    {
        std::make_heap(j_array.begin(), j_array.end());
        CHECK(std::is_heap(j_array.begin(), j_array.end()));
        std::sort_heap(j_array.begin(), j_array.end());
        CHECK(j_array == json({false, true, 3, 13, 29, {{"one", 1}, {"two", 2}}, {1, 2, 3}, "baz", "foo"}));
    }
}

TEST_CASE("concepts")
{
    SECTION("container requirements for json")
    {
        // X: container class: json
        // T: type of objects: json
        // a, b: values of type X: json

        // TABLE 96 - Container Requirements

        // X::value_type must return T
        CHECK((std::is_same<json::value_type, json>::value));

        // X::reference must return lvalue of T
        CHECK((std::is_same<json::reference, json&>::value));

        // X::const_reference must return const lvalue of T
        CHECK((std::is_same<json::const_reference, const json&>::value));

        // X::iterator must return iterator whose value_type is T
        CHECK((std::is_same<json::iterator::value_type, json>::value));
        // X::iterator must meet the forward iterator requirements
        CHECK((std::is_base_of<std::forward_iterator_tag, typename std::iterator_traits<json::iterator>::iterator_category>::value));
        // X::iterator must be convertible to X::const_iterator
        CHECK((std::is_convertible<json::iterator, json::const_iterator>::value));

        // X::const_iterator must return iterator whose value_type is T
        CHECK((std::is_same<json::const_iterator::value_type, json>::value));
        // X::const_iterator must meet the forward iterator requirements
        CHECK((std::is_base_of<std::forward_iterator_tag, typename std::iterator_traits<json::const_iterator>::iterator_category>::value));

        // X::difference_type must return a signed integer
        CHECK((std::is_signed<json::difference_type>::value));
        // X::difference_type must be identical to X::iterator::difference_type
        CHECK((std::is_same<json::difference_type, json::iterator::difference_type>::value));
        // X::difference_type must be identical to X::const_iterator::difference_type
        CHECK((std::is_same<json::difference_type, json::const_iterator::difference_type>::value));

        // X::size_type must return an unsigned integer
        CHECK((std::is_unsigned<json::size_type>::value));
        // X::size_type can represent any non-negative value of X::difference_type
        CHECK(std::numeric_limits<json::difference_type>::max() <=
              std::numeric_limits<json::size_type>::max());

        // the expression "X u" has the post-condition "u.empty()"
        {
            json u;
            CHECK(u.empty());
        }

        // the expression "X()" has the post-condition "X().empty()"
        CHECK(json().empty());
    }

    SECTION("class json")
    {
        SECTION("DefaultConstructible")
        {
            CHECK(std::is_nothrow_default_constructible<json>::value);
        }

        SECTION("MoveConstructible")
        {
            CHECK(std::is_nothrow_move_constructible<json>::value);
        }

        SECTION("CopyConstructible")
        {
            CHECK(std::is_copy_constructible<json>::value);
        }

        SECTION("MoveAssignable")
        {
            CHECK(std::is_nothrow_move_assignable<json>::value);
        }

        SECTION("CopyAssignable")
        {
            CHECK(std::is_copy_assignable<json>::value);
        }

        SECTION("Destructible")
        {
            CHECK(std::is_nothrow_destructible<json>::value);
        }

        SECTION("StandardLayoutType")
        {
            CHECK(std::is_standard_layout<json>::value);
        }
    }

    SECTION("class iterator")
    {
        SECTION("CopyConstructible")
        {
            CHECK(std::is_nothrow_copy_constructible<json::iterator>::value);
            CHECK(std::is_nothrow_copy_constructible<json::const_iterator>::value);
        }

        SECTION("CopyAssignable")
        {
            CHECK(std::is_nothrow_copy_assignable<json::iterator>::value);
            CHECK(std::is_nothrow_copy_assignable<json::const_iterator>::value);
        }

        SECTION("Destructible")
        {
            CHECK(std::is_nothrow_destructible<json::iterator>::value);
            CHECK(std::is_nothrow_destructible<json::const_iterator>::value);
        }

        SECTION("Swappable")
        {
            {
                json j {1, 2, 3};
                json::iterator it1 = j.begin();
                json::iterator it2 = j.end();
                std::swap(it1, it2);
                CHECK(it1 == j.end());
                CHECK(it2 == j.begin());
            }
            {
                json j {1, 2, 3};
                json::const_iterator it1 = j.cbegin();
                json::const_iterator it2 = j.cend();
                std::swap(it1, it2);
                CHECK(it1 == j.end());
                CHECK(it2 == j.begin());
            }
        }
    }
}

TEST_CASE("iterator_wrapper")
{
    SECTION("object")
    {
        SECTION("value")
        {
            json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const value")
        {
            json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("array")
    {
        SECTION("value")
        {
            json j = {"A", "B"};
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            json j = {"A", "B"};
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const value")
        {
            json j = {"A", "B"};
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            json j = {"A", "B"};
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("primitive")
    {
        SECTION("value")
        {
            json j = 1;
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("reference")
        {
            json j = 1;
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("const value")
        {
            json j = 1;
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("reference")
        {
            json j = 1;
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }
    }
}

TEST_CASE("compliance tests from json.org")
{
    // test cases are from http://json.org/JSON_checker/

    SECTION("expected failures")
    {
        for (auto filename :
                {
                    //"test/json_tests/fail1.json",
                    "test/json_tests/fail2.json",
                    "test/json_tests/fail3.json",
                    "test/json_tests/fail4.json",
                    "test/json_tests/fail5.json",
                    "test/json_tests/fail6.json",
                    "test/json_tests/fail7.json",
                    "test/json_tests/fail8.json",
                    "test/json_tests/fail9.json",
                    "test/json_tests/fail10.json",
                    "test/json_tests/fail11.json",
                    "test/json_tests/fail12.json",
                    "test/json_tests/fail13.json",
                    "test/json_tests/fail14.json",
                    "test/json_tests/fail15.json",
                    "test/json_tests/fail16.json",
                    "test/json_tests/fail17.json",
                    //"test/json_tests/fail18.json",
                    "test/json_tests/fail19.json",
                    "test/json_tests/fail20.json",
                    "test/json_tests/fail21.json",
                    "test/json_tests/fail22.json",
                    "test/json_tests/fail23.json",
                    "test/json_tests/fail24.json",
                    "test/json_tests/fail25.json",
                    "test/json_tests/fail26.json",
                    "test/json_tests/fail27.json",
                    "test/json_tests/fail28.json",
                    "test/json_tests/fail29.json",
                    "test/json_tests/fail30.json",
                    "test/json_tests/fail31.json",
                    "test/json_tests/fail32.json",
                    "test/json_tests/fail33.json"
                })
        {
            CAPTURE(filename);
            json j;
            std::ifstream f(filename);
            CHECK_THROWS_AS(j << f, std::invalid_argument);
        }
    }

    SECTION("expected passes")
    {
        for (auto filename :
                {
                    "test/json_tests/pass1.json",
                    "test/json_tests/pass2.json",
                    "test/json_tests/pass3.json"
                })
        {
            CAPTURE(filename);
            json j;
            std::ifstream f(filename);
            CHECK_NOTHROW(j << f);
        }
    }
}

TEST_CASE("compliance tests from nativejson-benchmark")
{
    // test cases from https://github.com/miloyip/nativejson-benchmark/blob/master/src/main.cpp

    SECTION("doubles")
    {
        auto TEST_DOUBLE = [](const std::string & json_string, const double expected)
        {
            CAPTURE(json_string);
            CAPTURE(expected);
            CHECK(json::parse(json_string)[0].get<double>() == Approx(expected));
        };

        TEST_DOUBLE("[0.0]", 0.0);
        TEST_DOUBLE("[-0.0]", -0.0);
        TEST_DOUBLE("[1.0]", 1.0);
        TEST_DOUBLE("[-1.0]", -1.0);
        TEST_DOUBLE("[1.5]", 1.5);
        TEST_DOUBLE("[-1.5]", -1.5);
        TEST_DOUBLE("[3.1416]", 3.1416);
        TEST_DOUBLE("[1E10]", 1E10);
        TEST_DOUBLE("[1e10]", 1e10);
        TEST_DOUBLE("[1E+10]", 1E+10);
        TEST_DOUBLE("[1E-10]", 1E-10);
        TEST_DOUBLE("[-1E10]", -1E10);
        TEST_DOUBLE("[-1e10]", -1e10);
        TEST_DOUBLE("[-1E+10]", -1E+10);
        TEST_DOUBLE("[-1E-10]", -1E-10);
        TEST_DOUBLE("[1.234E+10]", 1.234E+10);
        TEST_DOUBLE("[1.234E-10]", 1.234E-10);
        TEST_DOUBLE("[1.79769e+308]", 1.79769e+308);
        TEST_DOUBLE("[2.22507e-308]", 2.22507e-308);
        TEST_DOUBLE("[-1.79769e+308]", -1.79769e+308);
        TEST_DOUBLE("[-2.22507e-308]", -2.22507e-308);
        TEST_DOUBLE("[4.9406564584124654e-324]", 4.9406564584124654e-324); // minimum denormal
        TEST_DOUBLE("[2.2250738585072009e-308]", 2.2250738585072009e-308); // Max subnormal double
        TEST_DOUBLE("[2.2250738585072014e-308]", 2.2250738585072014e-308); // Min normal positive double
        TEST_DOUBLE("[1.7976931348623157e+308]", 1.7976931348623157e+308); // Max double
        TEST_DOUBLE("[1e-10000]", 0.0);                                   // must underflow
        TEST_DOUBLE("[18446744073709551616]",
                    18446744073709551616.0);    // 2^64 (max of uint64_t + 1, force to use double)
        TEST_DOUBLE("[-9223372036854775809]",
                    -9223372036854775809.0);    // -2^63 - 1(min of int64_t + 1, force to use double)
        TEST_DOUBLE("[0.9868011474609375]",
                    0.9868011474609375);          // https://github.com/miloyip/rapidjson/issues/120
        TEST_DOUBLE("[123e34]", 123e34);                                  // Fast Path Cases In Disguise
        TEST_DOUBLE("[45913141877270640000.0]", 45913141877270640000.0);
        TEST_DOUBLE("[2.2250738585072011e-308]",
                    2.2250738585072011e-308);
        //TEST_DOUBLE("[1e-00011111111111]", 0.0);
        //TEST_DOUBLE("[-1e-00011111111111]", -0.0);
        TEST_DOUBLE("[1e-214748363]", 0.0);
        TEST_DOUBLE("[1e-214748364]", 0.0);
        //TEST_DOUBLE("[1e-21474836311]", 0.0);
        TEST_DOUBLE("[0.017976931348623157e+310]", 1.7976931348623157e+308); // Max double in another form

        // Since
        // abs((2^-1022 - 2^-1074) - 2.2250738585072012e-308) = 3.109754131239141401123495768877590405345064751974375599... ¡Á 10^-324
        // abs((2^-1022) - 2.2250738585072012e-308) = 1.830902327173324040642192159804623318305533274168872044... ¡Á 10 ^ -324
        // So 2.2250738585072012e-308 should round to 2^-1022 = 2.2250738585072014e-308
        TEST_DOUBLE("[2.2250738585072012e-308]",
                    2.2250738585072014e-308);

        // More closer to normal/subnormal boundary
        // boundary = 2^-1022 - 2^-1075 = 2.225073858507201136057409796709131975934819546351645648... ¡Á 10^-308
        TEST_DOUBLE("[2.22507385850720113605740979670913197593481954635164564e-308]",
                    2.2250738585072009e-308);
        TEST_DOUBLE("[2.22507385850720113605740979670913197593481954635164565e-308]",
                    2.2250738585072014e-308);

        // 1.0 is in (1.0 - 2^-54, 1.0 + 2^-53)
        // 1.0 - 2^-54 = 0.999999999999999944488848768742172978818416595458984375
        TEST_DOUBLE("[0.999999999999999944488848768742172978818416595458984375]", 1.0); // round to even
        TEST_DOUBLE("[0.999999999999999944488848768742172978818416595458984374]",
                    0.99999999999999989); // previous double
        TEST_DOUBLE("[0.999999999999999944488848768742172978818416595458984376]", 1.0); // next double
        // 1.0 + 2^-53 = 1.00000000000000011102230246251565404236316680908203125
        TEST_DOUBLE("[1.00000000000000011102230246251565404236316680908203125]", 1.0); // round to even
        TEST_DOUBLE("[1.00000000000000011102230246251565404236316680908203124]", 1.0); // previous double
        TEST_DOUBLE("[1.00000000000000011102230246251565404236316680908203126]",
                    1.00000000000000022); // next double

        // Numbers from https://github.com/floitsch/double-conversion/blob/master/test/cctest/test-strtod.cc

        TEST_DOUBLE("[72057594037927928.0]", 72057594037927928.0);
        TEST_DOUBLE("[72057594037927936.0]", 72057594037927936.0);
        TEST_DOUBLE("[72057594037927932.0]", 72057594037927936.0);
        TEST_DOUBLE("[7205759403792793199999e-5]", 72057594037927928.0);
        TEST_DOUBLE("[7205759403792793200001e-5]", 72057594037927936.0);

        TEST_DOUBLE("[9223372036854774784.0]", 9223372036854774784.0);
        TEST_DOUBLE("[9223372036854775808.0]", 9223372036854775808.0);
        TEST_DOUBLE("[9223372036854775296.0]", 9223372036854775808.0);
        TEST_DOUBLE("[922337203685477529599999e-5]", 9223372036854774784.0);
        TEST_DOUBLE("[922337203685477529600001e-5]", 9223372036854775808.0);

        TEST_DOUBLE("[10141204801825834086073718800384]", 10141204801825834086073718800384.0);
        TEST_DOUBLE("[10141204801825835211973625643008]", 10141204801825835211973625643008.0);
        TEST_DOUBLE("[10141204801825834649023672221696]", 10141204801825835211973625643008.0);
        TEST_DOUBLE("[1014120480182583464902367222169599999e-5]", 10141204801825834086073718800384.0);
        TEST_DOUBLE("[1014120480182583464902367222169600001e-5]", 10141204801825835211973625643008.0);

        TEST_DOUBLE("[5708990770823838890407843763683279797179383808]",
                    5708990770823838890407843763683279797179383808.0);
        TEST_DOUBLE("[5708990770823839524233143877797980545530986496]",
                    5708990770823839524233143877797980545530986496.0);
        TEST_DOUBLE("[5708990770823839207320493820740630171355185152]",
                    5708990770823839524233143877797980545530986496.0);
        TEST_DOUBLE("[5708990770823839207320493820740630171355185151999e-3]",
                    5708990770823838890407843763683279797179383808.0);
        TEST_DOUBLE("[5708990770823839207320493820740630171355185152001e-3]",
                    5708990770823839524233143877797980545530986496.0);

        {
            char n1e308[312];   // '1' followed by 308 '0'
            n1e308[0] = '[';
            n1e308[1] = '1';
            for (int j = 2; j < 310; j++)
            {
                n1e308[j] = '0';
            }
            n1e308[310] = ']';
            n1e308[311] = '\0';
            TEST_DOUBLE(n1e308, 1E308);
        }

        // Cover trimming
        TEST_DOUBLE(
            "[2.22507385850720113605740979670913197593481954635164564802342610972482222202107694551652952390813508"
            "7914149158913039621106870086438694594645527657207407820621743379988141063267329253552286881372149012"
            "9811224514518898490572223072852551331557550159143974763979834118019993239625482890171070818506906306"
            "6665599493827577257201576306269066333264756530000924588831643303777979186961204949739037782970490505"
            "1080609940730262937128958950003583799967207254304360284078895771796150945516748243471030702609144621"
            "5722898802581825451803257070188608721131280795122334262883686223215037756666225039825343359745688844"
            "2390026549819838548794829220689472168983109969836584681402285424333066033985088644580400103493397042"
            "7567186443383770486037861622771738545623065874679014086723327636718751234567890123456789012345678901"
            "e-308]",
            2.2250738585072014e-308);
    }

    SECTION("strings")
    {
        auto TEST_STRING = [](const std::string & json_string, const std::string & expected)
        {
            CAPTURE(json_string);
            CAPTURE(expected);
            CHECK(json::parse(json_string)[0].get<std::string>() == expected);
        };

        TEST_STRING("[\"\"]", "");
        TEST_STRING("[\"Hello\"]", "Hello");
        TEST_STRING("[\"Hello\\nWorld\"]", "Hello\nWorld");
        //TEST_STRING("[\"Hello\\u0000World\"]", "Hello\0World");
        TEST_STRING("[\"\\\"\\\\/\\b\\f\\n\\r\\t\"]", "\"\\/\b\f\n\r\t");
        TEST_STRING("[\"\\u0024\"]", "\x24");         // Dollar sign U+0024
        TEST_STRING("[\"\\u00A2\"]", "\xC2\xA2");     // Cents sign U+00A2
        TEST_STRING("[\"\\u20AC\"]", "\xE2\x82\xAC"); // Euro sign U+20AC
        TEST_STRING("[\"\\uD834\\uDD1E\"]", "\xF0\x9D\x84\x9E");  // G clef sign U+1D11E
    }

    SECTION("roundtrip")
    {
        // test cases are from https://github.com/miloyip/nativejson-benchmark/tree/master/data/roundtrip

        for (auto filename :
                {
                    "test/json_roundtrip/roundtrip01.json",
                    "test/json_roundtrip/roundtrip02.json",
                    "test/json_roundtrip/roundtrip03.json",
                    "test/json_roundtrip/roundtrip04.json",
                    "test/json_roundtrip/roundtrip05.json",
                    "test/json_roundtrip/roundtrip06.json",
                    "test/json_roundtrip/roundtrip07.json",
                    "test/json_roundtrip/roundtrip08.json",
                    "test/json_roundtrip/roundtrip09.json",
                    "test/json_roundtrip/roundtrip10.json",
                    "test/json_roundtrip/roundtrip11.json",
                    "test/json_roundtrip/roundtrip12.json",
                    //"test/json_roundtrip/roundtrip13.json",
                    "test/json_roundtrip/roundtrip14.json",
                    "test/json_roundtrip/roundtrip15.json",
                    "test/json_roundtrip/roundtrip16.json",
                    "test/json_roundtrip/roundtrip17.json",
                    //"test/json_roundtrip/roundtrip18.json",
                    //"test/json_roundtrip/roundtrip19.json",
                    //"test/json_roundtrip/roundtrip20.json",
                    //"test/json_roundtrip/roundtrip21.json",
                    "test/json_roundtrip/roundtrip22.json",
                    "test/json_roundtrip/roundtrip23.json",
                    //"test/json_roundtrip/roundtrip24.json",
                    //"test/json_roundtrip/roundtrip25.json",
                    //"test/json_roundtrip/roundtrip26.json",
                    //"test/json_roundtrip/roundtrip27.json"
                })
        {
            CAPTURE(filename);
            std::ifstream f(filename);
            std::string json_string( (std::istreambuf_iterator<char>(f) ),
                                     (std::istreambuf_iterator<char>()) );

            json j = json::parse(json_string);
            CHECK(j.dump() == json_string);
        }
    }
}

TEST_CASE("test suite from json-test-suite")
{
    SECTION("read all sample.json")
    {
        // read a file with all unicode characters stored as single-character
        // strings in a JSON array
        std::ifstream f("test/json_testsuite/sample.json");
        json j;
        CHECK_NOTHROW(j << f);

        // the array has 3 elements
        CHECK(j.size() == 3);
    }
}

TEST_CASE("json.org examples")
{
    // here, we list all JSON values from http://json.org/example

    SECTION("1.json")
    {
        std::ifstream f("test/json.org/1.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("2.json")
    {
        std::ifstream f("test/json.org/2.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("3.json")
    {
        std::ifstream f("test/json.org/3.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("4.json")
    {
        std::ifstream f("test/json.org/4.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("5.json")
    {
        std::ifstream f("test/json.org/5.json");
        json j;
        CHECK_NOTHROW(j << f);
    }
}

TEST_CASE("RFC 7159 examples")
{
    // here, we list all JSON values from the RFC 7159 document

    SECTION("7. Strings")
    {
        CHECK(json::parse("\"\\u005C\"") == json("\\"));
        CHECK(json::parse("\"\\uD834\\uDD1E\"") == json("𝄞"));
        CHECK(json::parse("\"𝄞\"") == json("𝄞"));
    }

    SECTION("8.3 String Comparison")
    {
        CHECK(json::parse("\"a\\b\"") == json::parse("\"a\u005Cb\""));
    }

    SECTION("13 Examples")
    {
        {
            CHECK_NOTHROW(json(R"(
            {
                 "Image": {
                     "Width":  800,
                     "Height": 600,
                     "Title":  "View from 15th Floor",
                     "Thumbnail": {
                         "Url":    "http://www.example.com/image/481989943",
                         "Height": 125,
                         "Width":  100
                     },
                     "Animated" : false,
                     "IDs": [116, 943, 234, 38793]
                   }
               }
            )"));
        }

        {
            CHECK_NOTHROW(json(R"(
                [
                    {
                       "precision": "zip",
                       "Latitude":  37.7668,
                       "Longitude": -122.3959,
                       "Address":   "",
                       "City":      "SAN FRANCISCO",
                       "State":     "CA",
                       "Zip":       "94107",
                       "Country":   "US"
                    },
                    {
                       "precision": "zip",
                       "Latitude":  37.371991,
                       "Longitude": -122.026020,
                       "Address":   "",
                       "City":      "SUNNYVALE",
                       "State":     "CA",
                       "Zip":       "94085",
                       "Country":   "US"
                    }
            ])"));
        }

        CHECK(json::parse("\"Hello world!\"") == json("Hello world!"));
        CHECK(json::parse("42") == json(42));
        CHECK(json::parse("true") == json(true));
    }
}

TEST_CASE("Unicode", "[hide]")
{
    SECTION("full enumeration of Unicode codepoints")
    {
        // create a string from a codepoint
        auto codepoint_to_unicode = [](std::size_t cp)
        {
            char* buffer = new char[10];
            sprintf(buffer, "\\u%04lx", cp);
            std::string result(buffer);
            delete[] buffer;
            return result;
        };

        // generate all codepoints
        for (std::size_t cp = 0; cp <= 0x10FFFFu; ++cp)
        {
            // The Unicode standard permanently reserves these code point
            // values for UTF-16 encoding of the high and low surrogates, and
            // they will never be assigned a character, so there should be no
            // reason to encode them. The official Unicode standard says that
            // no UTF forms, including UTF-16, can encode these code points.
            if (cp >= 0xD800u and cp <= 0xDFFFu)
            {
                continue;
            }

            std::string res;

            if (cp < 0x10000u)
            {
                // codepoint can be represented with 16 bit
                res += codepoint_to_unicode(cp);
            }
            else
            {
                // codepoint can be represented with a pair
                res += codepoint_to_unicode(0xd800u + (((cp - 0x10000u) >> 10) & 0x3ffu));
                res += codepoint_to_unicode(0xdc00u + ((cp - 0x10000u) & 0x3ffu));
            }

            try
            {
                json j1, j2;
                CHECK_NOTHROW(j1 = json::parse("\"" + res + "\""));
                CHECK_NOTHROW(j2 = json::parse(j1.dump()));
                CHECK(j1 == j2);
            }
            catch (std::invalid_argument)
            {
                // we ignore parsing errors
            }
        }
    }

    SECTION("read all unicode characters")
    {
        // read a file with all unicode characters stored as single-character
        // strings in a JSON array
        std::ifstream f("test/json_nlohmann_tests/all_unicode.json");
        json j;
        CHECK_NOTHROW(j << f);

        // the array has 1112064 + 1 elemnts (a terminating "null" value)
        CHECK(j.size() == 1112065);
    }
}

TEST_CASE("regression tests")
{
    SECTION("issue #60 - Double quotation mark is not parsed correctly")
    {
        SECTION("escape_dobulequote")
        {
            auto s = "[\"\\\"foo\\\"\"]";
            json j = json::parse(s);
            auto expected = R"(["\"foo\""])"_json;
            CHECK(j == expected);
        }
    }

    SECTION("issue #70 - Handle infinity and NaN cases")
    {
        SECTION("NAN value")
        {
            CHECK(json(NAN) == json());
            CHECK(json(json::number_float_t(NAN)) == json());
        }

        SECTION("infinity")
        {
            CHECK(json(INFINITY) == json());
            CHECK(json(json::number_float_t(INFINITY)) == json());
        }
    }

    SECTION("pull request #71 - handle enum type")
    {
        enum { t = 0 };
        json j = json::array();
        j.push_back(t);

        j.push_back(json::object(
        {
            {"game_type", t}
        }));
    }

    SECTION("issue #76 - dump() / parse() not idempotent")
    {
        // create JSON object
        json fields;
        fields["one"] = std::string("one");
        fields["two"] = std::string("two three");
        fields["three"] = std::string("three \"four\"");

        // create another JSON object by deserializing the serialization
        std::string payload = fields.dump();
        json parsed_fields = json::parse(payload);

        // check individual fields to match both objects
        CHECK(parsed_fields["one"] == fields["one"]);
        CHECK(parsed_fields["two"] == fields["two"]);
        CHECK(parsed_fields["three"] == fields["three"]);

        // check individual fields to match original input
        CHECK(parsed_fields["one"] == std::string("one"));
        CHECK(parsed_fields["two"] == std::string("two three"));
        CHECK(parsed_fields["three"] == std::string("three \"four\""));

        // check equality of the objects
        CHECK(parsed_fields == fields);

        // check equality of the serialized objects
        CHECK(fields.dump() == parsed_fields.dump());

        // check everything in one line
        CHECK(fields == json::parse(fields.dump()));
    }

    SECTION("issue #82 - lexer::get_number return NAN")
    {
        const auto content = R"(
        {
            "Test":"Test1",
            "Number":100,
            "Foo":42.42
        })";

        std::stringstream ss;
        ss << content;
        json j;
        ss >> j;

        std::string test = j["Test"];
        CHECK(test == "Test1");
        int number = j["Number"];
        CHECK(number == 100);
        float foo = j["Foo"];
        CHECK(foo == Approx(42.42));
    }

    SECTION("issue #89 - nonstandard integer type")
    {
        // create JSON class with nonstandard integer number type
        nlohmann::basic_json<std::map, std::vector, std::string, bool, int32_t, float> j;
        j["int_1"] = 1;
        // we need to cast to int to compile with Catch - the value is int32_t
        CHECK(static_cast<int>(j["int_1"]) == 1);
    }

    SECTION("issue #93 reverse_iterator operator inheritance problem")
    {
        {
            json a = {1, 2, 3};
            json::reverse_iterator rit = a.rbegin();
            ++rit;
            CHECK(*rit == json(2));
            CHECK(rit.value() == json(2));
        }
        {
            json a = {1, 2, 3};
            json::reverse_iterator rit = ++a.rbegin();
        }
        {
            json a = {1, 2, 3};
            json::reverse_iterator rit = a.rbegin();
            ++rit;
            json b = {0, 0, 0};
            std::transform(rit, a.rend(), b.rbegin(), [](json el)
            {
                return el;
            });
            CHECK(b == json({0, 1, 2}));
        }
        {
            json a = {1, 2, 3};
            json b = {0, 0, 0};
            std::transform(++a.rbegin(), a.rend(), b.rbegin(), [](json el)
            {
                return el;
            });
            CHECK(b == json({0, 1, 2}));
        }
    }

    SECTION("issue #100 - failed to iterator json object with reverse_iterator")
    {
        json config =
        {
            { "111", 111 },
            { "112", 112 },
            { "113", 113 }
        };

        std::stringstream ss;

        for (auto it = config.begin(); it != config.end(); ++it)
        {
            ss << it.key() << ": " << it.value() << '\n';
        }

        for (auto it = config.rbegin(); it != config.rend(); ++it)
        {
            ss << it.key() << ": " << it.value() << '\n';
        }

        CHECK(ss.str() == "111: 111\n112: 112\n113: 113\n113: 113\n112: 112\n111: 111\n");
    }

    SECTION("issue #101 - binary string causes numbers to be dumped as hex")
    {
        int64_t number = 10;
        std::string bytes{"\x00" "asdf\n", 6};
        json j;
        j["int64"] = number;
        j["binary string"] = bytes;
        // make sure the number is really printed as decimal "10" and not as
        // hexadecimal "a"
        CHECK(j.dump() == "{\"binary string\":\"\\u0000asdf\\n\",\"int64\":10}");
    }

    SECTION("issue #111 - subsequent unicode chars")
    {
        std::string bytes{0x7, 0x7};
        json j;
        j["string"] = bytes;
        CHECK(j["string"] == "\u0007\u0007");
    }
}
