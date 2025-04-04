//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <deque>
#include <forward_list>
#include <fstream>
#include <list>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <valarray>

TEST_CASE("constructors")
{
    SECTION("create an empty value with a given type")
    {
        SECTION("null")
        {
            auto const t = json::value_t::null;
            json const j(t);
            CHECK(j.type() == t);
        }

        SECTION("discarded")
        {
            auto const t = json::value_t::discarded;
            json const j(t);
            CHECK(j.type() == t);
        }

        SECTION("object")
        {
            auto const t = json::value_t::object;
            json const j(t);
            CHECK(j.type() == t);
        }

        SECTION("array")
        {
            auto const t = json::value_t::array;
            json const j(t);
            CHECK(j.type() == t);
        }

        SECTION("boolean")
        {
            auto const t = json::value_t::boolean;
            json const j(t);
            CHECK(j.type() == t);
            CHECK(j == false);
        }

        SECTION("string")
        {
            auto const t = json::value_t::string;
            json const j(t);
            CHECK(j.type() == t);
            CHECK(j == "");
        }

        SECTION("number_integer")
        {
            auto const t = json::value_t::number_integer;
            json const j(t);
            CHECK(j.type() == t);
            CHECK(j == 0);
        }

        SECTION("number_unsigned")
        {
            auto const t = json::value_t::number_unsigned;
            json const j(t);
            CHECK(j.type() == t);
            CHECK(j == 0);
        }

        SECTION("number_float")
        {
            auto const t = json::value_t::number_float;
            json const j(t);
            CHECK(j.type() == t);
            CHECK(j == 0.0);
        }

        SECTION("binary")
        {
            auto const t = json::value_t::binary;
            json const j(t);
            CHECK(j.type() == t);
            CHECK(j == json::binary({}));
        }
    }

    SECTION("create a null object (implicitly)")
    {
        SECTION("no parameter")
        {
            json const j{};
            CHECK(j.type() == json::value_t::null);
        }
    }

    SECTION("create a null object (explicitly)")
    {
        SECTION("parameter")
        {
            json const j(nullptr);
            CHECK(j.type() == json::value_t::null);
        }
    }

    SECTION("create an object (explicit)")
    {
        SECTION("empty object")
        {
            json::object_t const o{};
            json const j(o);
            CHECK(j.type() == json::value_t::object);
        }

        SECTION("filled object")
        {
            json::object_t const o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json const j(o);
            CHECK(j.type() == json::value_t::object);
        }
    }

    SECTION("create an object (implicit)")
    {
        // reference object
        json::object_t const o_reference {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
        json const j_reference(o_reference);

        SECTION("std::map<json::string_t, json>")
        {
            std::map<json::string_t, json> const o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json const j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::map<std::string, std::string> #600")
        {
            const std::map<std::string, std::string> m
            {
                {"a", "b"},
                {"c", "d"},
                {"e", "f"},
            };

            json const j(m);
            CHECK((j.get<decltype(m)>() == m));
        }

        SECTION("std::map<const char*, json>")
        {
            std::map<const char*, json> const o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json const j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            std::multimap<json::string_t, json> const o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json const j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            std::unordered_map<json::string_t, json> const o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json const j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            std::unordered_multimap<json::string_t, json> const o {{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}};
            json const j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("associative container literal")
        {
            json const j({{"a", json(1)}, {"b", json(1u)}, {"c", json(2.2)}, {"d", json(false)}, {"e", json("string")}, {"f", json()}});
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }
    }

    SECTION("create an array (explicit)")
    {
        SECTION("empty array")
        {
            json::array_t const a{};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
        }

        SECTION("filled array")
        {
            json::array_t const a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
        }
    }

    SECTION("create an array (implicit)")
    {
        // reference array
        json::array_t const a_reference {json(1), json(1u), json(2.2), json(false), json("string"), json()};
        json const j_reference(a_reference);

        SECTION("std::list<json>")
        {
            std::list<json> const a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::pair")
        {
            std::pair<float, std::string> const p{1.0f, "string"};
            json const j(p);

            CHECK(j.type() == json::value_t::array);
            CHECK(j.get<decltype(p)>() == p);
            REQUIRE(j.size() == 2);
            CHECK(j[0] == std::get<0>(p));
            CHECK(j[1] == std::get<1>(p));
        }

        SECTION("std::pair with discarded values")
        {
            json const j{1, 2.0, "string"};

            const auto p = j.get<std::pair<int, float>>();
            CHECK(p.first == j[0]);
            CHECK(p.second == j[1]);
        }

        SECTION("std::tuple")
        {
            const auto t = std::make_tuple(1.0, std::string{"string"}, 42, std::vector<int> {0, 1});
            json const j(t);

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
            json const j{1, 2.0, "string", 42};

            const auto t = j.get<std::tuple<int, float, std::string>>();
            CHECK(std::get<0>(t) == j[0]);
            CHECK(std::get<1>(t) == j[1]);
            // CHECK(std::get<2>(t) == j[2]); // commented out due to CI issue, see https://github.com/nlohmann/json/pull/3985 and https://github.com/nlohmann/json/issues/4025
        }

        SECTION("std::pair/tuple/array failures")
        {
            json const j{1};

            CHECK_THROWS_WITH_AS((j.get<std::pair<int, int>>()), "[json.exception.out_of_range.401] array index 1 is out of range", json::out_of_range&);
            CHECK_THROWS_WITH_AS((j.get<std::tuple<int, int>>()), "[json.exception.out_of_range.401] array index 1 is out of range", json::out_of_range&);
            CHECK_THROWS_WITH_AS((j.get<std::array<int, 3>>()), "[json.exception.out_of_range.401] array index 1 is out of range", json::out_of_range&);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> const a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::array<json, 6>")
        {
            std::array<json, 6> const a {{json(1), json(1u), json(2.2), json(false), json("string"), json()}};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);

            const auto a2 = j.get<std::array<json, 6>>();
            CHECK(a2 == a);
        }

        SECTION("std::valarray<int>")
        {
            std::valarray<int> const va = {1, 2, 3, 4, 5};
            json const j(va);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == json({1, 2, 3, 4, 5}));

            auto jva = j.get<std::valarray<int>>();
            CHECK(jva.size() == va.size());
            for (size_t i = 0; i < jva.size(); ++i)
            {
                CHECK(va[i] == jva[i]);
            }
        }

        SECTION("std::valarray<double>")
        {
            std::valarray<double> const va = {1.2, 2.3, 3.4, 4.5, 5.6};
            json const j(va);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == json({1.2, 2.3, 3.4, 4.5, 5.6}));

            auto jva = j.get<std::valarray<double>>();
            CHECK(jva.size() == va.size());
            for (size_t i = 0; i < jva.size(); ++i)
            {
                CHECK(va[i] == jva[i]);
            }
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> const a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> const a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::set<json>")
        {
            std::set<json> const a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
            // we cannot really check for equality here
        }

        SECTION("std::unordered_set<json>")
        {
            std::unordered_set<json> const a {json(1), json(1u), json(2.2), json(false), json("string"), json()};
            json const j(a);
            CHECK(j.type() == json::value_t::array);
            // we cannot really check for equality here
        }

        SECTION("sequence container literal")
        {
            json const j({json(1), json(1u), json(2.2), json(false), json("string"), json()});
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }
    }

    SECTION("create a string (explicit)")
    {
        SECTION("empty string")
        {
            json::string_t const s{};
            json const j(s);
            CHECK(j.type() == json::value_t::string);
        }

        SECTION("filled string")
        {
            json::string_t const s {"Hello world"};
            json const j(s);
            CHECK(j.type() == json::value_t::string);
        }
    }

    SECTION("create a string (implicit)")
    {
        // reference string
        json::string_t const s_reference {"Hello world"};
        json const j_reference(s_reference);

        SECTION("std::string")
        {
            std::string const s {"Hello world"};
            json const j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("char[]")
        {
            const char s[] {"Hello world"}; // NOLINT(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            json const j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("const char*")
        {
            const char* s {"Hello world"};
            json const j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("string literal")
        {
            json const j("Hello world");
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }
    }

    SECTION("create a boolean (explicit)")
    {
        SECTION("empty boolean")
        {
            json::boolean_t const b{};
            json const j(b);
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("filled boolean (true)")
        {
            json const j(true);
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("filled boolean (false)")
        {
            json const j(false);
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("from std::vector<bool>::reference")
        {
            std::vector<bool> v{true};
            json const j(v[0]);
            CHECK(std::is_same<decltype(v[0]), std::vector<bool>::reference>::value);
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("from std::vector<bool>::const_reference")
        {
            const std::vector<bool> v{true};
            json const j(v[0]);
            CHECK(std::is_same<decltype(v[0]), std::vector<bool>::const_reference>::value);
            CHECK(j.type() == json::value_t::boolean);
        }
    }

    SECTION("create a binary (explicit)")
    {
        SECTION("empty binary")
        {
            json::binary_t const b{};
            json const j(b);
            CHECK(j.type() == json::value_t::binary);
        }

        SECTION("filled binary")
        {
            json::binary_t const b({1, 2, 3});
            json const j(b);
            CHECK(j.type() == json::value_t::binary);
        }
    }

    SECTION("create an integer number (explicit)")
    {
        SECTION("uninitialized value")
        {
            json::number_integer_t const n{};
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
        }

        SECTION("initialized value")
        {
            json::number_integer_t const n(42);
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
        }
    }

    SECTION("create an integer number (implicit)")
    {
        // reference objects
        json::number_integer_t const n_reference = 42;
        json const j_reference(n_reference);
        json::number_unsigned_t const n_unsigned_reference = 42;
        json const j_unsigned_reference(n_unsigned_reference);

        SECTION("short")
        {
            short const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned short")
        {
            unsigned short const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("int")
        {
            int const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned int")
        {
            unsigned int const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("long")
        {
            long const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned long")
        {
            unsigned long const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("long long")
        {
            long long const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned long long")
        {
            unsigned long long const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("int8_t")
        {
            int8_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int16_t")
        {
            int16_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int32_t")
        {
            int32_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int64_t")
        {
            int64_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast8_t")
        {
            int_fast8_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast16_t")
        {
            int_fast16_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast32_t")
        {
            int_fast32_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast64_t")
        {
            int_fast64_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least8_t")
        {
            int_least8_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least16_t")
        {
            int_least16_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least32_t")
        {
            int_least32_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least64_t")
        {
            int_least64_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint8_t")
        {
            uint8_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint16_t")
        {
            uint16_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint32_t")
        {
            uint32_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint64_t")
        {
            uint64_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_fast8_t")
        {
            uint_fast8_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_fast16_t")
        {
            uint_fast16_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_fast32_t")
        {
            uint_fast32_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_fast64_t")
        {
            uint_fast64_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_least8_t")
        {
            uint_least8_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_least16_t")
        {
            uint_least16_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_least32_t")
        {
            uint_least32_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("uint_least64_t")
        {
            uint_least64_t const n = 42;
            json const j(n);
            CHECK(j.type() == json::value_t::number_unsigned);
            CHECK(j == j_unsigned_reference);
        }

        SECTION("integer literal without suffix")
        {
            json const j(42);
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
            json const j(42L);
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
            json const j(42LL);
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
            json::number_float_t const n{};
            json const j(n);
            CHECK(j.type() == json::value_t::number_float);
        }

        SECTION("initialized value")
        {
            json::number_float_t const n(42.23);
            json const j(n);
            CHECK(j.type() == json::value_t::number_float);
        }

        SECTION("NaN")
        {
            // NaN is stored properly, but serialized to null
            json::number_float_t const n(std::numeric_limits<json::number_float_t>::quiet_NaN());
            json const j(n);
            CHECK(j.type() == json::value_t::number_float);

            // check round trip of NaN
            json::number_float_t const d{j};
            CHECK((std::isnan(d) && std::isnan(n)) == true);

            // check that NaN is serialized to null
            CHECK(j.dump() == "null");
        }

        SECTION("infinity")
        {
            // infinity is stored properly, but serialized to null
            json::number_float_t const n(std::numeric_limits<json::number_float_t>::infinity());
            json const j(n);
            CHECK(j.type() == json::value_t::number_float);

            // check round trip of infinity
            json::number_float_t const d{j};
            CHECK(d == n);

            // check that inf is serialized to null
            CHECK(j.dump() == "null");
        }
    }

    SECTION("create a floating-point number (implicit)")
    {
        // reference object
        json::number_float_t const n_reference = 42.23;
        json const j_reference(n_reference);

        SECTION("float")
        {
            float const n = 42.23f;
            json const j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_data.m_value.number_float == Approx(j_reference.m_data.m_value.number_float));
        }

        SECTION("double")
        {
            double const n = 42.23;
            json const j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_data.m_value.number_float == Approx(j_reference.m_data.m_value.number_float));
        }

        SECTION("long double")
        {
            long double const n = 42.23L;
            json const j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_data.m_value.number_float == Approx(j_reference.m_data.m_value.number_float));
        }

        SECTION("floating-point literal without suffix")
        {
            json const j(42.23);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_data.m_value.number_float == Approx(j_reference.m_data.m_value.number_float));
        }

        SECTION("integer literal with f suffix")
        {
            json const j(42.23f);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_data.m_value.number_float == Approx(j_reference.m_data.m_value.number_float));
        }

        SECTION("integer literal with l suffix")
        {
            json const j(42.23L);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_data.m_value.number_float == Approx(j_reference.m_data.m_value.number_float));
        }
    }

    SECTION("create a container (array or object) from an initializer list")
    {
        SECTION("empty initializer list")
        {
            SECTION("explicit")
            {
                json const j(json::initializer_list_t {});
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("implicit")
            {
                json const j {};
                CHECK(j.type() == json::value_t::null);
            }
        }

        SECTION("one element")
        {
            SECTION("array")
            {
                SECTION("explicit")
                {
                    json const j(json::initializer_list_t {json(json::array_t())});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json const j {json::array_t()};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("object")
            {
                SECTION("explicit")
                {
                    json const j(json::initializer_list_t {json(json::object_t())});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json const j {json::object_t()};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("string")
            {
                SECTION("explicit")
                {
                    json const j(json::initializer_list_t {json("Hello world")});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json const j {"Hello world"};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("boolean")
            {
                SECTION("explicit")
                {
                    json const j(json::initializer_list_t {json(true)});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json const j {true};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("number (integer)")
            {
                SECTION("explicit")
                {
                    json const j(json::initializer_list_t {json(1)});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json const j {1};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("number (unsigned)")
            {
                SECTION("explicit")
                {
                    json const j(json::initializer_list_t {json(1u)});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json const j {1u};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("number (floating-point)")
            {
                SECTION("explicit")
                {
                    json const j(json::initializer_list_t {json(42.23)});
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json const j {42.23};
                    CHECK(j.type() == json::value_t::array);
                }
            }
        }

        SECTION("more elements")
        {
            SECTION("explicit")
            {
                json const j(json::initializer_list_t {1, 1u, 42.23, true, nullptr, json::object_t(), json::array_t()});
                CHECK(j.type() == json::value_t::array);
            }

            SECTION("implicit")
            {
                json const j {1, 1u, 42.23, true, nullptr, json::object_t(), json::array_t()};
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("implicit type deduction")
        {
            SECTION("object")
            {
                json const j { {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false} };
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("array")
            {
                json const j { {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false}, 13 };
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("explicit type deduction")
        {
            SECTION("empty object")
            {
                json const j = json::object();
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("object")
            {
                json const j = json::object({ {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false} });
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("object with error")
            {
                json _;
                CHECK_THROWS_WITH_AS(_ = json::object({ {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false}, 13 }), "[json.exception.type_error.301] cannot create object from initializer list", json::type_error&);
            }

            SECTION("empty array")
            {
                json const j = json::array();
                CHECK(j.type() == json::value_t::array);
            }

            SECTION("array")
            {
                json const j = json::array({ {"one", 1}, {"two", 1u}, {"three", 2.2}, {"four", false} });
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("move from initializer_list")
        {
            SECTION("string")
            {
                SECTION("constructor with implicit types (array)")
                {
                    // This should break through any short string optimization in std::string
                    std::string source(1024, '!');
                    const auto* source_addr = source.data();
                    json j = {std::move(source)};
                    const auto* target_addr = j[0].get_ref<std::string const&>().data();
                    const bool success = (target_addr == source_addr);
                    CHECK(success);
                }

                SECTION("constructor with implicit types (object)")
                {
                    // This should break through any short string optimization in std::string
                    std::string source(1024, '!');
                    const auto* source_addr = source.data();
                    json j = {{"key", std::move(source)}};
                    const auto* target_addr = j["key"].get_ref<std::string const&>().data();
                    const bool success = (target_addr == source_addr);
                    CHECK(success);
                }

                SECTION("constructor with implicit types (object key)")
                {
                    // This should break through any short string optimization in std::string
                    std::string source(1024, '!');
                    const auto* source_addr = source.data();
                    json j = {{std::move(source), 42}};
                    const auto* target_addr = j.get_ref<json::object_t&>().begin()->first.data();
                    const bool success = (target_addr == source_addr);
                    CHECK(success);
                }
            }

            SECTION("array")
            {
                SECTION("constructor with implicit types (array)")
                {
                    json::array_t source = {1, 2, 3};
                    const auto* source_addr = source.data();
                    json j {std::move(source)};
                    const auto* target_addr = j[0].get_ref<json::array_t const&>().data();
                    const bool success = (target_addr == source_addr);
                    CHECK(success);
                }

                SECTION("constructor with implicit types (object)")
                {
                    json::array_t source = {1, 2, 3};
                    const auto* source_addr = source.data();
                    json const j {{"key", std::move(source)}};
                    const auto* target_addr = j["key"].get_ref<json::array_t const&>().data();
                    const bool success = (target_addr == source_addr);
                    CHECK(success);
                }

                SECTION("assignment with implicit types (array)")
                {
                    json::array_t source = {1, 2, 3};
                    const auto* source_addr = source.data();
                    json j = {std::move(source)};
                    const auto* target_addr = j[0].get_ref<json::array_t const&>().data();
                    const bool success = (target_addr == source_addr);
                    CHECK(success);
                }

                SECTION("assignment with implicit types (object)")
                {
                    json::array_t source = {1, 2, 3};
                    const auto* source_addr = source.data();
                    json j = {{"key", std::move(source)}};
                    const auto* target_addr = j["key"].get_ref<json::array_t const&>().data();
                    const bool success = (target_addr == source_addr);
                    CHECK(success);
                }
            }

            SECTION("object")
            {
                SECTION("constructor with implicit types (array)")
                {
                    json::object_t source = {{"hello", "world"}};
                    const json* source_addr = &source.at("hello");
                    json j {std::move(source)};
                    CHECK(&(j[0].get_ref<json::object_t const&>().at("hello")) == source_addr);
                }

                SECTION("constructor with implicit types (object)")
                {
                    json::object_t source = {{"hello", "world"}};
                    const json* source_addr = &source.at("hello");
                    json j {{"key", std::move(source)}};
                    CHECK(&(j["key"].get_ref<json::object_t const&>().at("hello")) == source_addr);
                }

                SECTION("assignment with implicit types (array)")
                {
                    json::object_t source = {{"hello", "world"}};
                    const json* source_addr = &source.at("hello");
                    json j = {std::move(source)};
                    CHECK(&(j[0].get_ref<json::object_t const&>().at("hello")) == source_addr);
                }

                SECTION("assignment with implicit types (object)")
                {
                    json::object_t source = {{"hello", "world"}};
                    const json* source_addr = &source.at("hello");
                    json j = {{"key", std::move(source)}};
                    CHECK(&(j["key"].get_ref<json::object_t const&>().at("hello")) == source_addr);
                }
            }

            SECTION("json")
            {
                SECTION("constructor with implicit types (array)")
                {
                    json source {1, 2, 3};
                    const json* source_addr = &source[0];
                    json j {std::move(source), {}};
                    CHECK(&j[0][0] == source_addr);
                }

                SECTION("constructor with implicit types (object)")
                {
                    json source {1, 2, 3};
                    const json* source_addr = &source[0];
                    json j {{"key", std::move(source)}};
                    CHECK(&j["key"][0] == source_addr);
                }

                SECTION("assignment with implicit types (array)")
                {
                    json source {1, 2, 3};
                    const json* source_addr = &source[0];
                    json j = {std::move(source), {}};
                    CHECK(&j[0][0] == source_addr);
                }

                SECTION("assignment with implicit types (object)")
                {
                    json source {1, 2, 3};
                    const json* source_addr = &source[0];
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
            json const v = {1, "foo", 34.23, {1, 2, 3}, {{"A", 1}, {"B", 2u}}};
            json const arr(0, v);
            CHECK(arr.size() == 0);
        }

        SECTION("cnt = 1")
        {
            json const v = {1, "foo", 34.23, {1, 2, 3}, {{"A", 1}, {"B", 2u}}};
            json const arr(1, v);
            CHECK(arr.size() == 1);
            for (const auto& x : arr)
            {
                CHECK(x == v);
            }
        }

        SECTION("cnt = 3")
        {
            json const v = {1, "foo", 34.23, {1, 2, 3}, {{"A", 1}, {"B", 2u}}};
            json const arr(3, v);
            CHECK(arr.size() == 3);
            for (const auto& x : arr)
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
                    json const j_new(jobject.begin(), jobject.end());
                    CHECK(j_new == jobject);
                }
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    json const j_new(jobject.cbegin(), jobject.cend());
                    CHECK(j_new == jobject);
                }
            }

            SECTION("json(begin(), begin())")
            {
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    json const j_new(jobject.begin(), jobject.begin());
                    CHECK(j_new == json::object());
                }
                {
                    json const jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    json const j_new(jobject.cbegin(), jobject.cbegin());
                    CHECK(j_new == json::object());
                }
            }

            SECTION("construct from subrange")
            {
                json const jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                json const j_new(jobject.find("b"), jobject.find("e"));
                CHECK(j_new == json({{"b", 1}, {"c", 17u}, {"d", false}}));
            }

            SECTION("incompatible iterators")
            {
                {
                    json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                    json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    CHECK_THROWS_WITH_AS(json(jobject.begin(), jobject2.end()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator&);
                    CHECK_THROWS_WITH_AS(json(jobject2.begin(), jobject.end()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator&);
                }
                {
                    json const jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                    json const jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                    CHECK_THROWS_WITH_AS(json(jobject.cbegin(), jobject2.cend()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator&);
                    CHECK_THROWS_WITH_AS(json(jobject2.cbegin(), jobject.cend()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator&);
                }
            }
        }

        SECTION("array")
        {
            SECTION("json(begin(), end())")
            {
                {
                    json jarray = {1, 2, 3, 4, 5};
                    json const j_new(jarray.begin(), jarray.end());
                    CHECK(j_new == jarray);
                }
                {
                    json const jarray = {1, 2, 3, 4, 5};
                    json const j_new(jarray.cbegin(), jarray.cend());
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
                    json const jarray = {1, 2, 3, 4, 5};
                    json const j_new(jarray.cbegin(), jarray.cbegin());
                    CHECK(j_new == json::array());
                }
            }

            SECTION("construct from subrange")
            {
                {
                    json jarray = {1, 2, 3, 4, 5};
                    json const j_new(jarray.begin() + 1, jarray.begin() + 3);
                    CHECK(j_new == json({2, 3}));
                }
                {
                    json const jarray = {1, 2, 3, 4, 5};
                    json const j_new(jarray.cbegin() + 1, jarray.cbegin() + 3);
                    CHECK(j_new == json({2, 3}));
                }
            }

            SECTION("incompatible iterators")
            {
                {
                    json jarray = {1, 2, 3, 4};
                    json jarray2 = {2, 3, 4, 5};
                    CHECK_THROWS_WITH_AS(json(jarray.begin(), jarray2.end()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator&);
                    CHECK_THROWS_WITH_AS(json(jarray2.begin(), jarray.end()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator&);
                }
                {
                    json const jarray = {1, 2, 3, 4};
                    json const jarray2 = {2, 3, 4, 5};
                    CHECK_THROWS_WITH_AS(json(jarray.cbegin(), jarray2.cend()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator&);
                    CHECK_THROWS_WITH_AS(json(jarray2.cbegin(), jarray.cend()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator&);
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
                        CHECK_THROWS_WITH_AS(json(j.begin(), j.end()), "[json.exception.invalid_iterator.206] cannot construct with iterators from null", json::invalid_iterator&);
                    }
                    {
                        json const j;
                        CHECK_THROWS_WITH_AS(json(j.cbegin(), j.cend()), "[json.exception.invalid_iterator.206] cannot construct with iterators from null", json::invalid_iterator&);
                    }
                }

                SECTION("string")
                {
                    {
                        json j = "foo";
                        json const j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json const j = "bar";
                        json const j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("number (boolean)")
                {
                    {
                        json j = false;
                        json const j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json const j = true;
                        json const j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17;
                        json const j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json const j = 17;
                        json const j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("number (unsigned)")
                {
                    {
                        json j = 17u;
                        json const j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json const j = 17u;
                        json const j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("number (floating point)")
                {
                    {
                        json j = 23.42;
                        json const j_new(j.begin(), j.end());
                        CHECK(j == j_new);
                    }
                    {
                        json const j = 23.42;
                        json const j_new(j.cbegin(), j.cend());
                        CHECK(j == j_new);
                    }
                }

                SECTION("binary")
                {
                    {
                        json j = json::binary({1, 2, 3});
                        json const j_new(j.begin(), j.end());
                        CHECK((j == j_new));
                    }
                    {
                        json const j = json::binary({1, 2, 3});
                        json const j_new(j.cbegin(), j.cend());
                        CHECK((j == j_new));
                    }
                }
            }

            SECTION("construct with two invalid iterators")
            {
                SECTION("string")
                {
                    {
                        json j = "foo";
                        CHECK_THROWS_WITH_AS(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                    {
                        json const j = "bar";
                        CHECK_THROWS_WITH_AS(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                }

                SECTION("number (boolean)")
                {
                    {
                        json j = false;
                        CHECK_THROWS_WITH_AS(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                    {
                        json const j = true;
                        CHECK_THROWS_WITH_AS(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17;
                        CHECK_THROWS_WITH_AS(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                    {
                        json const j = 17;
                        CHECK_THROWS_WITH_AS(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                }

                SECTION("number (integer)")
                {
                    {
                        json j = 17u;
                        CHECK_THROWS_WITH_AS(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                    {
                        json const j = 17u;
                        CHECK_THROWS_WITH_AS(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                }

                SECTION("number (floating point)")
                {
                    {
                        json j = 23.42;
                        CHECK_THROWS_WITH_AS(json(j.end(), j.end()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.begin(), j.begin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                    {
                        json const j = 23.42;
                        CHECK_THROWS_WITH_AS(json(j.cend(), j.cend()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                        CHECK_THROWS_WITH_AS(json(j.cbegin(), j.cbegin()), "[json.exception.invalid_iterator.204] iterators out of range", json::invalid_iterator&);
                    }
                }
            }
        }
    }
}
