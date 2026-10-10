//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++20-only part of unit-comparison.cpp (tests of operator<=> and
// other three-way comparison specific behavior). It is kept in a separate translation unit
// so the (much larger) unit-comparison.cpp is built for C++11 only and not rebuilt for
// every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#ifdef JSON_HAS_CPP_20
#if JSON_HAS_THREE_WAY_COMPARISON
#include <cmath>
#include <compare>
#include <cstddef>
#include <limits>
#include <string>
#include <utility>
#include <vector>

// this can be replaced with the doctest stl extension header in version 2.5
namespace doctest
{
template<> struct StringMaker<std::partial_ordering>
{
    static String convert(const std::partial_ordering& order)
    {
        if (order == std::partial_ordering::less)
        {
            return "std::partial_ordering::less";
        }
        if (order == std::partial_ordering::equivalent)
        {
            return "std::partial_ordering::equivalent";
        }
        if (order == std::partial_ordering::greater)
        {
            return "std::partial_ordering::greater";
        }
        if (order == std::partial_ordering::unordered)
        {
            return "std::partial_ordering::unordered";
        }
        return "{?}";
    }
};
} // namespace doctest

TEST_CASE("lexicographical comparison operators (C++20)")
{
    constexpr auto f_ = false;
    constexpr auto _t = true;
    constexpr auto nan = std::numeric_limits<json::number_float_t>::quiet_NaN();
    constexpr auto lt = std::partial_ordering::less;
    constexpr auto gt = std::partial_ordering::greater;
    constexpr auto eq = std::partial_ordering::equivalent;
    constexpr auto un = std::partial_ordering::unordered;

    INFO("using 3-way comparison");

#if JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
    INFO("using legacy comparison");
#endif

    SECTION("types")
    {
        std::vector<json::value_t> j_types =
        {
            json::value_t::null,
            json::value_t::boolean,
            json::value_t::number_integer,
            json::value_t::number_unsigned,
            json::value_t::number_float,
            json::value_t::object,
            json::value_t::array,
            json::value_t::string,
            json::value_t::binary,
            json::value_t::discarded
        };

        std::vector<std::vector<bool>> expected_lt =
        {
            //0   1   2   3   4   5   6   7   8   9
            {f_, _t, _t, _t, _t, _t, _t, _t, _t, f_}, //  0
            {f_, f_, _t, _t, _t, _t, _t, _t, _t, f_}, //  1
            {f_, f_, f_, f_, f_, _t, _t, _t, _t, f_}, //  2
            {f_, f_, f_, f_, f_, _t, _t, _t, _t, f_}, //  3
            {f_, f_, f_, f_, f_, _t, _t, _t, _t, f_}, //  4
            {f_, f_, f_, f_, f_, f_, _t, _t, _t, f_}, //  5
            {f_, f_, f_, f_, f_, f_, f_, _t, _t, f_}, //  6
            {f_, f_, f_, f_, f_, f_, f_, f_, _t, f_}, //  7
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  8
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  9
        };

        SECTION("comparison: less")
        {
            for (size_t i = 0; i < j_types.size(); ++i)
            {
                for (size_t j = 0; j < j_types.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    // check precomputed values
                    CHECK((j_types[i] < j_types[j]) == expected_lt[i][j]);
                }
            }
        }

        SECTION("comparison: 3-way")
        {
            // doctest runs the REQUIRE in the test case body once per leaf section; keep it
            // here to run it as often as before the 3-way sections moved from unit-comparison.cpp
            REQUIRE(std::isnan(nan));

            std::vector<std::vector<std::partial_ordering>> expected =
            {
                //0   1   2   3   4   5   6   7   8   9
                {eq, lt, lt, lt, lt, lt, lt, lt, lt, un}, //  0
                {gt, eq, lt, lt, lt, lt, lt, lt, lt, un}, //  1
                {gt, gt, eq, eq, eq, lt, lt, lt, lt, un}, //  2
                {gt, gt, eq, eq, eq, lt, lt, lt, lt, un}, //  3
                {gt, gt, eq, eq, eq, lt, lt, lt, lt, un}, //  4
                {gt, gt, gt, gt, gt, eq, lt, lt, lt, un}, //  5
                {gt, gt, gt, gt, gt, gt, eq, lt, lt, un}, //  6
                {gt, gt, gt, gt, gt, gt, gt, eq, lt, un}, //  7
                {gt, gt, gt, gt, gt, gt, gt, gt, eq, un}, //  8
                {un, un, un, un, un, un, un, un, un, un}, //  9
            };

            // check expected partial_ordering against expected boolean
            REQUIRE(expected.size() == expected_lt.size());
            for (size_t i = 0; i < expected.size(); ++i)
            {
                REQUIRE(expected[i].size() == expected_lt[i].size());
                for (size_t j = 0; j < expected[i].size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CHECK(std::is_lt(expected[i][j]) == expected_lt[i][j]);
                }
            }

            // check 3-way comparison against expected partial_ordering
            REQUIRE(expected.size() == j_types.size());
            for (size_t i = 0; i < j_types.size(); ++i)
            {
                REQUIRE(expected[i].size() == j_types.size());
                for (size_t j = 0; j < j_types.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CHECK((j_types[i] <=> j_types[j]) == expected[i][j]); // *NOPAD*
                }
            }
        }
    }

    SECTION("values")
    {
        json j_values =
        {
            nullptr, nullptr,                                              // 0 1
            -17, 42,                                                       // 2 3
            8u, 13u,                                                       // 4 5
            3.14159, 23.42,                                                // 6 7
            nan, nan,                                                      // 8 9
            "foo", "bar",                                                  // 10 11
            true, false,                                                   // 12 13
            {1, 2, 3}, {"one", "two", "three"},                            // 14 15
            {{"first", 1}, {"second", 2}}, {{"a", "A"}, {"b", {"B"}}},     // 16 17
            json::binary({1, 2, 3}), json::binary({1, 2, 4}),              // 18 19
            json(json::value_t::discarded), json(json::value_t::discarded) // 20 21
        };

        std::vector<std::vector<bool>> expected_eq =
        {
            //0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21
            {_t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  0
            {_t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  1
            {f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  2
            {f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  3
            {f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  4
            {f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  5
            {f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  6
            {f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  7
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  8
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  9
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 10
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 11
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 12
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, f_}, // 13
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_}, // 14
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_}, // 15
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_}, // 16
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_}, // 17
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_}, // 18
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_}, // 19
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 20
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 21
        };

        std::vector<std::vector<bool>> expected_lt =
        {
            //0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21
            {f_, f_, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, f_, f_}, //  0
            {f_, f_, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, f_, f_}, //  1
            {f_, f_, f_, _t, _t, _t, _t, _t, f_, f_, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, //  2
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, //  3
            {f_, f_, f_, _t, f_, _t, f_, _t, f_, f_, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, //  4
            {f_, f_, f_, _t, f_, f_, f_, _t, f_, f_, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, //  5
            {f_, f_, f_, _t, _t, _t, f_, _t, f_, f_, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, //  6
            {f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, //  7
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, //  8
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, //  9
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_}, // 10
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_}, // 11
            {f_, f_, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, f_, f_, _t, _t, _t, _t, _t, _t, f_, f_}, // 12
            {f_, f_, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, f_, _t, _t, _t, _t, _t, _t, f_, f_}, // 13
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, _t, f_, f_, _t, _t, f_, f_}, // 14
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_}, // 15
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, _t, _t, f_, f_, _t, _t, f_, f_}, // 16
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, _t, _t, _t, f_, _t, _t, f_, f_}, // 17
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, f_, f_}, // 18
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 19
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 20
            {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 21
        };

        SECTION("signed/unsigned mixed comparison above INT64_MAX")
        {
            const json above_int64_max = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1ULL;
            const json max_uint64 = (std::numeric_limits<std::uint64_t>::max)();
            const json negative_one = -1;
            const json one = 1;
            const json max_int64 = (std::numeric_limits<std::int64_t>::max)();

            CHECK((negative_one <=> above_int64_max) == std::partial_ordering::less); // *NOPAD*
            CHECK((above_int64_max <=> negative_one) == std::partial_ordering::greater); // *NOPAD*
            CHECK((negative_one <=> max_uint64) == std::partial_ordering::less); // *NOPAD*
            CHECK((max_uint64 <=> negative_one) == std::partial_ordering::greater); // *NOPAD*
            CHECK((one <=> above_int64_max) == std::partial_ordering::less); // *NOPAD*
            CHECK((above_int64_max <=> one) == std::partial_ordering::greater); // *NOPAD*
            CHECK((max_int64 <=> above_int64_max) == std::partial_ordering::less); // *NOPAD*
            CHECK((above_int64_max <=> max_int64) == std::partial_ordering::greater); // *NOPAD*
        }

        SECTION("integer/float mixed comparison is exact")
        {
            // Widening the integer to a double loses precision past the
            // mantissa, so 2^63-2 and 2^63-1 both used to compare equal to the
            // double 2^63 while differing from each other. That makes equality
            // intransitive and the ordering not a strict weak ordering.
            const json below_two_63 = static_cast<std::int64_t>(9223372036854775806LL);
            const json max_int64 = (std::numeric_limits<std::int64_t>::max)();
            const json two_63 = 9223372036854775808.0;

            // the same past the unsigned range
            const json max_uint64 = (std::numeric_limits<std::uint64_t>::max)();
            const json two_64 = 18446744073709551616.0;

            CHECK((max_int64 <=> two_63) == std::partial_ordering::less); // *NOPAD*
            CHECK((two_63 <=> max_int64) == std::partial_ordering::greater); // *NOPAD*
            CHECK((below_two_63 <=> max_int64) == std::partial_ordering::less); // *NOPAD*
            CHECK((max_uint64 <=> two_64) == std::partial_ordering::less); // *NOPAD*
            CHECK((json(1) <=> json(1.0)) == std::partial_ordering::equivalent); // *NOPAD*
            CHECK((json(1) <=> json(nan)) == std::partial_ordering::unordered); // *NOPAD*
        }

        SECTION("comparison: 3-way")
        {
            // doctest runs the REQUIRE in the test case body once per leaf section; keep it
            // here to run it as often as before the 3-way sections moved from unit-comparison.cpp
            REQUIRE(std::isnan(nan));

            std::vector<std::vector<std::partial_ordering>> expected =
            {
                //0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21
                {eq, eq, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, un, un}, //  0
                {eq, eq, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, un, un}, //  1
                {gt, gt, eq, lt, lt, lt, lt, lt, un, un, lt, lt, gt, gt, lt, lt, lt, lt, lt, lt, un, un}, //  2
                {gt, gt, gt, eq, gt, gt, gt, gt, un, un, lt, lt, gt, gt, lt, lt, lt, lt, lt, lt, un, un}, //  3
                {gt, gt, gt, lt, eq, lt, gt, lt, un, un, lt, lt, gt, gt, lt, lt, lt, lt, lt, lt, un, un}, //  4
                {gt, gt, gt, lt, gt, eq, gt, lt, un, un, lt, lt, gt, gt, lt, lt, lt, lt, lt, lt, un, un}, //  5
                {gt, gt, gt, lt, lt, lt, eq, lt, un, un, lt, lt, gt, gt, lt, lt, lt, lt, lt, lt, un, un}, //  6
                {gt, gt, gt, lt, gt, gt, gt, eq, un, un, lt, lt, gt, gt, lt, lt, lt, lt, lt, lt, un, un}, //  7
                {gt, gt, un, un, un, un, un, un, un, un, lt, lt, gt, gt, lt, lt, lt, lt, lt, lt, un, un}, //  8
                {gt, gt, un, un, un, un, un, un, un, un, lt, lt, gt, gt, lt, lt, lt, lt, lt, lt, un, un}, //  9
                {gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, eq, gt, gt, gt, gt, gt, gt, gt, lt, lt, un, un}, // 10
                {gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, lt, eq, gt, gt, gt, gt, gt, gt, lt, lt, un, un}, // 11
                {gt, gt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, eq, gt, lt, lt, lt, lt, lt, lt, un, un}, // 12
                {gt, gt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, lt, eq, lt, lt, lt, lt, lt, lt, un, un}, // 13
                {gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, lt, lt, gt, gt, eq, lt, gt, gt, lt, lt, un, un}, // 14
                {gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, lt, lt, gt, gt, gt, eq, gt, gt, lt, lt, un, un}, // 15
                {gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, lt, lt, gt, gt, lt, lt, eq, gt, lt, lt, un, un}, // 16
                {gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, lt, lt, gt, gt, lt, lt, lt, eq, lt, lt, un, un}, // 17
                {gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, eq, lt, un, un}, // 18
                {gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, gt, eq, un, un}, // 19
                {un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un}, // 20
                {un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un, un}, // 21
            };

            // check expected partial_ordering against expected booleans
            REQUIRE(expected.size() == expected_eq.size());
            REQUIRE(expected.size() == expected_lt.size());
            for (size_t i = 0; i < expected.size(); ++i)
            {
                REQUIRE(expected[i].size() == expected_eq[i].size());
                REQUIRE(expected[i].size() == expected_lt[i].size());
                for (size_t j = 0; j < expected[i].size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CHECK(std::is_eq(expected[i][j]) == expected_eq[i][j]);
                    CHECK(std::is_lt(expected[i][j]) == expected_lt[i][j]);
                    if (std::is_gt(expected[i][j]))
                    {
                        CHECK((!expected_eq[i][j] && !expected_lt[i][j]));
                    }
                }
            }

            // check that two values compare according to their expected ordering
            REQUIRE(expected.size() == j_values.size());
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                REQUIRE(expected[i].size() == j_values.size());
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CHECK((j_values[i] <=> j_values[j]) == expected[i][j]); // *NOPAD*
                }
            }
        }
    }

}

TEST_CASE("regression #3868 - heterogeneous comparisons compile under C++20 (P2468R2)")
{
    // Issue #3868: operator!= was preventing compiler from synthesizing reversed
    // operator== candidates under C++20's P2468R2 rewritten candidate rules.
    // Verify that heterogeneous comparisons now work.

    SECTION("string vs json")
    {
        std::string s = "string";
        json j = "string";
        CHECK(s == j);
        CHECK(j == s);
        CHECK_FALSE(s != j);
        CHECK_FALSE(j != s);
    }

    SECTION("other heterogeneous types")
    {
        int i = 42;
        json j = 42;
        CHECK(i == j);
        CHECK(j == i);
        CHECK_FALSE(i != j);
        CHECK_FALSE(j != i);
    }
}

#if JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
TEST_CASE("regression #5665 - scalar <= discarded and scalar >= discarded in C++20 legacy mode")
{
    // Issue #5665: with a scalar on the left-hand side, <= and >= only had the
    // candidate rewritten from operator<=>, which does not emulate the legacy
    // discarded-value behavior. Check that scalar-on-the-left now matches the
    // other three operand orders.
    const json discarded(json::value_t::discarded);
    const json one = 1;

    CHECK(discarded <= 1);
    CHECK(discarded >= 1);
    CHECK(one <= discarded);
    CHECK(one >= discarded);
    CHECK(1 <= discarded);
    CHECK(1 >= discarded);
    CHECK(1.5 <= discarded);
    CHECK(1.5 >= discarded);
}

#endif

TEST_CASE("containers are compared element by element (C++20)")
{
    // Containers nested deeper than a bound are compared without the call
    // stack, by code of their own; every relation is checked both at the top
    // level and below that bound.
    const auto deep = [](const json & j, const std::size_t depth)
    {
        json result = j;
        for (std::size_t i = 0; i < depth; ++i)
        {
            result = json::array({std::move(result)});
        }
        return result;
    };

    for (const std::size_t depth : std::vector<std::size_t> {0, 200})
    {
        CAPTURE(depth)

        // objects with different keys
        {
            const json a = deep({{"a", 1}}, depth);
            const json b = deep({{"b", 1}}, depth);
            CHECK((a <=> b) == std::partial_ordering::less); // *NOPAD*
            CHECK((b <=> a) == std::partial_ordering::greater); // *NOPAD*
            CHECK((a <=> a) == std::partial_ordering::equivalent); // *NOPAD*
        }

        // a container that is a prefix of the other one
        {
            // the one that runs out of elements first is the smaller one
            const json shorter = deep({1}, depth);
            const json longer = deep({1, 2}, depth);

            const json smaller_object = deep({{"a", 1}}, depth);
            const json larger_object = deep({{"a", 1}, {"b", 2}}, depth);
            CHECK((shorter <=> longer) == std::partial_ordering::less); // *NOPAD*
            CHECK((longer <=> shorter) == std::partial_ordering::greater); // *NOPAD*
        }

        // elements that cannot be ordered
        {
            const double nan = std::numeric_limits<double>::quiet_NaN();
            const json lhs = deep({nan, 1}, depth);
            const json rhs = deep({nan, 2}, depth);
            // operator<=> stops there, as std::lexicographical_compare_three_way
            // does, and operator< is derived from it
            CHECK((lhs <=> rhs) == std::partial_ordering::unordered); // *NOPAD*
            CHECK_FALSE(lhs < rhs);
        }
    }
}

TEST_CASE("operator<=> of binary values with a different subtype does not depend on nesting depth")
{
    // #5654: std::vector<std::uint8_t>::operator<=>, which the binary type's
    // own operator<=> uses, ignores the subtype that operator== checks. So a
    // pair of binary values with the same bytes but a different subtype is
    // unequal, yet <=>-equivalent - the same inconsistency between == and <=>
    // that a NaN has. Within the nesting bound, an array compares itself
    // with std::vector's own operator<=>, which treats an equivalent pair as
    // undecided and lets the next element decide, same as
    // std::lexicographical_compare_three_way does. Past the bound,
    // compare_iteratively<true>() takes over and must classify the pair the
    // same way, or the result of operator<=> - and of <, which C++20 derives
    // from it - depends on how deeply the values are nested.
    const json a = json::array({json::binary({1}, 1), 1});
    const json b = json::array({json::binary({1}, 2), 2});

    // the root inconsistency: unequal, yet <=>-equivalent
    CHECK_FALSE(a[0] == b[0]);
    CHECK((a[0] <=> b[0]) == std::partial_ordering::equivalent); // *NOPAD*

    const auto deep = [](const json & j, const std::size_t depth)
    {
        json result = j;
        for (std::size_t i = 0; i < depth; ++i)
        {
            result = json::array({std::move(result)});
        }
        return result;
    };

    // 127 levels stay within nesting_depth_limit() (128); 128 and 200 do not,
    // and must still agree with the levels that do
    for (const std::size_t depth : std::vector<std::size_t> {0, 127, 128, 200})
    {
        CAPTURE(depth)
        const json x = deep(a, depth);
        const json y = deep(b, depth);
        CHECK((x <=> y) == std::partial_ordering::less); // *NOPAD*
        CHECK((y <=> x) == std::partial_ordering::greater); // *NOPAD*
        CHECK(x < y);
        CHECK(y > x);
        CHECK_FALSE(y < x);
    }
}

#endif // JSON_HAS_THREE_WAY_COMPARISON
#endif
