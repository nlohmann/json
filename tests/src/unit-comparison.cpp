//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake selects the C++ standard versions with which to build a
// unit test based on the presence of JSON_HAS_CPP_<VERSION> macros.
// When using macros that are only defined for particular versions of the standard
// (e.g., JSON_HAS_FILESYSTEM for C++17 and up), please mention the corresponding
// version macro in a comment close by, like this:
// JSON_HAS_CPP_<VERSION> (do not remove; see note at top of file)

#include "doctest_compatibility.h"

#include <algorithm>

#include <cctype>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

#if JSON_HAS_THREE_WAY_COMPARISON
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

#endif

namespace
{
// helper function to check std::less<json::value_t>
// see https://en.cppreference.com/w/cpp/utility/functional/less
template <typename A, typename B, typename U = std::less<json::value_t>>
bool f(A a, B b, U u = U())
{
    return u(a, b);
}
} // namespace

TEST_CASE("lexicographical comparison operators")
{
    constexpr auto f_ = false;
    constexpr auto _t = true;
    constexpr auto nan = std::numeric_limits<json::number_float_t>::quiet_NaN();
#if JSON_HAS_THREE_WAY_COMPARISON
    constexpr auto lt = std::partial_ordering::less;
    constexpr auto gt = std::partial_ordering::greater;
    constexpr auto eq = std::partial_ordering::equivalent;
    constexpr auto un = std::partial_ordering::unordered;
#endif

#if JSON_HAS_THREE_WAY_COMPARISON
    INFO("using 3-way comparison");
#endif

#if JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
    INFO("using legacy comparison");
#endif

    //REQUIRE(std::numeric_limits<json::number_float_t>::has_quiet_NaN);
    REQUIRE(std::isnan(nan));

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
            REQUIRE(expected_lt.size() == j_types.size());
            for (size_t i = 0; i < j_types.size(); ++i)
            {
                REQUIRE(expected_lt[i].size() == j_types.size());
                for (size_t j = 0; j < j_types.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    // check precomputed values
#if JSON_HAS_THREE_WAY_COMPARISON
                    // JSON_HAS_CPP_20 (do not remove; see note at top of file)
                    CHECK((j_types[i] < j_types[j]) == expected_lt[i][j]);
#else
                    CHECK(operator<(j_types[i], j_types[j]) == expected_lt[i][j]);
#endif
                    CHECK(f(j_types[i], j_types[j]) == expected_lt[i][j]);
                }
            }
        }
#if JSON_HAS_THREE_WAY_COMPARISON
        // JSON_HAS_CPP_20 (do not remove; see note at top of file)
        SECTION("comparison: 3-way")
        {
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
#endif
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

            CHECK_FALSE(above_int64_max == negative_one);
            CHECK(above_int64_max != negative_one);
            CHECK(negative_one < above_int64_max);
            CHECK(negative_one <= above_int64_max);
            CHECK_FALSE(negative_one > above_int64_max);
            CHECK_FALSE(negative_one >= above_int64_max);
            CHECK_FALSE(above_int64_max < negative_one);
            CHECK_FALSE(above_int64_max <= negative_one);
            CHECK(above_int64_max > negative_one);
            CHECK(above_int64_max >= negative_one);
            CHECK(negative_one != above_int64_max);
            CHECK_FALSE(negative_one == above_int64_max);

            CHECK_FALSE(max_uint64 == negative_one);
            CHECK(max_uint64 != negative_one);
            CHECK(negative_one < max_uint64);
            CHECK(negative_one <= max_uint64);
            CHECK_FALSE(negative_one > max_uint64);
            CHECK_FALSE(negative_one >= max_uint64);
            CHECK_FALSE(max_uint64 < negative_one);
            CHECK_FALSE(max_uint64 <= negative_one);
            CHECK(max_uint64 > negative_one);
            CHECK(max_uint64 >= negative_one);
            CHECK(negative_one != max_uint64);
            CHECK_FALSE(negative_one == max_uint64);

            CHECK_FALSE(one == above_int64_max);
            CHECK(one != above_int64_max);
            CHECK(one < above_int64_max);
            CHECK(one <= above_int64_max);
            CHECK_FALSE(one > above_int64_max);
            CHECK_FALSE(one >= above_int64_max);
            CHECK_FALSE(above_int64_max < one);
            CHECK_FALSE(above_int64_max <= one);
            CHECK(above_int64_max > one);
            CHECK(above_int64_max >= one);

            CHECK_FALSE(max_int64 == above_int64_max);
            CHECK(max_int64 != above_int64_max);
            CHECK(max_int64 < above_int64_max);
            CHECK(max_int64 <= above_int64_max);
            CHECK_FALSE(max_int64 > above_int64_max);
            CHECK_FALSE(max_int64 >= above_int64_max);
            CHECK_FALSE(above_int64_max < max_int64);
            CHECK_FALSE(above_int64_max <= max_int64);
            CHECK(above_int64_max > max_int64);
            CHECK(above_int64_max >= max_int64);

#if JSON_HAS_THREE_WAY_COMPARISON
            // JSON_HAS_CPP_20 (do not remove; see note at top of file)
            CHECK((negative_one <=> above_int64_max) == std::partial_ordering::less); // *NOPAD*
            CHECK((above_int64_max <=> negative_one) == std::partial_ordering::greater); // *NOPAD*
            CHECK((negative_one <=> max_uint64) == std::partial_ordering::less); // *NOPAD*
            CHECK((max_uint64 <=> negative_one) == std::partial_ordering::greater); // *NOPAD*
            CHECK((one <=> above_int64_max) == std::partial_ordering::less); // *NOPAD*
            CHECK((above_int64_max <=> one) == std::partial_ordering::greater); // *NOPAD*
            CHECK((max_int64 <=> above_int64_max) == std::partial_ordering::less); // *NOPAD*
            CHECK((above_int64_max <=> max_int64) == std::partial_ordering::greater); // *NOPAD*
#endif
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

            CHECK_FALSE(below_two_63 == two_63);
            CHECK_FALSE(max_int64 == two_63);
            CHECK(below_two_63 != max_int64);
            CHECK(below_two_63 < max_int64);
            CHECK(below_two_63 < two_63);
            CHECK(max_int64 < two_63);
            CHECK(two_63 > max_int64);
            CHECK_FALSE(two_63 < max_int64);

            // the same past the unsigned range
            const json max_uint64 = (std::numeric_limits<std::uint64_t>::max)();
            const json two_64 = 18446744073709551616.0;
            CHECK_FALSE(max_uint64 == two_64);
            CHECK(max_uint64 < two_64);
            CHECK(two_64 > max_uint64);

            // values a double represents exactly still compare equal
            CHECK(json(1) == json(1.0));
            CHECK(json(1u) == json(1.0));
            CHECK(json(-3) == json(-3.0));
            CHECK(json(1) < json(1.5));
            CHECK(json(1.5) < json(2));
            CHECK(json(2) > json(1.5));
            CHECK(json(-1) > json(-1.5));
            CHECK(json(-1.5) < json(-1));
            CHECK(json(-2) < json(-1.5));

            // a float below the range of the integer type
            CHECK(json(0) > json(-1e30));
            CHECK(json(-1e30) < json(0));
            CHECK(json(0u) > json(-0.5));
            CHECK(json(-0.5) < json(0u));

            // a NaN operand stays unordered against either integer kind
            CHECK_FALSE(json(1) == json(nan));
            CHECK_FALSE(json(1) < json(nan));
            CHECK_FALSE(json(nan) < json(1));
            CHECK_FALSE(json(1u) == json(nan));

#if JSON_HAS_THREE_WAY_COMPARISON
            // JSON_HAS_CPP_20 (do not remove; see note at top of file)
            CHECK((max_int64 <=> two_63) == std::partial_ordering::less); // *NOPAD*
            CHECK((two_63 <=> max_int64) == std::partial_ordering::greater); // *NOPAD*
            CHECK((below_two_63 <=> max_int64) == std::partial_ordering::less); // *NOPAD*
            CHECK((max_uint64 <=> two_64) == std::partial_ordering::less); // *NOPAD*
            CHECK((json(1) <=> json(1.0)) == std::partial_ordering::equivalent); // *NOPAD*
            CHECK((json(1) <=> json(nan)) == std::partial_ordering::unordered); // *NOPAD*
#endif
        }

        SECTION("compares unordered")
        {
            std::vector<std::vector<bool>> expected =
            {
                //0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  0
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  1
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  2
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  3
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  4
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  5
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  6
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  7
                {f_, f_, _t, _t, _t, _t, _t, _t, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  8
                {f_, f_, _t, _t, _t, _t, _t, _t, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, //  9
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 10
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 11
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 12
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 13
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 14
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 15
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 16
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 17
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 18
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, _t, _t}, // 19
                {_t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t}, // 20
                {_t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t, _t}, // 21
            };

            // check if two values compare unordered as expected
            REQUIRE(expected.size() == j_values.size());
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                REQUIRE(expected[i].size() == j_values.size());
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CHECK(json::compares_unordered(j_values[i], j_values[j]) == expected[i][j]);
                }
            }
        }

#if JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
        SECTION("compares unordered (inverse)")
        {
            std::vector<std::vector<bool>> expected =
            {
                //0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  0
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  1
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  2
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  3
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  4
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  5
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  6
                {f_, f_, f_, f_, f_, f_, f_, f_, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  7
                {f_, f_, _t, _t, _t, _t, _t, _t, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  8
                {f_, f_, _t, _t, _t, _t, _t, _t, _t, _t, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, //  9
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 10
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 11
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 12
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 13
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 14
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 15
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 16
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 17
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 18
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 19
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 20
                {f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_, f_}, // 21
            };

            // check that two values compare unordered as expected (with legacy-mode enabled)
            REQUIRE(expected.size() == j_values.size());
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                REQUIRE(expected[i].size() == j_values.size());
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CAPTURE(j_values[i])
                    CAPTURE(j_values[j])
                    CHECK(json::compares_unordered(j_values[i], j_values[j], true) == expected[i][j]);
                }
            }
        }
#endif

        SECTION("comparison: equal")
        {
            // check that two values compare equal
            REQUIRE(expected_eq.size() == j_values.size());
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                REQUIRE(expected_eq[i].size() == j_values.size());
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CHECK((j_values[i] == j_values[j]) == expected_eq[i][j]);
                }
            }

            // compare with null pointer
            json j_null;
            CHECK(j_null == nullptr);
            CHECK(nullptr == j_null);
        }

        SECTION("comparison: not equal")
        {
            // check that two values compare unequal as expected
            // operator!= now means exactly !(a==b) without special cases for NaN/discarded
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)

                    CHECK((j_values[i] != j_values[j]) == !(j_values[i] == j_values[j]));
                }
            }

            // compare with null pointer
            const json j_null;
            CHECK((j_null != nullptr) == !(j_null == nullptr));
            CHECK((nullptr != j_null) == !(nullptr == j_null));
        }

        SECTION("comparison: less")
        {
            // check that two values compare less than as expected
            REQUIRE(expected_lt.size() == j_values.size());
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                REQUIRE(expected_lt[i].size() == j_values.size());
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CHECK((j_values[i] < j_values[j]) == expected_lt[i][j]);
                }
            }
        }

        SECTION("comparison: less than or equal equal")
        {
            // check that two values compare less than or equal as expected
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    if (json::compares_unordered(j_values[i], j_values[j], true))
                    {
                        // if two values compare unordered,
                        // check that the boolean comparison result is always false
                        CHECK_FALSE(j_values[i] <= j_values[j]);
                    }
                    else
                    {
                        // otherwise, check that they compare according to their definition
                        // as the inverse of less than with the operand order reversed
                        CHECK((j_values[i] <= j_values[j]) == !(j_values[j] < j_values[i]));
                    }
                }
            }
        }

        SECTION("comparison: greater than")
        {
            // check that two values compare greater than as expected
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    if (json::compares_unordered(j_values[i], j_values[j]))
                    {
                        // if two values compare unordered,
                        // check that the boolean comparison result is always false
                        CHECK_FALSE(j_values[i] > j_values[j]);
                    }
                    else
                    {
                        // otherwise, check that they compare according to their definition
                        // as the inverse of less than or equal which is defined as
                        // the inverse of less than with the operand order reversed
                        CHECK((j_values[i] > j_values[j]) == !(j_values[i] <= j_values[j]));
                        CHECK((j_values[i] > j_values[j]) == !!(j_values[j] < j_values[i]));
                    }
                }
            }
        }

        SECTION("comparison: greater than or equal")
        {
            // check that two values compare greater than or equal as expected
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    if (json::compares_unordered(j_values[i], j_values[j], true))
                    {
                        // if two values compare unordered,
                        // check that the boolean result is always false
                        CHECK_FALSE(j_values[i] >= j_values[j]);
                    }
                    else
                    {
                        // otherwise, check that they compare according to their definition
                        // as the inverse of less than
                        CHECK((j_values[i] >= j_values[j]) == !(j_values[i] < j_values[j]));
                    }
                }
            }
        }

#if JSON_HAS_THREE_WAY_COMPARISON
        // JSON_HAS_CPP_20 (do not remove; see note at top of file)
        SECTION("comparison: 3-way")
        {
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
#endif
    }

#if JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
    SECTION("parser callback regression")
    {
        SECTION("filter specific element")
        {
            const auto* s_object = R"(
                {
                    "foo": 2,
                    "bar": {
                        "baz": 1
                    }
                }
            )";
            const auto* s_array = R"(
                [1,2,[3,4,5],4,5]
            )";

            const json j_object = json::parse(s_object, [](int /*unused*/, json::parse_event_t /*unused*/, const json & j) noexcept
            {
                // filter all number(2) elements
                return j != json(2);
            });

            CHECK (j_object == json({{"bar", {{"baz", 1}}}}));

            const json j_array = json::parse(s_array, [](int /*unused*/, json::parse_event_t /*unused*/, const json & j) noexcept
            {
                return j != json(2);
            });

            CHECK (j_array == json({1, {3, 4, 5}, 4, 5}));
        }
    }
#endif
}

#if JSON_HAS_THREE_WAY_COMPARISON
// JSON_HAS_CPP_20 (do not remove; see note at top of file)

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

#endif

namespace
{
// orders keys ascending or descending, as chosen when a map is created
template<class Key>
class directed_less
{
  public:
    directed_less() = default;

    explicit directed_less(const bool descending) noexcept
        : m_descending(descending)
    {}

    bool operator()(const Key& lhs, const Key& rhs) const
    {
        return m_descending ? rhs < lhs : lhs < rhs;
    }

  private:
    bool m_descending = false;
};

// An object type that, like std::unordered_map, enumerates its entries in no
// fixed order - ascending or descending by key, depending on how the map was
// created - and whose operator== does not depend on that order.
// std::unordered_map itself cannot be used here: the standard does not
// require it to accept an incomplete mapped type such as basic_json, and
// libstdc++ 6 to 9 as well as the EDG front ends of icpc and nvc++ reject
// basic_json<std::unordered_map>. std::map, the default object type, works
// with all supported compilers.
template<class Key, class Value, class /*Compare*/, class Allocator>
struct unordered_object_t : std::map<Key, Value, directed_less<Key>, Allocator>
{
    using base_type = std::map<Key, Value, directed_less<Key>, Allocator>;
    using base_type::base_type;

    friend bool operator==(const unordered_object_t& lhs, const unordered_object_t& rhs)
    {
        return lhs.size() == rhs.size() && std::all_of(lhs.begin(), lhs.end(), [&rhs](const std::pair<const Key, Value>& entry)
        {
            const auto it = rhs.find(entry.first);
            return it != rhs.end() && it->second == entry.second;
        });
    }

    friend bool operator!=(const unordered_object_t& lhs, const unordered_object_t& rhs)
    {
        return !(lhs == rhs);
    }
};
using unordered_json = nlohmann::basic_json<unordered_object_t>;

// the entries "0" to "9", enumerated in ascending or in descending order
unordered_json make_unordered_object(const bool descending)
{
    unordered_json j = unordered_json::object_t(directed_less<std::string>(descending));
    for (int i = 0; i < 10; ++i)
    {
        j[std::to_string(i)] = i;
    }
    return j;
}

template<typename Json>
Json nest(Json j, const std::size_t depth)
{
    for (std::size_t i = 0; i < depth; ++i)
    {
        Json outer = Json::object();
        outer["x"] = std::move(j);
        j = std::move(outer);
    }
    return j;
}

// a std::map comparator with state: case-insensitive, unless constructed
// case-sensitive. Used to check that copying an object copies the original's
// comparator rather than default-constructing a new one (see #5649).
struct key_case_less
{
    key_case_less() = default;
    explicit key_case_less(const bool cs) noexcept : case_sensitive(cs) {}

    bool operator()(const std::string& a, const std::string& b) const
    {
        if (case_sensitive)
        {
            return a < b;
        }
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(),
                                            [](unsigned char x, unsigned char y)
        {
            return std::tolower(x) < std::tolower(y);
        });
    }

    bool case_sensitive = false;
};

template<class Key, class Value, class /*Compare*/, class Allocator>
using key_case_map = std::map<Key, Value, key_case_less, Allocator>;
using key_case_json = nlohmann::basic_json<key_case_map>;

// the innermost value of a chain of single-element arrays
template<typename Json>
const Json& innermost(const Json& j)
{
    const Json* p = &j;
    while (p->is_array())
    {
        p = &(*p)[0];
    }
    return *p;
}

// orders keys case-insensitively, so "key" and "KEY" compare equivalent
// (neither less than the other) although they are not equal
struct case_insensitive_less
{
    bool operator()(const std::string& a, const std::string& b) const
    {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(),
                                            [](unsigned char x, unsigned char y)
        {
            return std::tolower(x) < std::tolower(y);
        });
    }
};

template<class Key, class Value, class /*Compare*/, class Allocator>
using case_insensitive_map = std::map<Key, Value, case_insensitive_less, Allocator>;
using ci_json = nlohmann::basic_json<case_insensitive_map>;
} // namespace

TEST_CASE("equality of objects whose entries have no fixed order")
{
    // Values nested deeper than a bound are compared without the call stack,
    // entry by entry. That must agree with the object type's own operator==,
    // which for unordered_object_t (as for std::unordered_map) does not
    // depend on the order of the entries, and for ordered_map does.
    REQUIRE(make_unordered_object(true).begin().key() == "9");
    REQUIRE(make_unordered_object(false).begin().key() == "0");

    for (const std::size_t depth : std::vector<std::size_t> {0, 200})
    {
        CAPTURE(depth)

        const unordered_json descending = nest(make_unordered_object(true), depth);
        const unordered_json ascending = nest(make_unordered_object(false), depth);
        CHECK(descending == ascending);
        CHECK_FALSE(descending != ascending);

        // a copy is equal to its original
        const unordered_json copy = descending; // NOLINT(performance-unnecessary-copy-initialization)
        CHECK(copy == descending);

        // a different value, a different key, or another entry still count
        unordered_json other_value = make_unordered_object(true);
        other_value["5"] = 42;
        CHECK_FALSE(nest(other_value, depth) == ascending);

        unordered_json other_key = make_unordered_object(true);
        other_key.erase("5");
        other_key["50"] = 5;
        CHECK_FALSE(nest(other_key, depth) == ascending);

        unordered_json more_entries = make_unordered_object(true);
        more_entries["10"] = 10;
        CHECK_FALSE(nest(more_entries, depth) == ascending);
        CHECK_FALSE(ascending == nest(more_entries, depth));

        // ordered_json compares its entries in sequence
        const nlohmann::ordered_json ab = nest(nlohmann::ordered_json({{"a", 1}, {"b", 2}}), depth);
        const nlohmann::ordered_json ba = nest(nlohmann::ordered_json({{"b", 2}, {"a", 1}}), depth);
        CHECK_FALSE(ab == ba);
        CHECK(ab != ba);
    }
}

TEST_CASE("copying an object preserves its comparator's state")
{
    // Past the iterative deep copy's nesting bound, an object copy used to be
    // built with a default-constructed comparator instead of a copy of the
    // original's. For an object type whose comparator carries state - here, a
    // std::map that compares keys case-sensitively only when created that way
    // - this reordered the copy's keys and could even drop entries that the
    // original's comparator kept distinct (see #5649).
    key_case_json object = key_case_json::object_t(key_case_less(true)); // case-sensitive
    object["b"] = 1;
    object["B"] = 2;
    object["a"] = 3;
    REQUIRE(object.dump() == R"({"B":2,"a":3,"b":1})");

    for (const std::size_t depth : std::vector<std::size_t> {0, 127, 128, 200})
    {
        CAPTURE(depth)

        key_case_json original = object;
        for (std::size_t i = 0; i < depth; ++i)
        {
            original = key_case_json::array({std::move(original)});
        }

        {
            const key_case_json copy = original; // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(innermost(copy).size() == 3);
            CHECK(innermost(copy).dump() == R"({"B":2,"a":3,"b":1})");
            CHECK(copy == original);
        }

        {
            key_case_json copy = key_case_json::array();
            copy = original;
            CHECK(innermost(copy).size() == 3);
            CHECK(innermost(copy).dump() == R"({"B":2,"a":3,"b":1})");
            CHECK(copy == original);
        }
    }
}

TEST_CASE("equality of an object whose comparator treats different keys as equivalent")
{
    // https://github.com/nlohmann/json/issues/5655: past the nesting bound,
    // the entries are compared without the call stack, and a key that finds
    // no counterpart at the same position is looked up with find(), which
    // uses the object's own comparator. A case-insensitive comparator then
    // finds "KEY" for "key" and must not accept that pair as a match - the
    // object type's own operator==, like std::map's, compares keys with ==.
    ci_json a = ci_json::object();
    a["key"] = 1;
    ci_json b = ci_json::object();
    b["KEY"] = 1;

    // sanity check: the object type's own comparison already disagrees
    CHECK_FALSE(a.get_ref<const ci_json::object_t&>() == b.get_ref<const ci_json::object_t&>());

    for (const std::size_t depth : std::vector<std::size_t> {0, 127, 128, 200})
    {
        CAPTURE(depth)

        const ci_json x = nest(a, depth);
        const ci_json y = nest(b, depth);
        CHECK_FALSE(x == y);
        CHECK(x != y);
    }
}

TEST_CASE("containers are compared element by element")
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
            CHECK_FALSE(a == b);
            CHECK(a != b);
            CHECK(a < b);
            CHECK(b > a);
            CHECK_FALSE(b < a);
#if JSON_HAS_THREE_WAY_COMPARISON
            // JSON_HAS_CPP_20 (do not remove; see note at top of file)
            CHECK((a <=> b) == std::partial_ordering::less); // *NOPAD*
            CHECK((b <=> a) == std::partial_ordering::greater); // *NOPAD*
            CHECK((a <=> a) == std::partial_ordering::equivalent); // *NOPAD*
#endif
        }

        // a container that is a prefix of the other one
        {
            // the one that runs out of elements first is the smaller one
            const json shorter = deep({1}, depth);
            const json longer = deep({1, 2}, depth);
            CHECK(shorter < longer);
            CHECK(longer > shorter);
            CHECK_FALSE(longer < shorter);
            CHECK_FALSE(shorter == longer);

            const json smaller_object = deep({{"a", 1}}, depth);
            const json larger_object = deep({{"a", 1}, {"b", 2}}, depth);
            CHECK(smaller_object < larger_object);
            CHECK(larger_object > smaller_object);
            CHECK_FALSE(smaller_object == larger_object);
#if JSON_HAS_THREE_WAY_COMPARISON
            // JSON_HAS_CPP_20 (do not remove; see note at top of file)
            CHECK((shorter <=> longer) == std::partial_ordering::less); // *NOPAD*
            CHECK((longer <=> shorter) == std::partial_ordering::greater); // *NOPAD*
#endif
        }

        // elements that cannot be ordered
        {
            const double nan = std::numeric_limits<double>::quiet_NaN();
            const json lhs = deep({nan, 1}, depth);
            const json rhs = deep({nan, 2}, depth);

            CHECK_FALSE(lhs == lhs);
            CHECK_FALSE(rhs < lhs);
#if JSON_HAS_THREE_WAY_COMPARISON
            // JSON_HAS_CPP_20 (do not remove; see note at top of file)
            // operator<=> stops there, as std::lexicographical_compare_three_way
            // does, and operator< is derived from it
            CHECK((lhs <=> rhs) == std::partial_ordering::unordered); // *NOPAD*
            CHECK_FALSE(lhs < rhs);
#else
            // operator< skips a pair of elements that cannot be ordered, as
            // std::lexicographical_compare does, and the next pair decides
            CHECK(lhs < rhs);
#endif
        }
    }
}

#if JSON_HAS_THREE_WAY_COMPARISON
// JSON_HAS_CPP_20 (do not remove; see note at top of file)
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
#endif
