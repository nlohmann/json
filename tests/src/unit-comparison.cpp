//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake selects the C++ standard versions with which to build a
// unit test based on the presence of JSON_HAS_CPP_<VERSION> macros.
// When using macros that are only defined for particular versions of the standard
// (e.g., JSON_HAS_FILESYSTEM for C++17 and up), please mention the corresponding
// version macro in a comment close by, like this:
// JSON_HAS_CPP_<VERSION> (do not remove; see note at top of file)

#include "doctest_compatibility.h"

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
                        CHECK_FALSE(j_values[i] != j_values[j]);
                    }
                    else
                    {
                        // otherwise, check that they compare according to their definition
                        // as the inverse of equal
                        CHECK((j_values[i] != j_values[j]) == !(j_values[i] == j_values[j]));
                    }
                }
            }

            // compare with null pointer
            const json j_null;
            CHECK((j_null != nullptr) == false);
            CHECK((nullptr != j_null) == false);
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

            json j_object = json::parse(s_object, [](int /*unused*/, json::parse_event_t /*unused*/, const json & j) noexcept
            {
                // filter all number(2) elements
                return j != json(2);
            });

            CHECK (j_object == json({{"bar", {{"baz", 1}}}}));

            json j_array = json::parse(s_array, [](int /*unused*/, json::parse_event_t /*unused*/, const json & j) noexcept
            {
                return j != json(2);
            });

            CHECK (j_array == json({1, {3, 4, 5}, 4, 5}));
        }
    }
#endif
}
