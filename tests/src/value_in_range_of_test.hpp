//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

// shared between unit-32bit.cpp (which must keep including this header,
// because JSON_32bitTest=ONLY builds only that file) and unit-bjdata.cpp

#include <climits> // CHAR_BIT
#include <limits>
#include <string>
#include <type_traits>

#include <nlohmann/json.hpp>

template <typename OfType, typename T, bool MinInRange, bool MaxInRange>
struct trait_test_arg
{
    using of_type = OfType;
    using type = T;
    static constexpr bool min_in_range = MinInRange;
    static constexpr bool max_in_range = MaxInRange;
};

TEST_CASE_TEMPLATE_DEFINE("value_in_range_of trait", T, value_in_range_of_test) // NOLINT(readability-math-missing-parentheses)
{
    using nlohmann::detail::value_in_range_of;

    using of_type = typename T::of_type;
    using type = typename T::type;
    constexpr bool min_in_range = T::min_in_range;
    constexpr bool max_in_range = T::max_in_range;

    type const val_min = std::numeric_limits<type>::min();
    type const val_min2 = val_min + 1;
    type const val_max = std::numeric_limits<type>::max();
    type const val_max2 = val_max - 1;

    REQUIRE(CHAR_BIT == 8);

    std::string of_type_str;
    if (std::is_unsigned<of_type>::value)
    {
        of_type_str += "u";
    }
    of_type_str += "int";
    of_type_str += std::to_string(sizeof(of_type) * 8);

    INFO("of_type := ", of_type_str);

    std::string type_str;
    if (std::is_unsigned<type>::value)
    {
        type_str += "u";
    }
    type_str += "int";
    type_str += std::to_string(sizeof(type) * 8);

    INFO("type := ", type_str);

    CAPTURE(val_min)
    CAPTURE(min_in_range)
    CAPTURE(val_max)
    CAPTURE(max_in_range)

    if (min_in_range)
    {
        CHECK(value_in_range_of<of_type>(val_min));
        CHECK(value_in_range_of<of_type>(val_min2));
    }
    else
    {
        CHECK_FALSE(value_in_range_of<of_type>(val_min));
        CHECK_FALSE(value_in_range_of<of_type>(val_min2));
    }

    if (max_in_range)
    {
        CHECK(value_in_range_of<of_type>(val_max));
        CHECK(value_in_range_of<of_type>(val_max2));
    }
    else
    {
        CHECK_FALSE(value_in_range_of<of_type>(val_max));
        CHECK_FALSE(value_in_range_of<of_type>(val_max2));
    }
}
