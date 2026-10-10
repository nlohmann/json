//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++20-only part of unit-iterators2.cpp (iterators and
// std::ranges). It is kept in a separate translation unit so the (much larger) unit-
// iterators2.cpp is built for C++11 only and not rebuilt for every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#ifdef JSON_HAS_CPP_20
#include <iterator>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#if JSON_HAS_RANGES
    #include <algorithm>
    #include <ranges>
#endif

TEST_CASE("iterators 2 (C++20)")
{
#if JSON_HAS_RANGES
    SECTION("ranges")
    {
        SECTION("concepts")
        {
            using nlohmann::detail::iteration_proxy_value;
            CHECK(std::bidirectional_iterator<json::iterator>);
            CHECK(std::input_iterator<iteration_proxy_value<json::iterator>>);

            CHECK(std::is_same<json::iterator, std::ranges::iterator_t<json>>::value);
            CHECK(std::ranges::bidirectional_range<json>);

            using nlohmann::detail::iteration_proxy;
            using items_type = decltype(std::declval<json&>().items());
            CHECK(std::is_same<items_type, iteration_proxy<json::iterator>>::value);
            CHECK(std::is_same<iteration_proxy_value<json::iterator>, std::ranges::iterator_t<items_type>>::value);
            CHECK(std::ranges::input_range<items_type>);
        }

        SECTION("algorithms")
        {
            SECTION("copy")
            {
                json j{"foo", "bar"};
                auto j_copied = json::array();

                std::ranges::copy(j, std::back_inserter(j_copied));

                CHECK(j == j_copied);
            }

            SECTION("find_if")
            {
                json j{1, 3, 2, 4};
                auto j_even = json::array();

#if JSON_USE_IMPLICIT_CONVERSIONS
                auto it = std::ranges::find_if(j, [](int v) noexcept
                {
                    return (v % 2) == 0;
                });
#else
                auto it = std::ranges::find_if(j, [](const json & j) noexcept
                {
                    int v;
                    j.get_to(v);
                    return (v % 2) == 0;
                });
#endif

                CHECK(*it == 2);
            }
        }

        SECTION("views")
        {
            SECTION("reverse")
            {
                json j{1, 2, 3, 4, 5};
                json j_expected{5, 4, 3, 2, 1};

                auto reversed = j | std::views::reverse;
                CHECK(reversed == j_expected);
            }

            SECTION("transform")
            {
                json j
                {
                    { "a_key", "a_value"},
                    { "b_key", "b_value"},
                    { "c_key", "c_value"},
                };
                json j_expected{"a_key", "b_key", "c_key"};

                // NOLINTNEXTLINE(fuchsia-trailing-return)
                auto transformed = j.items() | std::views::transform([](const auto & item) -> std::string_view
                {
                    return item.key();
                });
                auto j_transformed = json::array();
                std::ranges::copy(transformed, std::back_inserter(j_transformed));

                CHECK(j_transformed == j_expected);
            }
        }
    }
#endif
}

#endif
