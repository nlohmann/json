//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-regression2.cpp (std::variant, std::any
// and std::optional regression tests). It is kept in a separate translation unit so the
// (much larger) unit-regression2.cpp is built for C++11 only and not rebuilt for every C++
// standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#ifdef JSON_HAS_CPP_17
#include <string>
#include <type_traits>
#include <vector>

#include <any>
#include <variant>

#if __has_include(<optional>)
    #include <optional>
#elif __has_include(<experimental/optional>)
    #include <experimental/optional>
#endif

/////////////////////////////////////////////////////////////////////
// for #4804
/////////////////////////////////////////////////////////////////////
using json_4804 = nlohmann::json::with_binary_t<std::vector<std::byte>>;

TEST_CASE("regression tests 2 (C++17)")
{
    SECTION("issue #1292 - Serializing std::variant causes stack overflow")
    {
        static_assert(!std::is_constructible<json, std::variant<int, float>>::value, "unexpected value");
    }

    SECTION("issue #5066 - MSVC converts json to std::variant<json> via the conversion operator")
    {
        // std::variant<json> must not be retrievable via get<>(), because otherwise the
        // implicit conversion operator becomes a candidate that MSVC picks over the variant's
        // converting constructor, routing a number through the string from_json overload
        static_assert(!nlohmann::detail::is_detected<nlohmann::detail::get_template_function, const json&, std::variant<json>>::value,
                      "std::variant<json> must not be retrievable via get<>()");

        // clang before 7 cannot instantiate libstdc++'s std::variant<json>
#if !(defined(__clang__) && __clang_major__ < 7)
        // push_back, not emplace_back: #5066 needs the implicit conversion
        // from json to the vector's value type
        std::vector<std::variant<json>> v;
        v.push_back(json(1)); // NOLINT(hicpp-use-emplace,modernize-use-emplace)
        CHECK(std::get<0>(v[0]) == 1);
#endif
    }
}

#endif
