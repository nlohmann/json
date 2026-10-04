//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// This file tests the opt-in JSON_DISABLE_TUPLE_REFERENCE_CONVERSION, so it
// defines the macro itself rather than relying on a -D flag, and runs in every
// build.
#ifdef JSON_DISABLE_TUPLE_REFERENCE_CONVERSION
    #undef JSON_DISABLE_TUPLE_REFERENCE_CONVERSION
#endif

#define JSON_DISABLE_TUPLE_REFERENCE_CONVERSION 1

#include <nlohmann/json.hpp>
using nlohmann::json;
using nlohmann::ordered_json;

#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

// clang before 4 and GCC before 5 cannot create a std::tuple of basic_json
// references at all, with or without JSON_DISABLE_TUPLE_REFERENCE_CONVERSION:
// the tuple constructors make them instantiate basic_json's conversion operator
// for libstdc++'s internal tuple bases, which fails hard
#if (defined(__clang__) && __clang_major__ < 4) || (!defined(__clang__) && defined(__GNUC__) && __GNUC__ < 5)
    #define SKIP_TESTS_FOR_JSON_REFERENCE_TUPLES
#endif

TEST_CASE("JSON_DISABLE_TUPLE_REFERENCE_CONVERSION")
{
    SECTION("json is not constructible from a one-element tuple of a json reference")
    {
        CHECK_FALSE(std::is_constructible<json, std::tuple<json&>>::value);
        CHECK_FALSE(std::is_constructible<json, std::tuple<const json&>>::value);
        CHECK_FALSE(std::is_constructible < json, std::tuple < json && >>::value);
        CHECK_FALSE(std::is_constructible<json, const std::tuple<json&>&>::value);
        CHECK_FALSE(std::is_constructible<ordered_json, std::tuple<ordered_json&>>::value);
    }

#ifndef SKIP_TESTS_FOR_JSON_REFERENCE_TUPLES
    SECTION("issue #2226 - tuple<const json&> from tuple<json&> keeps the reference")
    {
        json j = true;
        const std::tuple<const json&> tup(std::forward_as_tuple(j));
        CHECK(&std::get<0>(tup) == &j);
    }

    SECTION("tuple<json> from tuple<json&> copies the element")
    {
        const json j = {{"key", "value"}};
        const std::tuple<json> t1(std::forward_as_tuple(j));
        CHECK(std::get<0>(t1) == j);

        json j2 = "text";
        const std::tuple<json> t2(std::forward_as_tuple(std::move(j2)));
        CHECK(std::get<0>(t2) == "text");
    }
#endif

    SECTION("other tuple conversions are not affected")
    {
        const json j = true;

        // one-element tuple holding a json value
        CHECK(json(std::make_tuple(j)) == json::array({true}));

        // tuples with more than one element, even when holding references
        int i = 1;
#ifndef SKIP_TESTS_FOR_JSON_REFERENCE_TUPLES
        CHECK(json(std::forward_as_tuple(i, j)) == json::array({1, true}));
        CHECK(json(std::forward_as_tuple(j, j)) == json::array({true, true}));
#endif

        // one-element tuples holding references to other types
        std::string s = "text";
        CHECK(json(std::forward_as_tuple(s)) == json::array({"text"}));
        CHECK(json(std::forward_as_tuple(i)) == json::array({1}));

#ifndef SKIP_TESTS_FOR_JSON_REFERENCE_TUPLES
        // a reference to a different basic_json specialization
        ordered_json oj = true;
        CHECK(json(std::forward_as_tuple(oj)) == json::array({true}));
#endif
    }
}
