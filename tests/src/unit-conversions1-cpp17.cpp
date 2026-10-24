//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-conversions1.cpp (conversions to and from
// std::string_view). It is kept in a separate translation unit so the (much larger) unit-
// conversions1.cpp is built for C++11 only and not rebuilt for every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

// workaround for MSVC, which does not set __cplusplus to the language version (#464)
#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_HAS_CXX17) && _HAS_CXX17 == 1) // fix for issue #464
    #define JSON_HAS_CPP_17
#endif

#ifdef JSON_HAS_CPP_17
#include <string>
#include <string_view>

#if __has_include(<optional>)
    #include <optional>
#elif __has_include(<experimental/optional>)
    #include <experimental/optional>
#endif

TEST_CASE("value conversion (C++17)")
{
    SECTION("get a string (explicit)")
    {
        const json::string_t s_reference{"Hello world"};
        json j(s_reference);

        SECTION("std::string_view")
        {
            std::string_view const s = j.get<std::string_view>();
            CHECK(json(s) == j);
        }

        SECTION("exception in case of a non-string type using string_view")
        {
            CHECK_THROWS_WITH_AS(json(json::value_t::null).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is null", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::object).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is object", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::array).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is array", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::boolean).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is boolean", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::number_integer).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::number_unsigned).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::number_float).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
        }
    }

    SECTION("get a string (explicit, get_to)")
    {
        const json::string_t s_reference{"Hello world"};
        json j(s_reference);

        SECTION("std::string_view")
        {
            std::string const s = "previous value";
            std::string_view sv = s;
            j.get_to(sv);
            CHECK(json(sv) == j);
        }
    }

#if JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("get a string (implicit)")
    {
        const json::string_t s_reference{"Hello world"};
        json j(s_reference);

        SECTION("std::string_view")
        {
            std::string_view const s = j.get<std::string_view>();
            CHECK(json(s) == j);
        }
    }
#endif

}

#endif
