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

#include <nlohmann/json.hpp>
using json = nlohmann::json;

// JSON_HAS_CPP_20 (do not remove; see note at top of file)
#if JSON_HAS_STD_FORMAT

#include <iterator>
#include <string>

TEST_CASE("std::formatter<nlohmann::json>")
{
    SECTION("compact formatting matches dump()")
    {
        CHECK(std::format("{}", json(nullptr)) == json(nullptr).dump());
        CHECK(std::format("{}", json(true)) == json(true).dump());
        CHECK(std::format("{}", json(42)) == json(42).dump());
        CHECK(std::format("{}", json(42.23)) == json(42.23).dump());
        CHECK(std::format("{}", json("foo")) == json("foo").dump());
        CHECK(std::format("{}", json::array({1, 2, 3})) == json::array({1, 2, 3}).dump());

        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        CHECK(std::format("{}", j) == j.dump());
    }

    SECTION("'#' triggers pretty-printing with an indent of 4, like dump(4)")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        CHECK(std::format("{:#}", j) == j.dump(4));
        CHECK(std::format("{:#}", json::array()) == json::array().dump(4));
    }

    SECTION("format args other than an empty spec or '#' are rejected")
    {
        // std::vformat parses the format string at runtime (unlike std::format, whose
        // format_string type is checked at compile time), so it lets us verify that an
        // invalid spec throws std::format_error without needing a compile-time-illegal
        // format string.
        const json j = 42;
        CHECK_THROWS_AS(std::vformat("{:x}", std::make_format_args(j)), std::format_error);
        CHECK_THROWS_AS(std::vformat("{:10}", std::make_format_args(j)), std::format_error);
    }

    SECTION("std::format_to writes through an arbitrary output iterator")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        std::string out;
        std::format_to(std::back_inserter(out), "{}", j);
        CHECK(out == j.dump());
    }
}

#endif
