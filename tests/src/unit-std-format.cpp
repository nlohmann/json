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

    SECTION("a width sets the indent, like dump(width), with or without '#'")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        CHECK(std::format("{:2}", j) == j.dump(2));
        CHECK(std::format("{:#2}", j) == j.dump(2));
        CHECK(std::format("{:8}", j) == j.dump(8));
    }

    SECTION("fill-and-align sets the indent character, like dump(indent, indent_char)")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        CHECK(std::format("{:.>#}", j) == j.dump(4, '.'));
        CHECK(std::format("{:.>#3}", j) == j.dump(3, '.'));
        CHECK(std::format("{:.>3}", j) == j.dump(3, '.'));
        // the alignment direction itself ('<', '>', '^') has no separate meaning for
        // JSON values -- only the fill character before it is used as the indent character
        CHECK(std::format("{:.<3}", j) == j.dump(3, '.'));
        CHECK(std::format("{:.^3}", j) == j.dump(3, '.'));
    }

    SECTION("format args with no meaning for JSON values are rejected")
    {
        // std::vformat parses the format string at runtime (unlike std::format, whose
        // format_string type is checked at compile time), so it lets us verify that an
        // invalid spec throws std::format_error without needing a compile-time-illegal
        // format string.
        const json j = 42;
        CHECK_THROWS_AS(std::vformat("{:x}", std::make_format_args(j)), std::format_error);
        CHECK_THROWS_AS(std::vformat("{:+}", std::make_format_args(j)), std::format_error);   // sign
        CHECK_THROWS_AS(std::vformat("{:-}", std::make_format_args(j)), std::format_error);   // sign
        CHECK_THROWS_AS(std::vformat("{: }", std::make_format_args(j)), std::format_error);   // sign
        CHECK_THROWS_AS(std::vformat("{:04}", std::make_format_args(j)), std::format_error);  // '0' flag
        CHECK_THROWS_AS(std::vformat("{:.2}", std::make_format_args(j)), std::format_error);  // precision
        CHECK_THROWS_AS(std::vformat("{:L}", std::make_format_args(j)), std::format_error);   // locale
        const int dynamic_width = 4;
        CHECK_THROWS_AS(std::vformat("{:{}}", std::make_format_args(j, dynamic_width)), std::format_error); // dynamic width
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
