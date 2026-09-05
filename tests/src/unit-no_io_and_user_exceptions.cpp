//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This translation unit is a dedicated, small compile-and-run check for two
// configuration macros that (per #5423) were never exercised anywhere in the
// test matrix:
// - JSON_NO_IO, which removes the library's <istream>/<ostream> support
//   (operator<<, operator>>, and the stream-based overloads of dump()/parse())
// - the JSON_THROW_USER / JSON_TRY_USER / JSON_CATCH_USER trio, which lets a
//   user replace the library's internal exception handling
//
// Both macros are about excluding/replacing a facility the library would
// otherwise pull in on its own, and defining one has no bearing on the other,
// so -- to keep the test matrix small -- they are exercised together in a
// single dedicated file instead of two.
//
// JSON_NO_IO requires this file itself to never rely on <iostream>/<sstream>;
// only string-based parsing/dumping is used below.
#define JSON_NO_IO 1

// The user-supplied exception macros below are a *conforming* replacement:
// they simply forward to the real throw/try/catch keywords (via a counter so
// the test can assert each macro was actually invoked, not just defined), so
// every exception-related behavior the library relies on internally --
// including rethrowing std::out_of_range as json::out_of_range in at() --
// keeps working exactly as it would with the library's own default macros.
static int json_throw_user_call_count = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

#define JSON_THROW_USER(exception) do { ++json_throw_user_call_count; throw exception; } while (false) // NOLINT(cppcoreguidelines-macro-usage)
#define JSON_TRY_USER try // NOLINT(cppcoreguidelines-macro-usage)
#define JSON_CATCH_USER(exception) catch (exception) // NOLINT(cppcoreguidelines-macro-usage)

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;

TEST_CASE("JSON_NO_IO")
{
    // everything that does not touch <istream>/<ostream> must keep working:
    // parsing from and dumping to std::string
    const json j = json::parse("{\"a\":[1,2,3],\"b\":true}");
    CHECK(j.dump() == "{\"a\":[1,2,3],\"b\":true}");
    CHECK(j.at("a").size() == 3);
    CHECK(j.at("b").get<bool>() == true);
}

TEST_CASE("JSON_THROW_USER, JSON_TRY_USER, JSON_CATCH_USER")
{
    json_throw_user_call_count = 0;

    // a parse error goes through JSON_THROW directly, i.e., through our
    // JSON_THROW_USER override
    CHECK_THROWS_AS(json::parse("this is not JSON"), json::parse_error&);
    CHECK(json_throw_user_call_count > 0);

    // at() on an out-of-range array index internally catches std::out_of_range
    // (JSON_TRY_USER/JSON_CATCH_USER) and rethrows it as json::out_of_range
    // (JSON_THROW_USER again), so this exercises all three macros together
    const int count_before = json_throw_user_call_count;
    const json arr = json::array({1, 2, 3});
    CHECK_THROWS_AS(arr.at(10), json::out_of_range&);
    CHECK(json_throw_user_call_count > count_before);
}
