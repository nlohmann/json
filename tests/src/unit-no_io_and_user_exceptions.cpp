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

// this test relies on CHECK_THROWS_AS() actually invoking the guarded
// expression so json_throw_user_call_count gets bumped and can be observed
// afterwards; doctest's "--no-throw" test filter (which ci_test_noexceptions
// passes, together with a global -DJSON_NOEXCEPTION added to CMAKE_CXX_FLAGS
// for every translation unit in that build, this file included) compiles
// CHECK_THROWS_AS() out to a no-op that never even invokes the given
// expression -- so json::parse()/at() below would never be called at all and
// the call-count assertions would fail even though our JSON_THROW_USER
// override (which always really throws, regardless of JSON_NOEXCEPTION) would
// have worked fine on its own
#if !defined(JSON_NOEXCEPTION)
TEST_CASE("JSON_THROW_USER, JSON_TRY_USER, JSON_CATCH_USER")
{
    json_throw_user_call_count = 0;

    // json::parse() is [[nodiscard]] (JSON_HEDLEY_WARN_UNUSED_RESULT); under
    // GCC in C++11 mode that expands to __attribute__((warn_unused_result)),
    // which -- unlike a [[nodiscard]] attribute proper -- GCC does not
    // consider satisfied by doctest's CHECK_THROWS_AS() wrapping the
    // expression in a (void) cast, so the discarded return value would still
    // be flagged under -Werror=unused-result; assign it to discard it instead,
    // matching the established `json _ = json::parse(...)` pattern used
    // elsewhere in the test suite (see unit-class_parser.cpp)
    json _; // NOLINT(readability-identifier-naming)

    // a parse error goes through JSON_THROW directly, i.e., through our
    // JSON_THROW_USER override
    CHECK_THROWS_AS(_ = json::parse("this is not JSON"), json::parse_error&);
    CHECK(json_throw_user_call_count > 0);

    // at() on an out-of-range array index internally catches std::out_of_range
    // (JSON_TRY_USER/JSON_CATCH_USER) and rethrows it as json::out_of_range
    // (JSON_THROW_USER again), so this exercises all three macros together
    const int count_before = json_throw_user_call_count;
    const json arr = json::array({1, 2, 3});
    CHECK_THROWS_AS(arr.at(10), json::out_of_range&);
    CHECK(json_throw_user_call_count > count_before);
}
#endif
