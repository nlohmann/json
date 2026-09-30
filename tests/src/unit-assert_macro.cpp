//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// avoid warning when assert does not abort
DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Wstrict-overflow")
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wstrict-overflow")

/// global variable to record side effect of assert calls
static int assert_counter;

/// set failure variable to true instead of calling assert(x)
#define JSON_ASSERT(x) {if (!(x)) ++assert_counter; }

#include <nlohmann/json.hpp>
using nlohmann::json;

// the test assumes exceptions to work
#if !defined(JSON_NOEXCEPTION)
TEST_CASE("JSON_ASSERT(x)")
{
    SECTION("basic_json(first, second)")
    {
        assert_counter = 0;
        CHECK(assert_counter == 0);

        const json::iterator it{};
        json j;

        // in case assertions do not abort execution, an exception is thrown
        CHECK_THROWS_WITH_AS(json(it, j.end()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator);

        // check that assertion actually happened
        CHECK(assert_counter == 1);
    }

    SECTION("update() and merge_patch() with *this")
    {
        // update() and merge_patch() must not be called with *this (#5641);
        // the values are chosen so the calls still happen to work without
        // aborting, and only the assertion counter is checked
        json j = {{"a", 1}};

        assert_counter = 0;
        j.update(j);
        CHECK(assert_counter == 1);

        assert_counter = 0;
        j.update(j.cbegin(), j.cend());
        CHECK(assert_counter == 1);

        assert_counter = 0;
        j.merge_patch(j);
        CHECK(assert_counter == 1);

        // a copy is fine
        assert_counter = 0;
        j.update(json(j));
        j.merge_patch(json(j));
        CHECK(assert_counter == 0);
        CHECK(j == json({{"a", 1}}));
    }
}
#endif

DOCTEST_GCC_SUPPRESS_WARNING_POP
DOCTEST_CLANG_SUPPRESS_WARNING_POP
