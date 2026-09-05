//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file makes sure that none of the internal JSON_HEDLEY_* macros (vendored
// from https://nemequ.github.io/hedley/, see
// include/nlohmann/thirdparty/hedley/hedley.hpp) leak into the including
// translation unit. include/nlohmann/detail/macro_unscope.hpp is supposed to
// #undef every JSON_HEDLEY_* macro (via hedley_undef.hpp) once json.hpp has
// been fully processed. See https://github.com/nlohmann/json/issues/5408,
// where JSON_HEDLEY_PRAGMA, JSON_HEDLEY_PREDICT_TRUE, JSON_HEDLEY_PREDICT_FALSE,
// and JSON_HEDLEY_CLANG_HAS_DECLSPEC_ATTRIBUTE escaped this cleanup because
// hedley_undef.hpp had no matching #undef for them.
//
// hedley_undef_checks.inc (included below) is generated at CMake configure/
// build time by cmake/scripts/gen_hedley_undef_check.cmake, which derives the
// full list of JSON_HEDLEY_* macro names directly from hedley.hpp. That way
// this test covers every macro Hedley actually defines -- not a hardcoded
// snapshot that would silently go stale the next time `make update_hedley`
// runs -- and can never drift from the vendored header.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

TEST_CASE("JSON_HEDLEY macros do not leak after including json.hpp")
{
#include "hedley_undef_checks.inc"
    CHECK(true); // keep an assertion when nothing leaked
}
