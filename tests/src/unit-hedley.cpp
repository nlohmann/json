//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

// Every JSON_HEDLEY_* macro defined in hedley.hpp must be undefined after
// including the public header (issue #5408). The per-macro checks are generated
// from hedley.hpp at CMake configure time so they cannot drift from the vendor.
TEST_CASE("JSON_HEDLEY macros do not leak after including json.hpp")
{
#include "hedley_undef_checks.inc"
    CHECK(true); // keep an assertion when nothing leaks
}
