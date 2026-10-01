//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Regression test for https://github.com/nlohmann/json/issues/5742: with
// JSON_DIAGNOSTICS, GCC (13 to at least 15) reports a false -Warray-bounds
// error in the inlined set_parents() at -O3. The warning depends on GCC's
// inlining decisions, so the sections cover patterns that trigger it on
// different GCC versions (#4819: GCC 13 and 14; #5742: GCC 14 and 15).
// On GCC, this file is compiled with -O3 -Werror=array-bounds (see
// tests/CMakeLists.txt), so the test fails to build if the warning returns.

#include "doctest_compatibility.h"

#ifdef JSON_DIAGNOSTICS
    #undef JSON_DIAGNOSTICS
#endif

#define JSON_DIAGNOSTICS 1

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <algorithm>
#include <iterator>
#include <utility>
#include <vector>

namespace
{
enum class diag_color
{
    red,
    green,
    blue
};

void to_json(json& j, const diag_color& c)
{
    static const std::pair<diag_color, json> m[] = // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    {
        {diag_color::red, "r"},
        {diag_color::green, "g"},
        {diag_color::blue, "b"},
    };
    const auto* it = std::find_if(std::begin(m), std::end(m), [c](const std::pair<diag_color, json>& p)
    {
        return p.first == c;
    });
    j = it->second;
}
} // namespace

TEST_CASE("diagnostics with optimization")
{
    SECTION("issue #4819 - object in vector")
    {
        std::vector<json> jsons{};
        jsons.emplace_back(json({{"key", "value"}}));
        CHECK(jsons.back()["key"] == "value");
    }

    SECTION("issue #5742 - string values from a static table")
    {
        json j = json::array();
        j.push_back(diag_color::red);
        j.push_back(diag_color::green);
        j.push_back(diag_color::blue);
        CHECK(j.dump() == R"(["r","g","b"])");
        CHECK_THROWS_WITH_AS(j[1].get<int>(), "[json.exception.type_error.302] (/1) type must be number, but is string", json::type_error);
    }
}
