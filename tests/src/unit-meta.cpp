//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.1
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("version information")
{
    SECTION("meta()")
    {
        json j = json::meta();

        CHECK(j["name"] == "JSON for Modern C++");
        CHECK(j["copyright"] == "(C) 2013-2022 Niels Lohmann");
        CHECK(j["url"] == "https://github.com/nlohmann/json");
        CHECK(j["version"] == json(
        {
            {"string", "3.11.1"},
            {"major", 3},
            {"minor", 11},
            {"patch", 1}
        }));

        CHECK(j.contains("platform"));
        CHECK(j.contains("compiler"));
        CHECK(j.contains("config"));

        const auto& j_cxx = j["compiler"];
        CHECK(j_cxx.contains("family"));
        CHECK(j_cxx.contains("version"));
        CHECK(j_cxx.contains("c++"));
        CHECK(j_cxx.contains("libc++"));

        const auto& j_lib = j_cxx["libc++"];
        CHECK(j_lib.contains("family"));
        CHECK(j_lib.contains("version"));
    }
}

#include "print_meta.cpp" // NOLINT(bugprone-suspicious-include)
