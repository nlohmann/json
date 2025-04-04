//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
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
        CHECK(j["copyright"] == "(C) 2013-2023 Niels Lohmann");
        CHECK(j["url"] == "https://github.com/nlohmann/json");
        CHECK(j["version"] == json(
        {
            {"string", "3.11.3"},
            {"major", 3},
            {"minor", 11},
            {"patch", 3}
        }));

        CHECK(j.find("platform") != j.end());
        CHECK(j.at("compiler").find("family") != j.at("compiler").end());
        CHECK(j.at("compiler").find("version") != j.at("compiler").end());
        CHECK(j.at("compiler").find("c++") != j.at("compiler").end());
    }
}
