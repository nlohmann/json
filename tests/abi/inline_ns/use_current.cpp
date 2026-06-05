//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

TEST_CASE("use current library with inline namespace")
{
    SECTION("implicitly")
    {
        using nlohmann::json;
        using nlohmann::ordered_json;

        json j;
        // In v3.10.5 mixing json_pointers of different basic_json types
        // results in implicit string conversion
        j[ordered_json::json_pointer("/root")] = json::object();
        CHECK(j.dump() == "{\"root\":{}}");
    }

    SECTION("explicitly")
    {
        using NLOHMANN_JSON_NAMESPACE::json;
        using NLOHMANN_JSON_NAMESPACE::ordered_json;

        json j;
        j[ordered_json::json_pointer("/root")] = json::object();
        CHECK(j.dump() == "{\"root\":{}}");
    }
}
