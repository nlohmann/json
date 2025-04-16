//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_DIAGNOSTICS 1
#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

TEST_CASE("Better diagnostics with positions")
{
    SECTION("invalid type")
    {
        const std::string json_invalid_string = R"(
        {
            "address": {
                "street": "Fake Street",
                "housenumber": "1"
            }
        }
        )";
        json j = json::parse(json_invalid_string);
        CHECK_THROWS_WITH_AS(j.at("address").at("housenumber").get<int>(),
                             "[json.exception.type_error.302] (/address/housenumber) (bytes 108-111) type must be number, but is string", json::type_error);
    }

    SECTION("invalid type without positions")
    {
        const json j = "foo";
        CHECK_THROWS_WITH_AS(j.get<int>(),
                             "[json.exception.type_error.302] type must be number, but is string", json::type_error);
    }
}
