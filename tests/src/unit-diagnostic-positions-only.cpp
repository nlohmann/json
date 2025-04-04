//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#ifdef JSON_DIAGNOSTICS
    #undef JSON_DIAGNOSTICS
#endif

#define JSON_DIAGNOSTICS 0
#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

TEST_CASE("Better diagnostics with positions only")
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
                             "[json.exception.type_error.302] (bytes 108-111) type must be number, but is string", json::type_error);
    }

    SECTION("invalid type without positions")
    {
        const json j = "foo";
        CHECK_THROWS_WITH_AS(j.get<int>(),
                             "[json.exception.type_error.302] type must be number, but is string", json::type_error);
    }
}
