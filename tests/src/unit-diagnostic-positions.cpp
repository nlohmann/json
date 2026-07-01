//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
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

    SECTION("JSON patch add to primitive parent (#4292)")
    {
        // the JSON Patch "add" target /foo/bar/baz has a string parent
        // (/foo/bar); the position of that parent is reported in the message
        const json doc = json::parse(R"({"foo":{"bar":"a string"}})");
        const json patch = json::parse(R"([{"op":"add","path":"/foo/bar/baz","value":1}])");
        CHECK_THROWS_WITH_AS(doc.patch(patch),
                             "[json.exception.out_of_range.411] (/foo/bar) (bytes 14-24) cannot add value: the JSON Patch 'add' target's parent is of type string, but must be an object or array", json::out_of_range);
    }
}
