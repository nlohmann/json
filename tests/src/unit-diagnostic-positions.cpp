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

    SECTION("positions of strings containing escape sequences")
    {
        // escape sequences make the token longer than the string it parses to,
        // so the positions must not be derived from the parsed value's length
        const auto check = [](const std::string & text, const std::string & token)
        {
            CAPTURE(text)
            CAPTURE(token)
            const json j = json::parse(text);
            const json& v = j.at("a");
            CHECK(text.substr(v.start_pos(), v.end_pos() - v.start_pos()) == token);
        };

        check(R"({"a":"plain"})", R"("plain")");
        check(R"({"a":"tab\there"})", R"("tab\there")");
        check(R"({"a":"\n\n\n\n\n\n"})", R"("\n\n\n\n\n\n")");
        check(R"({"a":"\""})", R"("\"")");
        check(R"({"a":"\\"})", R"("\\")");
        check(R"({"a":"é"})", R"("é")");
        check(R"({"a":"🌞"})", R"("🌞")");
        check("{\"a\":\"\xc3\xa9\"}", "\"\xc3\xa9\"");  // multi-byte UTF-8, no escapes

        // a string at the root, where an escape would otherwise push the
        // reported start position past the opening quote
        const std::string root = R"("a\tb")";
        const json j = json::parse(root);
        CHECK(j.start_pos() == 0);
        CHECK(j.end_pos() == root.size());
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
