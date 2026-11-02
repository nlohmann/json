//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json_view.hpp>
using nlohmann::json;
using nlohmann::json_document;

#include <functional>
#include <map>
#include <string>

// These tests were split off unit-json_view_compare.cpp, whose object file got
// too large for the MinGW assembler ("file too big").

namespace
{
// an object type that does not enumerate its members in ascending order of keys
template<typename Key, typename Value, typename /*Compare*/, typename Allocator>
using descending_object = std::map<Key, Value, std::greater<Key>, Allocator>;
} // namespace

TEST_CASE("json_view comparison of differing values")
{
    SECTION("values that differ in their first bytes, or are written differently")
    {
        const auto same = [](const char* x, const char* y)
        {
            const json_document dx = json_document::parse(x);
            const json_document dy = json_document::parse(y);
            const bool equal = dx.root() == dy.root();
            CHECK(equal == (json::parse(x) == json::parse(y)));
            CHECK(equal == (dx.root() == json::parse(y)));
            const nlohmann::json_editable_document ex = nlohmann::json_editable_document::parse(x);
            CHECK(equal == (ex.root() == dy.root()));
            return equal;
        };
        // booleans
        CHECK(!same("true", "false"));
        CHECK(!same("[true]", "[false]"));
        CHECK(!same(R"({"a":false,"b":[1]})", R"({"a":true,"b":[1]})"));
        CHECK(same(R"({"a":true,"b":[1]})", R"({"a":true,"b":[1]})"));
        // strings and keys of equal length that differ in the first eight bytes (they are compared in words)
        CHECK(!same(R"("abcdefghijklmnopqrstuvwxyz")", R"("Xbcdefghijklmnopqrstuvwxyz")"));
        CHECK(!same(R"(["abcdefghijklmnopq",1])", R"(["abcdefghXjklmnopq",1])"));
        CHECK(!same(R"({"abcdefghijklmnopq":1})", R"({"Xbcdefghijklmnopq":1})"));
        CHECK(!same(R"({"abcdefghijklmnopq":[1]})", R"({"abcdefghijklmnopX":[1]})"));
        // floats of one layout and different tokens are the same value
        CHECK(same("[1.5e0, 2]", "[1.5E0, 2]"));
        CHECK(same("[1.5e0, 2]", "[1.5e+0, 2]"));
        CHECK(same("[1.50, 2]", "[1.5, 2]"));
        CHECK(!same("[1.5e0, 2]", "[1.6e0, 2]"));
        CHECK(!same("[1.5e0, 2]", "[1.5E1, 2]"));
        CHECK(same(R"({"a":1.25e0,"b":[3]})", R"({"a":1.25E0,"b":[3]})"));
    }

    SECTION("a basic_json whose members are not sorted")
    {
        // (an object type that is not an ordered map, and does not keep its members sorted either)
        using descending_json = nlohmann::basic_json<descending_object>;
        using descending_document = nlohmann::basic_json_document<descending_json>;
        std::string text = "{";
        for (char key = 'a'; key <= 'p'; ++key)
        {
            text += (key != 'a' ? ",\"" : "\"") + std::string(1, key) + "\":[" + std::to_string(key) + "]";
        }
        text += "}";
        const descending_json j = descending_json::parse(text);
        const descending_document d = descending_document::parse(text);
        CHECK(d.root() == j);
        CHECK(j == d.root());
        descending_json other = j;
        other["k"] = 0;
        CHECK(d.root() != other);
        CHECK(other != d.root());
    }
}
