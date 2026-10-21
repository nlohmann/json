//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// Qt defines its keywords as macros (see qtmetamacros.h and qforeach.h) unless
// QT_NO_KEYWORDS is defined, and it is common to include Qt headers before this
// library; it must therefore not use these words as identifiers (see #5865)
#define slots
#define signals public
#define emit
#define Q_FOREACH(variable, container) for (variable : container) // NOLINT(bugprone-macro-parentheses): variable is a declaration, as in Qt
#define foreach Q_FOREACH
#define forever for (;;)

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("Qt keyword macros")
{
    SECTION("parse and dump")
    {
        const json j = json::parse(R"({"a": [1, 2.5, "x", null, true]})");
        CHECK(j.dump() == R"({"a":[1,2.5,"x",null,true]})");
    }

    SECTION("flatten and unflatten")
    {
        const json j = {{"a", {{"b", {1, 2}}, {"c", "d"}}}, {"e", nullptr}};
        CHECK(j.flatten().unflatten() == j);
    }

    SECTION("JSON pointer")
    {
        json j = {{"a", {{"b", {1, 2}}}}};
        CHECK(j.at(json::json_pointer("/a/b/1")) == 2);
        j[json::json_pointer("/a/c")] = 3;
        CHECK(j.contains(json::json_pointer("/a/c")));
    }

    SECTION("binary formats")
    {
        const json j = {{"a", {1, 2, 3}}, {"b", "c"}};
        CHECK(json::from_cbor(json::to_cbor(j)) == j);
        CHECK(json::from_msgpack(json::to_msgpack(j)) == j);
        CHECK(json::from_ubjson(json::to_ubjson(j)) == j);
        CHECK(json::from_bjdata(json::to_bjdata(j)) == j);
        CHECK(json::from_bson(json::to_bson(j)) == j);
    }

    SECTION("patch and diff")
    {
        const json source = {{"a", 1}, {"b", {1, 2}}};
        const json target = {{"a", 2}, {"c", "d"}};
        CHECK(source.patch(json::diff(source, target)) == target);
    }
}

// testing for the macros also keeps -Wunused-macros from rejecting them
#if !defined(slots) || !defined(signals) || !defined(emit) || !defined(Q_FOREACH) || !defined(foreach) || !defined(forever)
    #error "the Qt keyword macros must stay defined for the tests above"
#endif
