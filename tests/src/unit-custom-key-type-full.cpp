//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include "custom_key_test.hpp"

// object type whose key type has implicit conversion to std::string and operator== (see custom_key_test.hpp)
using custom_key_test::json_full;

TEST_CASE("custom object key types: copy (json_full)")
{
    custom_key_test::test_copy<json_full>();
}

TEST_CASE("custom object key types: parse (json_full)")
{
    custom_key_test::test_parse<json_full>();
}

TEST_CASE("custom object key types: merge_patch, update, and insert (json_full)")
{
    custom_key_test::test_patch<json_full>();
}

TEST_CASE("custom object key types: at() reports a missing key (json_full)")
{
    custom_key_test::test_at<json_full>();
}

TEST_CASE("custom object key types: BSON (json_full)")
{
    custom_key_test::test_bson<json_full>();
}

TEST_CASE("custom object key types: CBOR (json_full)")
{
    custom_key_test::test_cbor<json_full>();
}

TEST_CASE("custom object key types: MessagePack (json_full)")
{
    custom_key_test::test_msgpack<json_full>();
}

TEST_CASE("custom object key types: patch (json_full)")
{
    // the members of a patch are found by lookup, as their keys are not std::string
    const json_full j = json_full::parse(R"({"a":1,"b":[1,2],"c":{"d":2}})");
    const json_full patch = json_full::parse(R"([
        {"op": "add", "path": "/e", "value": 5},
        {"op": "remove", "path": "/a"},
        {"op": "replace", "path": "/c/d", "value": 3},
        {"op": "test", "path": "/c/d", "value": 3},
        {"op": "move", "from": "/e", "path": "/f"},
        {"op": "copy", "from": "/f", "path": "/g"},
        {"op": "add", "path": "/b/-", "value": 7}
    ])");

    CHECK(j.patch(patch).dump() == R"({"b":[1,2,7],"c":{"d":3},"f":5,"g":5})");

    // a patch with a missing member is rejected
    CHECK_THROWS_AS(j.patch(json_full::parse(R"([{"op": "add", "path": "/e"}])")), json_full::parse_error&);
    CHECK_THROWS_AS(j.patch(json_full::parse(R"([{"op": "test", "path": "/a", "value": 2}])")), json_full::other_error&);
}
