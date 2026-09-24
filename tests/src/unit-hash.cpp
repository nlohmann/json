//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

#include <set>

TEST_CASE("hash<nlohmann::json>")
{
    // Collect hashes for different JSON values and make sure that they are distinct
    // We cannot compare against fixed values, because the implementation of
    // std::hash may differ between compilers.

    std::set<std::size_t> hashes;

    // null
    hashes.insert(std::hash<json> {}(json(nullptr)));

    // boolean
    hashes.insert(std::hash<json> {}(json(true)));
    hashes.insert(std::hash<json> {}(json(false)));

    // string
    hashes.insert(std::hash<json> {}(json("")));
    hashes.insert(std::hash<json> {}(json("foo")));

    // number
    hashes.insert(std::hash<json> {}(json(0)));
    hashes.insert(std::hash<json> {}(json(static_cast<unsigned>(0))));

    hashes.insert(std::hash<json> {}(json(-1)));
    hashes.insert(std::hash<json> {}(json(0.0)));
    hashes.insert(std::hash<json> {}(json(42.23)));

    // array
    hashes.insert(std::hash<json> {}(json::array()));
    hashes.insert(std::hash<json> {}(json::array({1, 2, 3})));

    // object
    hashes.insert(std::hash<json> {}(json::object()));
    hashes.insert(std::hash<json> {}(json::object({{"foo", "bar"}})));

    // binary
    hashes.insert(std::hash<json> {}(json::binary({})));
    hashes.insert(std::hash<json> {}(json::binary({}, 0)));
    hashes.insert(std::hash<json> {}(json::binary({}, 42)));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3})));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3}, 0)));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3}, 42)));

    // discarded
    hashes.insert(std::hash<json> {}(json(json::value_t::discarded)));

    CHECK(hashes.size() == 21);
}

TEST_CASE("hash<nlohmann::ordered_json>")
{
    // Collect hashes for different JSON values and make sure that they are distinct
    // We cannot compare against fixed values, because the implementation of
    // std::hash may differ between compilers.

    std::set<std::size_t> hashes;

    // null
    hashes.insert(std::hash<ordered_json> {}(ordered_json(nullptr)));

    // boolean
    hashes.insert(std::hash<ordered_json> {}(ordered_json(true)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json(false)));

    // string
    hashes.insert(std::hash<ordered_json> {}(ordered_json("")));
    hashes.insert(std::hash<ordered_json> {}(ordered_json("foo")));

    // number
    hashes.insert(std::hash<ordered_json> {}(ordered_json(0)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json(static_cast<unsigned>(0))));

    hashes.insert(std::hash<ordered_json> {}(ordered_json(-1)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json(0.0)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json(42.23)));

    // array
    hashes.insert(std::hash<ordered_json> {}(ordered_json::array()));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::array({1, 2, 3})));

    // object
    hashes.insert(std::hash<ordered_json> {}(ordered_json::object()));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::object({{"foo", "bar"}})));

    // binary
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({})));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({}, 0)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({}, 42)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({1, 2, 3})));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({1, 2, 3}, 0)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({1, 2, 3}, 42)));

    // discarded
    hashes.insert(std::hash<ordered_json> {}(ordered_json(ordered_json::value_t::discarded)));

    CHECK(hashes.size() == 21);
}

TEST_CASE("deeply nested hash (issue #5545)")
{
    const std::size_t depth = 500;

    SECTION("nested array in json")
    {
        json j = 42;
        for (std::size_t i = 0; i < depth; ++i)
        {
            j = json::array({std::move(j)});
        }
        CHECK_NOTHROW(std::hash<json> {}(j));
        const auto h1 = std::hash<json> {}(j);
        const auto h2 = std::hash<json> {}(j);
        CHECK(h1 == h2);
        CHECK(h1 != 0);
    }

    SECTION("nested object in json")
    {
        json j = 42;
        for (std::size_t i = 0; i < depth; ++i)
        {
            j = json::object({{"key", std::move(j)}});
        }
        CHECK_NOTHROW(std::hash<json> {}(j));
        const auto h1 = std::hash<json> {}(j);
        const auto h2 = std::hash<json> {}(j);
        CHECK(h1 == h2);
        CHECK(h1 != 0);
    }

    SECTION("nested array in ordered_json")
    {
        ordered_json j = 42;
        for (std::size_t i = 0; i < depth; ++i)
        {
            j = ordered_json::array({std::move(j)});
        }
        CHECK_NOTHROW(std::hash<ordered_json> {}(j));
        const auto h1 = std::hash<ordered_json> {}(j);
        const auto h2 = std::hash<ordered_json> {}(j);
        CHECK(h1 == h2);
        CHECK(h1 != 0);
    }

    SECTION("nested object in ordered_json")
    {
        ordered_json j = 42;
        for (std::size_t i = 0; i < depth; ++i)
        {
            j = ordered_json::object({{"key", std::move(j)}});
        }
        CHECK_NOTHROW(std::hash<ordered_json> {}(j));
        const auto h1 = std::hash<ordered_json> {}(j);
        const auto h2 = std::hash<ordered_json> {}(j);
        CHECK(h1 == h2);
        CHECK(h1 != 0);
    }

    SECTION("hash_iterative produces identical results to recursive hash on arbitrary documents")
    {
        json j = {
            {"int", 1},
            {"str", "hello"},
            {"bool", true},
            {"null", nullptr},
            {"arr", {1, 2, 3, {{"inner", "val"}}}},
            {"obj", {{"a", 1}, {"b", {10, 20}}}}
        };
        CHECK(nlohmann::detail::hash_iterative(j) == std::hash<json> {}(j));
    }
}

