//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

TEST_CASE("tests on very large JSONs")
{
    SECTION("issue #1419 - Segmentation fault (stack overflow) due to unbounded recursion")
    {
        const auto depth = 5000000;

        std::string s(static_cast<std::size_t>(2 * depth), '[');
        std::fill(s.begin() + depth, s.end(), ']');

        json _;
        CHECK_NOTHROW(_ = nlohmann::json::parse(s));
    }
}

namespace
{
json nested_array(const std::size_t depth, json leaf)
{
    json j = std::move(leaf);
    for (std::size_t i = 0; i < depth; ++i)
    {
        json a = json::array();
        a.push_back(std::move(j));
        j = std::move(a);
    }
    return j;
}

json nested_object(const std::size_t depth, json leaf)
{
    json j = std::move(leaf);
    for (std::size_t i = 0; i < depth; ++i)
    {
        json o = json::object();
        o["k"] = std::move(j);
        j = std::move(o);
    }
    return j;
}
} // namespace

TEST_CASE("issue #5392 - binary writers on deeply nested values")
{
    // 200 > binary_write_depth_limit() (128), so the heap-stack path runs, but
    // 200 is still shallow enough for from_* and operator== (they still recurse).
    const json deep_array = nested_array(200, json(0));
    const json deep_object = nested_object(200, json("x"));
    const json empty_array = nested_array(200, json::array());
    const json mixed = nested_object(80, nested_array(80, json(true)));

    SECTION("roundtrip past the recursion bound")
    {
        CHECK(json::from_cbor(json::to_cbor(deep_array)) == deep_array);
        CHECK(json::from_msgpack(json::to_msgpack(deep_array)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array, true, false)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array, true, true)) == deep_array);
        CHECK(json::from_bjdata(json::to_bjdata(deep_array)) == deep_array);

        CHECK(json::from_cbor(json::to_cbor(deep_object)) == deep_object);
        CHECK(json::from_msgpack(json::to_msgpack(deep_object)) == deep_object);
        CHECK(json::from_ubjson(json::to_ubjson(deep_object)) == deep_object);
        CHECK(json::from_bjdata(json::to_bjdata(deep_object)) == deep_object);

        CHECK(json::from_cbor(json::to_cbor(empty_array)) == empty_array);
        CHECK(json::from_msgpack(json::to_msgpack(empty_array)) == empty_array);
        CHECK(json::from_ubjson(json::to_ubjson(empty_array)) == empty_array);

        CHECK(json::from_cbor(json::to_cbor(mixed)) == mixed);
        CHECK(json::from_msgpack(json::to_msgpack(mixed)) == mixed);
        CHECK(json::from_ubjson(json::to_ubjson(mixed)) == mixed);
    }

    SECTION("does not overflow the C++ stack")
    {
        const std::size_t depth = 100000;
        const json j = json::parse(std::string(depth, '[') + "0" + std::string(depth, ']'));

        std::vector<std::uint8_t> packed;
        CHECK_NOTHROW(packed = json::to_cbor(j));
        CHECK(packed.size() > depth);

        CHECK_NOTHROW(packed = json::to_msgpack(j));
        CHECK(packed.size() > depth);

        CHECK_NOTHROW(packed = json::to_ubjson(j));
        CHECK(packed.size() > depth);

        CHECK_NOTHROW(packed = json::to_ubjson(j, true, false));
        CHECK(packed.size() > depth);

        CHECK_NOTHROW(packed = json::to_bjdata(j));
        CHECK(packed.size() > depth);
    }
}

