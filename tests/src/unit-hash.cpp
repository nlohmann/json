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
#include <string>

namespace
{
// how detail::hash defines the hash of an array or object: the seeds of the
// elements, combined in order. Recursive, so only usable on values nested a
// few hundred levels deep - which is exactly what is needed to check that the
// iterative path taken below detail::hash_depth_limit() computes the same.
template<typename BasicJsonType>
std::size_t reference_hash(const BasicJsonType& j)
{
    using nlohmann::detail::combine;
    using string_t = typename BasicJsonType::string_t;

    if (!j.is_structured())
    {
        return std::hash<BasicJsonType> {}(j);
    }

    auto seed = combine(static_cast<std::size_t>(j.type()), j.size());
    for (const auto& element : j.items())
    {
        if (j.is_object())
        {
            seed = combine(seed, std::hash<string_t> {}(element.key()));
        }
        seed = combine(seed, reference_hash(element.value()));
    }
    return seed;
}

// a value nested `depth` levels deep, with siblings on every level
template<typename BasicJsonType>
BasicJsonType nested(const std::size_t depth, const bool objects)
{
    BasicJsonType value = "leaf";
    for (std::size_t i = 0; i < depth; ++i)
    {
        if (objects)
        {
            value = BasicJsonType{{"before", i}, {"nested", std::move(value)}, {"after", {i, "x"}}};
        }
        else
        {
            value = BasicJsonType::array({i, std::move(value), BasicJsonType::object({{"k", i}})});
        }
    }
    return value;
}

std::string nested_text(const std::size_t depth, const bool objects)
{
    std::string text;
    if (objects)
    {
        text.reserve(6 * depth + 1);
        for (std::size_t i = 0; i < depth; ++i)
        {
            text += "{\"a\":";
        }
        text += "1";
        text.append(depth, '}');
    }
    else
    {
        text.assign(depth, '[');
        text += "1";
        text.append(depth, ']');
    }
    return text;
}
} // namespace

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

TEST_CASE("hash of deeply nested values")
{
    SECTION("hashing past the descent bound computes the same values")
    {
        // every depth on either side of where the iterative path takes over
        for (std::size_t depth = 0; depth <= 2 * nlohmann::detail::hash_depth_limit() + 10; ++depth)
        {
            CAPTURE(depth);
            const auto arrays = nested<json>(depth, false);
            const auto objects = nested<json>(depth, true);
            const auto ordered = nested<ordered_json>(depth, true);
            CHECK(std::hash<json> {}(arrays) == reference_hash(arrays));
            CHECK(std::hash<json> {}(objects) == reference_hash(objects));
            CHECK(std::hash<ordered_json> {}(ordered) == reference_hash(ordered));
        }
    }

    SECTION("values nested too deeply for the call stack (#5545)")
    {
        // recursing once per level used to exhaust the call stack here; the
        // values are only parsed and hashed, never copied or compared, since
        // those recurse as well
        const std::size_t depth = 100000;
        for (const bool objects :
                {
                    false, true
                })
        {
            CAPTURE(objects);
            const auto text = nested_text(depth, objects);
            const auto a = json::parse(text);
            const auto b = json::parse(text);
            CHECK(std::hash<json> {}(a) == std::hash<json> {}(b));

            const auto c = ordered_json::parse(text);
            const auto d = ordered_json::parse(text);
            CHECK(std::hash<ordered_json> {}(c) == std::hash<ordered_json> {}(d));
        }
    }
}
