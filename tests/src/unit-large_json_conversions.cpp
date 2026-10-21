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

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

// split from unit-large_json.cpp so that both run in parallel and stay below
// the ctest timeout under Valgrind

namespace
{

// The text of a value nested depth levels deep around the number 0. Level i is
// an array if pattern[i % pattern.size()] is '[', and otherwise an object with
// the single member "a", which every object type enumerates in the same order.
std::string nested_text(std::size_t depth, const std::string& pattern)
{
    std::string text;
    std::string closing;
    for (std::size_t i = 0; i < depth; ++i)
    {
        const bool array = pattern[i % pattern.size()] == '[';
        text += array ? "[" : "{\"a\":";
        closing += array ? ']' : '}';
    }
    text += '0';
    text.append(closing.rbegin(), closing.rend());
    return text;
}

} // namespace

TEST_CASE("issue #5650 - stack overflow converting between specializations")
{
    // deep enough to exhaust the call stack, but small enough to stay cheap:
    // parsing is iterative, so building the values below costs little
    const std::size_t depth = 100000;

    const std::vector<std::string> patterns = {"[", "{", "[{"};

    SECTION("json to ordered_json")
    {
        for (const auto& pattern : patterns)
        {
            CAPTURE(pattern)
            const std::string text = nested_text(depth, pattern);
            const json j = json::parse(text);

            const nlohmann::ordered_json converted = j;
            CHECK(converted.dump() == text);
        }
    }

    SECTION("ordered_json to json")
    {
        for (const auto& pattern : patterns)
        {
            CAPTURE(pattern)
            const std::string text = nested_text(depth, pattern);
            const nlohmann::ordered_json o = nlohmann::ordered_json::parse(text);

            const json converted = o;
            CHECK(converted.dump() == text);
        }
    }

    SECTION("get<ordered_json>()")
    {
        for (const auto& pattern : patterns)
        {
            CAPTURE(pattern)
            const std::string text = nested_text(depth, pattern);
            const json j = json::parse(text);

            CHECK(j.get<nlohmann::ordered_json>().dump() == text);
        }
    }

    SECTION("depths around the bound of the recursive descent")
    {
        for (std::size_t d = 1; d <= 300; ++d)
        {
            CAPTURE(d)
            for (const auto& pattern : patterns)
            {
                CAPTURE(pattern)
                const std::string text = nested_text(d, pattern);
                const json j = json::parse(text);

                const nlohmann::ordered_json converted = j;
                CHECK(converted.dump() == text);
                const json back = converted;
                CHECK(back.dump() == text);
            }
        }
    }

    SECTION("values below the bound are converted as values above it")
    {
        // Bury a value below the bound, where it is converted without the
        // call stack, and compare it with the same value converted on its
        // own by the containers' range constructors. Its objects have
        // members that the two object types enumerate in different orders.
        const auto bury = [](nlohmann::ordered_json value)
        {
            for (std::size_t i = 0; i < 200; ++i)
            {
                value = nlohmann::ordered_json::array({std::move(value)});
            }
            return value;
        };
        const auto dig = [](const json & value)
        {
            const json* current = &value;
            for (std::size_t i = 0; i < 200; ++i)
            {
                current = &current->at(0);
            }
            return current;
        };

        nlohmann::ordered_json value = nlohmann::ordered_json::object();
        value["z"] = {1, -2, 3U, 4.5, true, nullptr, "six", nlohmann::ordered_json::binary({7, 8}, 9),
                      nlohmann::ordered_json::binary({10}), nlohmann::ordered_json::array(), nlohmann::ordered_json::object()
                     };
        value["y"] = {{"x", {{"w", 1}, {"v", 2}}}, {"u", {3, {{"t", 4}, {"s", 5}}}}};
        value["r"] = nlohmann::ordered_json::array({nlohmann::ordered_json(nlohmann::ordered_json::value_t::discarded)});

        const json converted_above = value;
        const json buried = bury(value);
        const json& converted_below = *dig(buried);

        CHECK(converted_below.dump() == converted_above.dump());
        CHECK(converted_below.at("z").at(7).get_binary().subtype() == 9);
        CHECK_FALSE(converted_below.at("z").at(8).get_binary().has_subtype());
        CHECK(converted_below.at("r").at(0).is_discarded());

        // a discarded value is never equal to anything, so compare the rest
        value.erase("r");
        const json without_discarded_above = value;
        const json without_discarded_buried = bury(value);
        CHECK(*dig(without_discarded_buried) == without_discarded_above);
    }
}
