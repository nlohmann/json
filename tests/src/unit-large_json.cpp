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

// Descend a chain of single-element containers and return the value at its end,
// reporting the number of levels traversed in @a depth.
//
// The values in the test case below are nested far deeper than the call stack
// can follow, so they must not be inspected with operator== or dump(): both are
// still recursive and would overflow the stack themselves.
const json* innermost_value(const json& j, std::size_t& depth)
{
    const json* current = &j;
    depth = 0;

    while ((current->is_array() || current->is_object()) && !current->empty())
    {
        current = current->is_array()
                  ? &current->front()
                  : &current->begin().value();
        ++depth;
    }

    return current;
}

} // namespace

TEST_CASE("tests on deeply nested JSONs")
{
    // deep enough to exhaust the call stack, but small enough to stay cheap:
    // parsing is iterative, so building the values below costs little
    const std::size_t depth = 100000;

    SECTION("issue #5387 - stack overflow in the copy constructor")
    {
        SECTION("array")
        {
            const json j = json::parse(std::string(depth, '[') + '0' + std::string(depth, ']'));

            const json copy(j); // NOLINT(performance-unnecessary-copy-initialization): the copy is what is tested

            std::size_t copy_depth = 0;
            CHECK(*innermost_value(copy, copy_depth) == 0);
            CHECK(copy_depth == depth);
        }

        SECTION("object")
        {
            std::string s;
            s.reserve((6 * depth) + 1);
            for (std::size_t i = 0; i < depth; ++i)
            {
                s += "{\"a\":";
            }
            s += '1';
            s.append(depth, '}');

            const json j = json::parse(s);

            const json copy(j); // NOLINT(performance-unnecessary-copy-initialization): the copy is what is tested

            std::size_t copy_depth = 0;
            CHECK(*innermost_value(copy, copy_depth) == 1);
            CHECK(copy_depth == depth);
        }

        SECTION("copy assignment")
        {
            // operator=(basic_json) takes its argument by value, so the deep
            // copy happens in the copy constructor
            const json j = json::parse(std::string(depth, '[') + '0' + std::string(depth, ']'));

            json target;
            target = j;

            std::size_t target_depth = 0;
            CHECK(*innermost_value(target, target_depth) == 0);
            CHECK(target_depth == depth);
        }

        SECTION("depths around the bound of the recursive descent")
        {
            // The copy constructor descends into a bounded number of levels and
            // completes whatever is below that without the call stack. Cover
            // every depth around that bound, so that the two ways of copying
            // are known to meet cleanly - wherever the bound is set.
            for (std::size_t d = 1; d <= 300; ++d)
            {
                CAPTURE(d);

                const json array = json::parse(std::string(d, '[') + '0' + std::string(d, ']'));
                const json array_copy(array); // NOLINT(performance-unnecessary-copy-initialization): the copy is what is tested
                std::size_t array_depth = 0;
                CHECK(*innermost_value(array_copy, array_depth) == 0);
                CHECK(array_depth == d);

                std::string object_text;
                for (std::size_t i = 0; i < d; ++i)
                {
                    object_text += "{\"a\":";
                }
                object_text += '1';
                object_text.append(d, '}');

                const json object = json::parse(object_text);
                const json object_copy(object); // NOLINT(performance-unnecessary-copy-initialization): the copy is what is tested
                std::size_t object_depth = 0;
                CHECK(*innermost_value(object_copy, object_depth) == 1);
                CHECK(object_depth == d);
            }
        }

        SECTION("a value that is deep in one place only")
        {
            json j = json::object();
            j["shallow"] = 1;
            j["deep"] = json::parse(std::string(depth, '[') + '0' + std::string(depth, ']'));
            j["also_shallow"] = json::array({1, 2, 3});

            const json copy(j);

            CHECK(copy["shallow"] == 1);
            CHECK(copy["also_shallow"] == json::array({1, 2, 3}));

            std::size_t deep_depth = 0;
            CHECK(*innermost_value(copy["deep"], deep_depth) == 0);
            CHECK(deep_depth == depth);
        }

        SECTION("the copy is independent of the original")
        {
            const json j = json::parse(std::string(depth, '[') + '0' + std::string(depth, ']'));

            json copy(j);

            // reach the innermost value without recursing and replace it
            json* current = &copy;
            while (current->is_array() && !current->empty())
            {
                current = &current->front();
            }
            *current = 42;

            std::size_t unused = 0;
            CHECK(*innermost_value(copy, unused) == 42);
            CHECK(*innermost_value(j, unused) == 0);
        }
    }
}

