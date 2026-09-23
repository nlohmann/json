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
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <string>

namespace
{
// RFC 7396's MergePatch, written recursively as in the RFC; only usable on
// values nested a few hundred levels deep
void reference_merge_patch(json& target, const json& patch)
{
    if (!patch.is_object())
    {
        target = patch;
        return;
    }
    if (!target.is_object())
    {
        target = json::object();
    }
    for (auto it = patch.begin(); it != patch.end(); ++it)
    {
        if (it.value().is_null())
        {
            target.erase(it.key());
        }
        else
        {
            reference_merge_patch(target[it.key()], it.value());
        }
    }
}

// objects nested `depth` levels deep under the key "a", with members that
// differ by `variant` on the way down
std::string nested_objects(const std::size_t depth, const int variant)
{
    std::string text;
    for (std::size_t i = 0; i < depth; ++i)
    {
        text += "{";
        if ((i + static_cast<std::size_t>(variant)) % 3 == 0)
        {
            text += "\"s" + std::to_string(variant) + "\":" + std::to_string(i) + ",";
        }
        if (variant == 2 && i % 5 == 0)
        {
            text += "\"s0\":null,";
        }
        text += "\"a\":";
    }
    text += variant == 1 ? "{\"x\":1,\"y\":null}" : "{\"y\":2}";
    text.append(depth, '}');
    return text;
}
} // namespace

TEST_CASE("JSON Merge Patch")
{
    SECTION("examples from RFC 7396")
    {
        SECTION("Section 1")
        {
            json document = R"({
                "a": "b",
                "c": {
                    "d": "e",
                    "f": "g"
                }
            })"_json;

            json const patch = R"({
                "a": "z",
                "c": {
                    "f": null
                }
            })"_json;

            json expected = R"({
                "a": "z",
                "c": {
                    "d": "e"
                }
            })"_json;

            document.merge_patch(patch);
            CHECK(document == expected);
        }

        SECTION("Section 3")
        {
            json document = R"({
                "title": "Goodbye!",
                "author": {
                    "givenName": "John",
                    "familyName": "Doe"
                },
                "tags": [
                    "example",
                    "sample"
                ],
                "content": "This will be unchanged"
            })"_json;

            json const patch = R"({
                "title": "Hello!",
                "phoneNumber": "+01-123-456-7890",
                "author": {
                    "familyName": null
                },
                "tags": [
                    "example"
                ]
            })"_json;

            json expected = R"({
                "title": "Hello!",
                "author": {
                    "givenName": "John"
                },
                "tags": [
                    "example"
                ],
                "content": "This will be unchanged",
                "phoneNumber": "+01-123-456-7890"
            })"_json;

            document.merge_patch(patch);
            CHECK(document == expected);
        }

        SECTION("Appendix A")
        {
            SECTION("Example 1")
            {
                json original = R"({"a":"b"})"_json;
                json const patch = R"({"a":"c"})"_json;
                json result = R"({"a":"c"})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 2")
            {
                json original = R"({"a":"b"})"_json;
                json const patch = R"({"b":"c"})"_json;
                json result = R"({"a":"b", "b":"c"})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 3")
            {
                json original = R"({"a":"b"})"_json;
                json const patch = R"({"a":null})"_json;
                json result = R"({})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 4")
            {
                json original = R"({"a":"b","b":"c"})"_json;
                json const patch = R"({"a":null})"_json;
                json result = R"({"b":"c"})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 5")
            {
                json original = R"({"a":["b"]})"_json;
                json const patch = R"({"a":"c"})"_json;
                json result = R"({"a":"c"})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 6")
            {
                json original = R"({"a":"c"})"_json;
                json const patch = R"({"a":["b"]})"_json;
                json result = R"({"a":["b"]})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 7")
            {
                json original = R"({"a":{"b": "c"}})"_json;
                json const patch = R"({"a":{"b":"d","c":null}})"_json;
                json result = R"({"a": {"b": "d"}})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 8")
            {
                json original = R"({"a":[{"b":"c"}]})"_json;
                json const patch = R"({"a":[1]})"_json;
                json result = R"({"a":[1]})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 9")
            {
                json original = R"(["a","b"])"_json;
                json const patch = R"(["c","d"])"_json;
                json result = R"(["c","d"])"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 10")
            {
                json original = R"({"a":"b"})"_json;
                json const patch = R"(["c"])"_json;
                json result = R"(["c"])"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 11")
            {
                json original = R"({"a":"foo"})"_json;
                json const patch = R"(null)"_json;
                json result = R"(null)"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 12")
            {
                json original = R"({"a":"foo"})"_json;
                json const patch = R"("bar")"_json;
                json result = R"("bar")"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 13")
            {
                json original = R"({"e":null})"_json;
                json const patch = R"({"a":1})"_json;
                json result = R"({"e":null,"a":1})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 14")
            {
                json original = R"([1,2])"_json;
                json const patch = R"({"a":"b","c":null})"_json;
                json result = R"({"a":"b"})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 15")
            {
                json original = R"({})"_json;
                json const patch = R"({"a":{"bb":{"ccc":null}}})"_json;
                json result = R"({"a":{"bb":{}}})"_json;

                original.merge_patch(patch);
                CHECK(original == result);
            }
        }
    }
}

TEST_CASE("JSON Merge Patch on deeply nested values")
{
    SECTION("patching past the descent bound gives the same result")
    {
        // every depth on either side of where the iterative version takes
        // over (basic_json::merge_depth_limit(), 128)
        for (std::size_t depth = 0; depth <= 300; ++depth)
        {
            CAPTURE(depth);
            for (int variant = 0; variant < 3; ++variant)
            {
                CAPTURE(variant);
                const json patch = json::parse(nested_objects(depth, variant));

                json result = json::parse(nested_objects(depth, (variant + 1) % 3));
                json expected = result;
                result.merge_patch(patch);
                reference_merge_patch(expected, patch);
                CHECK(result == expected);

                // a target that is not an object, and an empty one
                json from_null;
                from_null.merge_patch(patch);
                json expected_from_null;
                reference_merge_patch(expected_from_null, patch);
                CHECK(from_null == expected_from_null);
            }
        }
    }

    SECTION("patches nested too deeply for the call stack (#5393)")
    {
        // applying a patch used to recurse once per nesting level. The result
        // is only walked, never copied or compared, since those recurse too.
        const std::size_t depth = 100000;
        json target = json::parse(nested_objects(depth, 0));
        target.merge_patch(json::parse(nested_objects(depth, 1)));

        const json* p = &target;
        for (std::size_t i = 0; i < depth; ++i)
        {
            p = &p->at("a");
        }
        // {"y":2} patched with {"x":1,"y":null}
        CHECK(p->size() == 1);
        CHECK(p->at("x") == 1);
    }
}
