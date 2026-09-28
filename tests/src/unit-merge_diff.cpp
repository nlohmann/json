//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;
using nlohmann::ordered_json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

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

            json expected = R"({
                "a": "z",
                "c": {
                    "d": "e"
                }
            })"_json;

            auto patch = json::merge_diff(document, expected);
            CHECK(patch == R"({
                "a": "z",
                "c": {
                    "f": null
                }
            })"_json);

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

            auto patch = json::merge_diff(document, expected);
            CHECK(patch == R"({
                "title": "Hello!",
                "phoneNumber": "+01-123-456-7890",
                "author": {
                    "familyName": null
                },
                "tags": [
                    "example"
                ]
            })"_json);

            document.merge_patch(patch);
            CHECK(document == expected);
        }

        SECTION("Appendix A")
        {
            SECTION("Example 1")
            {
                json original = R"({"a":"b"})"_json;
                json result = R"({"a":"c"})"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"({"a":"c"})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 2")
            {
                json original = R"({"a":"b"})"_json;
                json result = R"({"a":"b", "b":"c"})"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"({"b":"c"})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 3")
            {
                json original = R"({"a":"b"})"_json;
                json result = R"({})"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"({"a":null})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 4")
            {
                json original = R"({"a":"b","b":"c"})"_json;
                json result = R"({"b":"c"})"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"({"a":null})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 5")
            {
                json original = R"({"a":["b"]})"_json;
                json result = R"({"a":"c"})"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"({"a":"c"})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 6")
            {
                json original = R"({"a":"c"})"_json;
                json result = R"({"a":["b"]})"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"({"a":["b"]})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 7")
            {
                json original = R"({"a":{"b": "c"}})"_json;
                json result = R"({"a": {"b": "d"}})"_json;

                auto patch = json::merge_diff(original, result);
                // differs from the RFC 7396, "c": null is not in the patch
                // because neither the source nor the target have the "c" key
                CHECK(patch == R"({"a":{"b":"d"}})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 8")
            {
                json original = R"({"a":[{"b":"c"}]})"_json;
                json result = R"({"a":[1]})"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"({"a":[1]})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 9")
            {
                json original = R"(["a","b"])"_json;
                json result = R"(["c","d"])"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"(["c","d"])"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 10")
            {
                json original = R"({"a":"b"})"_json;
                json result = R"(["c"])"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"(["c"])"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 11")
            {
                json original = R"({"a":"foo"})"_json;
                json result = R"(null)"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"(null)"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 12")
            {
                json original = R"({"a":"foo"})"_json;
                json result = R"("bar")"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"("bar")"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 13")
            {
                json original = R"({"e":null})"_json;
                json result = R"({"e":null,"a":1})"_json;

                auto patch = json::merge_diff(original, result);
                CHECK(patch == R"({"a":1})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 14")
            {
                json original = R"([1,2])"_json;
                json result = R"({"a":"b"})"_json;

                auto patch = json::merge_diff(original, result);
                // differs from the RFC 7396, "c": null is not in the patch
                // because neither the source nor the target have the "c" key
                CHECK(patch == R"({"a":"b"})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }

            SECTION("Example 15")
            {
                json original = R"({})"_json;
                json result = R"({"a":{"bb":{}}})"_json;

                auto patch = json::merge_diff(original, result);
                // differs from the RFC 7396, "ccc": null is not in the patch
                // because neither the source nor the target have the "ccc" key
                CHECK(patch == R"({"a":{"bb":{}}})"_json);

                original.merge_patch(patch);
                CHECK(original == result);
            }
        }
    }

    SECTION("null values")
    {
        SECTION("object with null value to object")
        {
            json original = R"({"a":null})"_json;
            json result   = R"({"a":{"b":"c"}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":"c"}})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({"a":{"b":"c"}})"_json);
        }

        SECTION("object to object with null value")
        {
            json original = R"({"a":{"b":"c"}})"_json;
            json result   = R"({"a":null})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":null})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({})"_json);
        }

        SECTION("primitive to object with null value")
        {
            json original = R"({"a":1})"_json;
            json result   = R"({"a":null})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":null})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({})"_json);
        }

        SECTION("nested primitive to object with null value")
        {
            json original = R"({"a":{"b":1}})"_json;
            json result   = R"({"a":{"b":null}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":null}})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({"a":{}})"_json);
        }

        SECTION("array value to object with null value")
        {
            json original = R"({"a":[1,2]})"_json;
            json result   = R"({"a":null})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":null})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({})"_json);
        }

        SECTION("nested object to object with null value")
        {
            json original = R"({"a":{"b":{"c":"d"}}})"_json;
            json result   = R"({"a":{"b":null}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":null}})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({"a":{}})"_json);
        }

        SECTION("nested primitive to object with null value with sibling")
        {
            json original = R"({"x":"y","a":{"b":"c"}})"_json;
            json result   = R"({"x":"y","a":{"b":null, "c":"d"}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":null,"c":"d"}})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({"x":"y","a":{"c":"d"}})"_json);
        }

        SECTION("empty object to object with null value")
        {
            json original = R"({})"_json;
            json result   = R"({"a":null})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":null})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({})"_json);
        }

        SECTION("null to object with null value")
        {
            json original = R"(null)"_json;
            json result   = R"({"a":null})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":null})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({})"_json);
        }

        SECTION("array to object with null value")
        {
            json original = R"([])"_json;
            json result   = R"({"a":null})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":null})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({})"_json);
        }

        SECTION("empty object to nested null value")
        {
            json original = R"({})"_json;
            json result   = R"({"a":{"b":null}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":null}})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({"a":{}})"_json);
        }

        SECTION("object to nested null value")
        {
            json original = R"({"a": 1})"_json;
            json result   = R"({"a":{"b":null}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":null}})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({"a":{}})"_json);
        }

        SECTION("primitive to nested null value")
        {
            json original = R"(1)"_json;
            json result   = R"({"a":{"b":null}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":null}})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({"a":{}})"_json);
        }

        SECTION("object with null value unchanged")
        {
            json original = R"({"a":null})"_json;
            json result   = R"({"a":null})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("object with null value to empty object")
        {
            json original = R"({"a":null})"_json;
            json result   = R"({})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":null})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("object with null value to primitive")
        {
            json original = R"({"a":null})"_json;
            json result   = R"({"a":1})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":1})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("array to array with null value")
        {
            json original = R"({"a":[1]})"_json;
            json result   = R"({"a":[null]})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":[null]})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("empty object to array with null value")
        {
            json original = R"({})"_json;
            json result   = R"({"a":[null]})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":[null]})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("doubly nested primitive to null value")
        {
            json original = R"({"a":{"b":{"c":1}}})"_json;
            json result   = R"({"a":{"b":{"c":null}}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":{"c":null}}})"_json);

            original.merge_patch(patch);
            CHECK(original == R"({"a":{"b":{}}})"_json);
        }
    }

    SECTION("no change")
    {
        SECTION("object")
        {
            json original = R"({"a":"b","b":"c"})"_json;
            json result   = R"({"a":"b","b":"c"})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch.empty());
            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("empty object")
        {
            json original = R"({})"_json;
            json result   = R"({})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch.empty());
            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("array")
        {
            json original = R"([1,2,3])"_json;
            json result   = R"([1,2,3])"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(!patch.empty());
            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("null")
        {
            json original = R"(null)"_json;
            json result   = R"(null)"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch.empty());
            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("string")
        {
            json original = R"("ab")"_json;
            json result   = R"("ab")"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(!patch.empty());
            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("number")
        {
            json original = R"(42)"_json;
            json result   = R"(42)"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(!patch.empty());
            original.merge_patch(patch);
            CHECK(original == result);
        }
    }

    SECTION("primitives")
    {
        SECTION("string")
        {
            json original = R"("a")"_json;
            json result   = R"("b")"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"("b")"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("number")
        {
            json original = R"(1)"_json;
            json result   = R"(2)"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"(2)"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("boolean")
        {
            json original = R"(false)"_json;
            json result   = R"(true)"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"(true)"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("object to primitive")
        {
            json original = R"({"a":{"b":"c"}})"_json;
            json result   = R"({"a":1})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":1})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("primitive to object")
        {
            json original = R"({"a":1})"_json;
            json result   = R"({"a":{"b":"c"}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":"c"}})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("object to empty string")
        {
            json original = R"({"a":{"b":"c"}})"_json;
            json result   = R"({"a":""})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":""})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("object to zero")
        {
            json original = R"({"a":{"b":"c"}})"_json;
            json result   = R"({"a":0})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":0})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("object to empty object")
        {
            json original = R"({"a":{"b":"c"}})"_json;
            json result   = R"({"a":{}})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":{"b":null}})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }
    }

    SECTION("arrays")
    {
        SECTION("array to array")
        {
            json original = R"([1,2,3])"_json;
            json result   = R"([1,2,4])"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"([1,2,4])"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("array to empty array")
        {
            json original = R"([1,2,3])"_json;
            json result   = R"([])"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"([])"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("empty array to array")
        {
            json original = R"([])"_json;
            json result   = R"([1,2,3])"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"([1,2,3])"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("object to empty array")
        {
            json original = R"({"a":{"b":"c"}})"_json;
            json result   = R"({"a":[]})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":[]})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("same keys")
        {
            json original = R"(["a","b"])"_json;
            json result   = R"({"a":1,"b":2})"_json;

            auto patch = json::merge_diff(original, result);
            CHECK(patch == R"({"a":1,"b":2})"_json);

            original.merge_patch(patch);
            CHECK(original == result);
        }
    }

    SECTION("ordered_json")
    {
        SECTION("changed value keeps member order")
        {
            auto original = ordered_json::parse(R"({"c":1,"b":2,"a":3})");
            auto result   = ordered_json::parse(R"({"c":1,"b":5,"a":3})");

            auto patch = ordered_json::merge_diff(original, result);
            CHECK(patch.dump() == R"({"b":5})");

            original.merge_patch(patch);
            CHECK(original == result);
            CHECK(original.dump() == R"({"c":1,"b":5,"a":3})");
        }

        SECTION("added members follow target order")
        {
            auto original = ordered_json::parse(R"({"b":1})");
            auto result   = ordered_json::parse(R"({"b":1,"z":2,"a":3})");

            auto patch = ordered_json::merge_diff(original, result);
            CHECK(patch.dump() == R"({"z":2,"a":3})");

            original.merge_patch(patch);
            CHECK(original == result);
            CHECK(original.dump() == R"({"b":1,"z":2,"a":3})");
        }

        SECTION("removed members follow source order")
        {
            auto original = ordered_json::parse(R"({"c":1,"b":2,"a":3})");
            auto result   = ordered_json::parse(R"({"b":2})");

            auto patch = ordered_json::merge_diff(original, result);
            CHECK(patch.dump() == R"({"c":null,"a":null})");

            original.merge_patch(patch);
            CHECK(original == result);
        }

        SECTION("nested objects keep member order")
        {
            auto original = ordered_json::parse(R"({"z":{"y":1,"x":2},"a":0})");
            auto result   = ordered_json::parse(R"({"z":{"y":1,"x":3,"w":4},"a":0})");

            auto patch = ordered_json::merge_diff(original, result);
            CHECK(patch.dump() == R"({"z":{"x":3,"w":4}})");

            original.merge_patch(patch);
            CHECK(original == result);
            CHECK(original.dump() == R"({"z":{"y":1,"x":3,"w":4},"a":0})");
        }

        SECTION("reordered members cannot be expressed")
        {
            auto original = ordered_json::parse(R"({"a":1,"b":2})");
            auto result   = ordered_json::parse(R"({"b":2,"a":1})");

            auto patch = ordered_json::merge_diff(original, result);
            CHECK(patch.empty());

            original.merge_patch(patch);
            CHECK(original != result);
            CHECK(original.dump() == R"({"a":1,"b":2})");
        }

        SECTION("member added before existing ones is appended")
        {
            auto original = ordered_json::parse(R"({"b":1})");
            auto result   = ordered_json::parse(R"({"a":0,"b":1})");

            auto patch = ordered_json::merge_diff(original, result);
            CHECK(patch.dump() == R"({"a":0})");

            original.merge_patch(patch);
            CHECK(original != result);
            CHECK(original.dump() == R"({"b":1,"a":0})");
        }
    }
}
