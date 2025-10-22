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
