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

            json expected = R"({
                "a": "z",
                "c": {
                    "d": "e"
                }
            })"_json;

            document.merge_patch(json::merge_diff(document, expected));
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

            document.merge_patch(json::merge_diff(document, expected));
            CHECK(document == expected);
        }

        SECTION("Appendix A")
        {
            SECTION("Example 1")
            {
                json original = R"({"a":"b"})"_json;
                json result = R"({"a":"c"})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 2")
            {
                json original = R"({"a":"b"})"_json;
                json result = R"({"a":"b", "b":"c"})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 3")
            {
                json original = R"({"a":"b"})"_json;
                json result = R"({})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 4")
            {
                json original = R"({"a":"b","b":"c"})"_json;
                json result = R"({"b":"c"})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 5")
            {
                json original = R"({"a":["b"]})"_json;
                json result = R"({"a":"c"})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 6")
            {
                json original = R"({"a":"c"})"_json;
                json result = R"({"a":["b"]})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 7")
            {
                json original = R"({"a":{"b": "c"}})"_json;
                json result = R"({"a": {"b": "d"}})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 8")
            {
                json original = R"({"a":[{"b":"c"}]})"_json;
                json result = R"({"a":[1]})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 9")
            {
                json original = R"(["a","b"])"_json;
                json result = R"(["c","d"])"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 10")
            {
                json original = R"({"a":"b"})"_json;
                json result = R"(["c"])"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 11")
            {
                json original = R"({"a":"foo"})"_json;
                json result = R"(null)"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 12")
            {
                json original = R"({"a":"foo"})"_json;
                json result = R"("bar")"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 13")
            {
                json original = R"({"e":null})"_json;
                json result = R"({"e":null,"a":1})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 14")
            {
                json original = R"([1,2])"_json;
                json result = R"({"a":"b"})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }

            SECTION("Example 15")
            {
                json original = R"({})"_json;
                json result = R"({"a":{"bb":{}}})"_json;

                original.merge_patch(json::merge_diff(original, result));
                CHECK(original == result);
            }
        }
    }

    SECTION("null values")
    {
        SECTION("object with null value to object")
        {
            json original = R"({"a":null})"_json;
            json result = R"({"a":{"b":"c"}})"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }

        SECTION("object to object with null value")
        {
            json original = R"({"a":{"b":"c"}})"_json;
            json result = R"({"a":null})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"a\" to null", json::other_error&);
        }

        SECTION("primitive to object with null value")
        {
            json original = R"({"a":1})"_json;
            json result   = R"({"a":null})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"a\" to null", json::other_error&);
        }

        SECTION("nested primitive to object with null value")
        {
            json original = R"({"a":{"b":1}})"_json;
            json result   = R"({"a":{"b":null}})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"b\" to null", json::other_error&);
        }

        SECTION("array value to object with null value")
        {
            json original = R"({"a":[1,2]})"_json;
            json result   = R"({"a":null})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"a\" to null", json::other_error&);
        }

        SECTION("nested object to object with null value")
        {
            json original = R"({"a":{"b":{"c":"d"}}})"_json;
            json result   = R"({"a":{"b":null}})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"b\" to null", json::other_error&);
        }

        SECTION("nested primitive to object with null value with sibling")
        {
            json original = R"({"x":"y","a":{"b":"c"}})"_json;
            json result   = R"({"x":"y","a":{"b":null, "c":"d"}})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"b\" to null", json::other_error&);
        }

        SECTION("empty object to object with null value")
        {
            json original = R"({})"_json;
            json result   = R"({"a":null})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"a\" to null", json::other_error&);
        }

        SECTION("null to object with null value")
        {
            json original = R"(null)"_json;
            json result   = R"({"a":null})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"a\" to null", json::other_error&);
        }

        SECTION("array to object with null value")
        {
            json original = R"([])"_json;
            json result   = R"({"a":null})"_json;

            json _;
            CHECK_THROWS_WITH_AS(_ = json::merge_diff(original, result), "[json.exception.other_error.503] cannot set \"a\" to null", json::other_error&);
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

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }

        SECTION("number")
        {
            json original = R"(1)"_json;
            json result   = R"(2)"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }

        SECTION("boolean")
        {
            json original = R"(false)"_json;
            json result   = R"(true)"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }

        SECTION("object to primitive")
        {
            json original = R"({"a":{"b":"c"}})"_json;
            json result   = R"({"a":1})"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }

        SECTION("primitive to object")
        {
            json original = R"({"a":1})"_json;
            json result   = R"({"a":{"b":"c"}})"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }
    }

    SECTION("arrays")
    {
        SECTION("array to array")
        {
            json original = R"([1,2,3])"_json;
            json result   = R"([1,2,4])"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }

        SECTION("array to empty array")
        {
            json original = R"([1,2,3])"_json;
            json result   = R"([])"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }

        SECTION("empty array to array")
        {
            json original = R"([])"_json;
            json result   = R"([1,2,3])"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }

        SECTION("same keys")
        {
            json original = R"(["a","b"])"_json;
            json result   = R"({"a":1,"b":2})"_json;

            original.merge_patch(json::merge_diff(original, result));
            CHECK(original == result);
        }
    }
}
