/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.9.0
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <fstream>
#include <test_data.hpp>

TEST_CASE("JSON patch")
{
    SECTION("examples from RFC 6902")
    {
        SECTION("4. Operations")
        {
            // the ordering of members in JSON objects is not significant:
            json op1 = R"({ "op": "add", "path": "/a/b/c", "value": "foo" })"_json;
            json op2 = R"({ "path": "/a/b/c", "op": "add", "value": "foo" })"_json;
            json op3 = R"({ "value": "foo", "path": "/a/b/c", "op": "add" })"_json;

            // check if the operation objects are equivalent
            CHECK(op1 == op2);
            CHECK(op1 == op3);
        }

        SECTION("4.1 add")
        {
            json patch = R"([{ "op": "add", "path": "/a/b/c", "value": [ "foo", "bar" ] }])"_json;

            // However, the object itself or an array containing it does need
            // to exist, and it remains an error for that not to be the case.
            // For example, an "add" with a target location of "/a/b" starting
            // with this document
            json doc1 = R"({ "a": { "foo": 1 } })"_json;

            // is not an error, because "a" exists, and "b" will be added to
            // its value.
            CHECK_NOTHROW(doc1.patch(patch));
            auto doc1_ans = R"(
                {
                    "a": {
                        "foo": 1,
                        "b": {
                            "c": [ "foo", "bar" ]
                        }
                    }
                }
            )"_json;
            CHECK(doc1.patch(patch) == doc1_ans);

            // It is an error in this document:
            json doc2 = R"({ "q": { "bar": 2 } })"_json;

            // because "a" does not exist.
            CHECK_THROWS_AS(doc2.patch(patch), json::out_of_range&);
            CHECK_THROWS_WITH(doc2.patch(patch),
                              "[json.exception.out_of_range.403] key 'a' not found");
        }

        SECTION("4.2 remove")
        {
            // If removing an element from an array, any elements above the
            // specified index are shifted one position to the left.
            json doc = {1, 2, 3, 4};
            json patch = {{{"op", "remove"}, {"path", "/1"}}};
            CHECK(doc.patch(patch) == json({1, 3, 4}));
        }

        SECTION("A.1. Adding an Object Member")
        {
            // An example target JSON document:
            json doc = R"(
                    { "foo": "bar"}
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "add", "path": "/baz", "value": "qux" }
                    ]
                )"_json;

            // The resulting JSON document:
            json expected = R"(
                    {
                        "baz": "qux",
                        "foo": "bar"
                    }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.2. Adding an Array Element")
        {
            // An example target JSON document:
            json doc = R"(
                    { "foo": [ "bar", "baz" ] }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "add", "path": "/foo/1", "value": "qux" }
                    ]
                )"_json;

            // The resulting JSON document:
            json expected = R"(
                    { "foo": [ "bar", "qux", "baz" ] }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.3. Removing an Object Member")
        {
            // An example target JSON document:
            json doc = R"(
                    {
                        "baz": "qux",
                        "foo": "bar"
                    }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "remove", "path": "/baz" }
                    ]
                )"_json;

            // The resulting JSON document:
            json expected = R"(
                    { "foo": "bar" }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.4. Removing an Array Element")
        {
            // An example target JSON document:
            json doc = R"(
                    { "foo": [ "bar", "qux", "baz" ] }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "remove", "path": "/foo/1" }
                    ]
                )"_json;

            // The resulting JSON document:
            json expected = R"(
                    { "foo": [ "bar", "baz" ] }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.5. Replacing a Value")
        {
            // An example target JSON document:
            json doc = R"(
                    {
                        "baz": "qux",
                        "foo": "bar"
                    }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "replace", "path": "/baz", "value": "boo" }
                    ]
                )"_json;

            json expected = R"(
                    {
                        "baz": "boo",
                        "foo": "bar"
                    }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.6. Moving a Value")
        {
            // An example target JSON document:
            json doc = R"(
                    {
                        "foo": {
                           "bar": "baz",
                            "waldo": "fred"
                        },
                        "qux": {
                            "corge": "grault"
                        }
                    }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "move", "from": "/foo/waldo", "path": "/qux/thud" }
                    ]
                )"_json;

            // The resulting JSON document:
            json expected = R"(
                    {
                        "foo": {
                           "bar": "baz"
                        },
                        "qux": {
                            "corge": "grault",
                            "thud": "fred"
                        }
                    }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.7. Moving a Value")
        {
            // An example target JSON document:
            json doc = R"(
                    { "foo": [ "all", "grass", "cows", "eat" ] }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "move", "from": "/foo/1", "path": "/foo/3" }
                    ]
                )"_json;

            // The resulting JSON document:
            json expected = R"(
                    { "foo": [ "all", "cows", "eat", "grass" ] }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.8. Testing a Value: Success")
        {
            // An example target JSON document:
            json doc = R"(
                    {
                         "baz": "qux",
                         "foo": [ "a", 2, "c" ]
                    }
                )"_json;

            // A JSON Patch document that will result in successful evaluation:
            json patch = R"(
                    [
                        { "op": "test", "path": "/baz", "value": "qux" },
                        { "op": "test", "path": "/foo/1", "value": 2 }
                    ]
                )"_json;

            // check if evaluation does not throw
            CHECK_NOTHROW(doc.patch(patch));
            // check if patched document is unchanged
            CHECK(doc.patch(patch) == doc);
        }

        SECTION("A.9. Testing a Value: Error")
        {
            // An example target JSON document:
            json doc = R"(
                    { "baz": "qux" }
                )"_json;

            // A JSON Patch document that will result in an error condition:
            json patch = R"(
                    [
                        { "op": "test", "path": "/baz", "value": "bar" }
                    ]
                )"_json;

            // check that evaluation throws
            CHECK_THROWS_AS(doc.patch(patch), json::other_error&);
            CHECK_THROWS_WITH_STD_STR(doc.patch(patch), "[json.exception.other_error.501] unsuccessful: " + patch[0].dump());
        }

        SECTION("A.10. Adding a Nested Member Object")
        {
            // An example target JSON document:
            json doc = R"(
                    { "foo": "bar" }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "add", "path": "/child", "value": { "grandchild": { } } }
                    ]
                )"_json;

            // The resulting JSON document:
            json expected = R"(
                {
                    "foo": "bar",
                    "child": {
                        "grandchild": {
                        }
                    }
                }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.11. Ignoring Unrecognized Elements")
        {
            // An example target JSON document:
            json doc = R"(
                    { "foo": "bar" }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "add", "path": "/baz", "value": "qux", "xyz": 123 }
                    ]
                )"_json;

            json expected = R"(
                    {
                        "foo": "bar",
                        "baz": "qux"
                    } 
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.12. Adding to a Nonexistent Target")
        {
            // An example target JSON document:
            json doc = R"(
                    { "foo": "bar" }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "add", "path": "/baz/bat", "value": "qux" }
                    ]
                )"_json;

            // This JSON Patch document, applied to the target JSON document
            // above, would result in an error (therefore, it would not be
            // applied), because the "add" operation's target location that
            // references neither the root of the document, nor a member of
            // an existing object, nor a member of an existing array.

            CHECK_THROWS_AS(doc.patch(patch), json::out_of_range&);
            CHECK_THROWS_WITH(doc.patch(patch),
                              "[json.exception.out_of_range.403] key 'baz' not found");
        }

        // A.13. Invalid JSON Patch Document
        // not applicable

        SECTION("A.14. Escape Ordering")
        {
            // An example target JSON document:
            json doc = R"(
                    {
                        "/": 9,
                        "~1": 10
                    }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        {"op": "test", "path": "/~01", "value": 10}
                    ]
                )"_json;

            json expected = R"(
                    {
                        "/": 9,
                        "~1": 10
                    } 
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("A.15. Comparing Strings and Numbers")
        {
            // An example target JSON document:
            json doc = R"(
                    {
                        "/": 9,
                        "~1": 10
                    } 
                )"_json;

            // A JSON Patch document that will result in an error condition:
            json patch = R"(
                    [
                        {"op": "test", "path": "/~01", "value": "10"}
                    ]
                )"_json;

            // check that evaluation throws
            CHECK_THROWS_AS(doc.patch(patch), json::other_error&);
            CHECK_THROWS_WITH_STD_STR(doc.patch(patch), "[json.exception.other_error.501] unsuccessful: " + patch[0].dump());
        }

        SECTION("A.16. Adding an Array Value")
        {
            // An example target JSON document:
            json doc = R"(
                    { "foo": ["bar"] }
                )"_json;

            // A JSON Patch document:
            json patch = R"(
                    [
                        { "op": "add", "path": "/foo/-", "value": ["abc", "def"] }
                    ]
                )"_json;

            // The resulting JSON document:
            json expected = R"(
                    { "foo": ["bar", ["abc", "def"]] }
                )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }
    }

    SECTION("own examples")
    {
        SECTION("add")
        {
            SECTION("add to the root element")
            {
                // If the path is the root of the target document - the
                // specified value becomes the entire content of the target
                // document.

                // An example target JSON document:
                json doc = 17;

                // A JSON Patch document:
                json patch = R"(
                        [
                            { "op": "add", "path": "", "value": [1,2,3] }
                        ]
                    )"_json;

                // The resulting JSON document:
                json expected = {1, 2, 3};

                // check if patched value is as expected
                CHECK(doc.patch(patch) == expected);

                // check roundtrip
                CHECK(doc.patch(json::diff(doc, expected)) == expected);
            }

            SECTION("add to end of the array")
            {
                // The specified index MUST NOT be greater than the number of
                // elements in the array. The example below uses and index of
                // exactly the number of elements in the array which is legal.

                // An example target JSON document:
                json doc = {0, 1, 2};

                // A JSON Patch document:
                json patch = R"(
                    [
                        { "op": "add", "path": "/3", "value": 3 }
                    ]
                )"_json;

                // The resulting JSON document:
                json expected = {0, 1, 2, 3};

                // check if patched value is as expected
                CHECK(doc.patch(patch) == expected);

                // check roundtrip
                CHECK(doc.patch(json::diff(doc, expected)) == expected);
            }
        }

        SECTION("copy")
        {
            // An example target JSON document:
            json doc = R"(
                {
                    "foo": {
                        "bar": "baz",
                        "waldo": "fred"
                    },
                    "qux": {
                       "corge": "grault"
                    }
                }
            )"_json;

            // A JSON Patch document:
            json patch = R"(
                [
                    { "op": "copy", "from": "/foo/waldo", "path": "/qux/thud" }
                ]
            )"_json;

            // The resulting JSON document:
            json expected = R"(
                {
                    "foo": {
                        "bar": "baz",
                        "waldo": "fred"
                    },
                    "qux": {
                       "corge": "grault",
                       "thud": "fred"
                    }
                }
            )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == expected);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, expected)) == expected);
        }

        SECTION("replace")
        {
            json j = "string";
            json patch = {{{"op", "replace"}, {"path", ""}, {"value", 1}}};
            CHECK(j.patch(patch) == json(1));
        }

        SECTION("documentation GIF")
        {
            {
                // a JSON patch
                json p1 = R"(
                     [{"op": "add", "path": "/GB", "value": "London"}]
                    )"_json;

                // a JSON value
                json source = R"(
                      {"D": "Berlin", "F": "Paris"}
                    )"_json;

                // apply the patch
                json target = source.patch(p1);
                // target = { "D": "Berlin", "F": "Paris", "GB": "London" }
                CHECK(target == R"({ "D": "Berlin", "F": "Paris", "GB": "London" })"_json);

                // create a diff from two JSONs
                json p2 = json::diff(target, source);
                // p2 = [{"op": "delete", "path": "/GB"}]
                CHECK(p2 == R"([{"op":"remove","path":"/GB"}])"_json);
            }
            {
                // a JSON value
                json j = {"good", "bad", "ugly"};

                // a JSON pointer
                auto ptr = json::json_pointer("/2");

                // use to access elements
                j[ptr] = {{"it", "cattivo"}};
                CHECK(j == R"(["good","bad",{"it":"cattivo"}])"_json);

                // use user-defined string literal
                j["/2/en"_json_pointer] = "ugly";
                CHECK(j == R"(["good","bad",{"en":"ugly","it":"cattivo"}])"_json);

                json flat = j.flatten();
                CHECK(flat == R"({"/0":"good","/1":"bad","/2/en":"ugly","/2/it":"cattivo"})"_json);
            }
        }
    }

    SECTION("errors")
    {
        SECTION("unknown operation")
        {
            SECTION("not an array")
            {
                json j;
                json patch = {{"op", "add"}, {"path", ""}, {"value", 1}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.104] parse error: JSON patch must be an array of objects");
            }

            SECTION("not an array of objects")
            {
                json j;
                json patch = {"op", "add", "path", "", "value", 1};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.104] parse error: JSON patch must be an array of objects");
            }

            SECTION("missing 'op'")
            {
                json j;
                json patch = {{{"foo", "bar"}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation must have member 'op'");
            }

            SECTION("non-string 'op'")
            {
                json j;
                json patch = {{{"op", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation must have string member 'op'");
            }

            SECTION("invalid operation")
            {
                json j;
                json patch = {{{"op", "foo"}, {"path", ""}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation value 'foo' is invalid");
            }
        }

        SECTION("add")
        {
            SECTION("missing 'path'")
            {
                json j;
                json patch = {{{"op", "add"}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'add' must have member 'path'");
            }

            SECTION("non-string 'path'")
            {
                json j;
                json patch = {{{"op", "add"}, {"path", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'add' must have string member 'path'");
            }

            SECTION("missing 'value'")
            {
                json j;
                json patch = {{{"op", "add"}, {"path", ""}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'add' must have member 'value'");
            }

            SECTION("invalid array index")
            {
                json j = {1, 2};
                json patch = {{{"op", "add"}, {"path", "/4"}, {"value", 4}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.401] array index 4 is out of range");
            }
        }

        SECTION("remove")
        {
            SECTION("missing 'path'")
            {
                json j;
                json patch = {{{"op", "remove"}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'remove' must have member 'path'");
            }

            SECTION("non-string 'path'")
            {
                json j;
                json patch = {{{"op", "remove"}, {"path", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'remove' must have string member 'path'");
            }

            SECTION("nonexisting target location (array)")
            {
                json j = {1, 2, 3};
                json patch = {{{"op", "remove"}, {"path", "/17"}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.401] array index 17 is out of range");
            }

            SECTION("nonexisting target location (object)")
            {
                json j = {{"foo", 1}, {"bar", 2}};
                json patch = {{{"op", "remove"}, {"path", "/baz"}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.403] key 'baz' not found");
            }

            SECTION("root element as target location")
            {
                json j = "string";
                json patch = {{{"op", "remove"}, {"path", ""}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.405] JSON pointer has no parent");
            }
        }

        SECTION("replace")
        {
            SECTION("missing 'path'")
            {
                json j;
                json patch = {{{"op", "replace"}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'replace' must have member 'path'");
            }

            SECTION("non-string 'path'")
            {
                json j;
                json patch = {{{"op", "replace"}, {"path", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'replace' must have string member 'path'");
            }

            SECTION("missing 'value'")
            {
                json j;
                json patch = {{{"op", "replace"}, {"path", ""}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'replace' must have member 'value'");
            }

            SECTION("nonexisting target location (array)")
            {
                json j = {1, 2, 3};
                json patch = {{{"op", "replace"}, {"path", "/17"}, {"value", 19}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.401] array index 17 is out of range");
            }

            SECTION("nonexisting target location (object)")
            {
                json j = {{"foo", 1}, {"bar", 2}};
                json patch = {{{"op", "replace"}, {"path", "/baz"}, {"value", 3}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.403] key 'baz' not found");
            }
        }

        SECTION("move")
        {
            SECTION("missing 'path'")
            {
                json j;
                json patch = {{{"op", "move"}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'move' must have member 'path'");
            }

            SECTION("non-string 'path'")
            {
                json j;
                json patch = {{{"op", "move"}, {"path", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'move' must have string member 'path'");
            }

            SECTION("missing 'from'")
            {
                json j;
                json patch = {{{"op", "move"}, {"path", ""}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'move' must have member 'from'");
            }

            SECTION("non-string 'from'")
            {
                json j;
                json patch = {{{"op", "move"}, {"path", ""}, {"from", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'move' must have string member 'from'");
            }

            SECTION("nonexisting from location (array)")
            {
                json j = {1, 2, 3};
                json patch = {{{"op", "move"}, {"path", "/0"}, {"from", "/5"}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.401] array index 5 is out of range");
            }

            SECTION("nonexisting from location (object)")
            {
                json j = {{"foo", 1}, {"bar", 2}};
                json patch = {{{"op", "move"}, {"path", "/baz"}, {"from", "/baz"}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.403] key 'baz' not found");
            }
        }

        SECTION("copy")
        {
            SECTION("missing 'path'")
            {
                json j;
                json patch = {{{"op", "copy"}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'copy' must have member 'path'");
            }

            SECTION("non-string 'path'")
            {
                json j;
                json patch = {{{"op", "copy"}, {"path", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'copy' must have string member 'path'");
            }

            SECTION("missing 'from'")
            {
                json j;
                json patch = {{{"op", "copy"}, {"path", ""}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'copy' must have member 'from'");
            }

            SECTION("non-string 'from'")
            {
                json j;
                json patch = {{{"op", "copy"}, {"path", ""}, {"from", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'copy' must have string member 'from'");
            }

            SECTION("nonexisting from location (array)")
            {
                json j = {1, 2, 3};
                json patch = {{{"op", "copy"}, {"path", "/0"}, {"from", "/5"}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.401] array index 5 is out of range");
            }

            SECTION("nonexisting from location (object)")
            {
                json j = {{"foo", 1}, {"bar", 2}};
                json patch = {{{"op", "copy"}, {"path", "/fob"}, {"from", "/baz"}}};
                CHECK_THROWS_AS(j.patch(patch), json::out_of_range&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.out_of_range.403] key 'baz' not found");
            }
        }

        SECTION("test")
        {
            SECTION("missing 'path'")
            {
                json j;
                json patch = {{{"op", "test"}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'test' must have member 'path'");
            }

            SECTION("non-string 'path'")
            {
                json j;
                json patch = {{{"op", "test"}, {"path", 1}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'test' must have string member 'path'");
            }

            SECTION("missing 'value'")
            {
                json j;
                json patch = {{{"op", "test"}, {"path", ""}}};
                CHECK_THROWS_AS(j.patch(patch), json::parse_error&);
                CHECK_THROWS_WITH(j.patch(patch),
                                  "[json.exception.parse_error.105] parse error: operation 'test' must have member 'value'");
            }
        }
    }

    SECTION("Examples from jsonpatch.com")
    {
        SECTION("Simple Example")
        {
            // The original document
            json doc = R"(
                {
                  "baz": "qux",
                  "foo": "bar"
                }
            )"_json;

            // The patch
            json patch = R"(
                [
                  { "op": "replace", "path": "/baz", "value": "boo" },
                  { "op": "add", "path": "/hello", "value": ["world"] },
                  { "op": "remove", "path": "/foo"}
                ]
            )"_json;

            // The result
            json result = R"(
                {
                   "baz": "boo",
                   "hello": ["world"]
                }
            )"_json;

            // check if patched value is as expected
            CHECK(doc.patch(patch) == result);

            // check roundtrip
            CHECK(doc.patch(json::diff(doc, result)) == result);
        }

        SECTION("Operations")
        {
            // The original document
            json doc = R"(
                {
                  "biscuits": [
                    {"name":"Digestive"},
                    {"name": "Choco Liebniz"}
                  ]
                }
            )"_json;

            SECTION("add")
            {
                // The patch
                json patch = R"(
                    [
                        {"op": "add", "path": "/biscuits/1", "value": {"name": "Ginger Nut"}}
                    ]
                )"_json;

                // The result
                json result = R"(
                    {
                      "biscuits": [
                        {"name": "Digestive"},
                        {"name": "Ginger Nut"},
                        {"name": "Choco Liebniz"}
                      ]
                    }
                )"_json;

                // check if patched value is as expected
                CHECK(doc.patch(patch) == result);

                // check roundtrip
                CHECK(doc.patch(json::diff(doc, result)) == result);
            }

            SECTION("remove")
            {
                // The patch
                json patch = R"(
                    [
                        {"op": "remove", "path": "/biscuits"}
                    ]
                )"_json;

                // The result
                json result = R"(
                    {}
                )"_json;

                // check if patched value is as expected
                CHECK(doc.patch(patch) == result);

                // check roundtrip
                CHECK(doc.patch(json::diff(doc, result)) == result);
            }

            SECTION("replace")
            {
                // The patch
                json patch = R"(
                    [
                        {"op": "replace", "path": "/biscuits/0/name", "value": "Chocolate Digestive"}
                    ]
                )"_json;

                // The result
                json result = R"(
                    {
                      "biscuits": [
                        {"name": "Chocolate Digestive"},
                        {"name": "Choco Liebniz"}
                      ]
                    }
                )"_json;

                // check if patched value is as expected
                CHECK(doc.patch(patch) == result);

                // check roundtrip
                CHECK(doc.patch(json::diff(doc, result)) == result);
            }

            SECTION("copy")
            {
                // The patch
                json patch = R"(
                    [
                        {"op": "copy", "from": "/biscuits/0", "path": "/best_biscuit"}
                    ]
                )"_json;

                // The result
                json result = R"(
                    {
                      "biscuits": [
                        {"name": "Digestive"},
                        {"name": "Choco Liebniz"}
                      ],
                      "best_biscuit": {
                        "name": "Digestive"
                      }
                    }
                )"_json;

                // check if patched value is as expected
                CHECK(doc.patch(patch) == result);

                // check roundtrip
                CHECK(doc.patch(json::diff(doc, result)) == result);
            }

            SECTION("move")
            {
                // The patch
                json patch = R"(
                    [
                        {"op": "move", "from": "/biscuits", "path": "/cookies"}
                    ]
                )"_json;

                // The result
                json result = R"(
                    {
                      "cookies": [
                        {"name": "Digestive"},
                        {"name": "Choco Liebniz"}
                      ]
                    }
                )"_json;

                // check if patched value is as expected
                CHECK(doc.patch(patch) == result);

                // check roundtrip
                CHECK(doc.patch(json::diff(doc, result)) == result);
            }

            SECTION("test")
            {
                // The patch
                json patch = R"(
                    [
                        {"op": "test", "path": "/best_biscuit/name", "value": "Choco Liebniz"}
                    ]
                )"_json;

                // the test will fail
                CHECK_THROWS_AS(doc.patch(patch), json::other_error&);
                CHECK_THROWS_WITH_STD_STR(doc.patch(patch), "[json.exception.other_error.501] unsuccessful: " + patch[0].dump());
            }
        }
    }

    SECTION("Examples from bruth.github.io/jsonpatch-js")
    {
        SECTION("add")
        {
            CHECK(R"( {} )"_json.patch(
                      R"( [{"op": "add", "path": "/foo", "value": "bar"}] )"_json
                  ) == R"( {"foo": "bar"} )"_json);

            CHECK(R"( {"foo": [1, 3]} )"_json.patch(
                      R"( [{"op": "add", "path": "/foo", "value": "bar"}] )"_json
                  ) == R"( {"foo": "bar"} )"_json);

            CHECK(R"( {"foo": [{}]} )"_json.patch(
                      R"( [{"op": "add", "path": "/foo/0/bar", "value": "baz"}] )"_json
                  ) == R"( {"foo": [{"bar": "baz"}]} )"_json);
        }

        SECTION("remove")
        {
            CHECK(R"( {"foo": "bar"} )"_json.patch(
                      R"( [{"op": "remove", "path": "/foo"}] )"_json
                  ) == R"( {} )"_json);

            CHECK(R"( {"foo": [1, 2, 3]} )"_json.patch(
                      R"( [{"op": "remove", "path": "/foo/1"}] )"_json
                  ) == R"( {"foo": [1, 3]} )"_json);

            CHECK(R"( {"foo": [{"bar": "baz"}]} )"_json.patch(
                      R"( [{"op": "remove", "path": "/foo/0/bar"}] )"_json
                  ) == R"( {"foo": [{}]} )"_json);
        }

        SECTION("replace")
        {
            CHECK(R"( {"foo": "bar"} )"_json.patch(
                      R"( [{"op": "replace", "path": "/foo", "value": 1}] )"_json
                  ) == R"( {"foo": 1} )"_json);

            CHECK(R"( {"foo": [1, 2, 3]} )"_json.patch(
                      R"( [{"op": "replace", "path": "/foo/1", "value": 4}] )"_json
                  ) == R"( {"foo": [1, 4, 3]} )"_json);

            CHECK(R"( {"foo": [{"bar": "baz"}]} )"_json.patch(
                      R"( [{"op": "replace", "path": "/foo/0/bar", "value": 1}] )"_json
                  ) == R"( {"foo": [{"bar": 1}]} )"_json);
        }

        SECTION("move")
        {
            CHECK(R"( {"foo": [1, 2, 3]} )"_json.patch(
                      R"( [{"op": "move", "from": "/foo", "path": "/bar"}] )"_json
                  ) == R"( {"bar": [1, 2, 3]} )"_json);
        }

        SECTION("copy")
        {
            CHECK(R"( {"foo": [1, 2, 3]} )"_json.patch(
                      R"( [{"op": "copy", "from": "/foo/1", "path": "/bar"}] )"_json
                  ) == R"( {"foo": [1, 2, 3], "bar": 2} )"_json);
        }

        SECTION("copy")
        {
            CHECK_NOTHROW(R"( {"foo": "bar"} )"_json.patch(
                              R"( [{"op": "test", "path": "/foo", "value": "bar"}] )"_json));
        }
    }

    SECTION("Tests from github.com/json-patch/json-patch-tests")
    {
        for (auto filename :
                {
                    TEST_DATA_DIRECTORY "/json-patch-tests/spec_tests.json",
                    TEST_DATA_DIRECTORY "/json-patch-tests/tests.json"
                })
        {
            CAPTURE(filename)
            std::ifstream f(filename);
            json suite = json::parse(f);

            for (const auto& test : suite)
            {
                INFO_WITH_TEMP(test.value("comment", ""));

                // skip tests marked as disabled
                if (test.value("disabled", false))
                {
                    continue;
                }

                const auto& doc = test["doc"];
                const auto& patch = test["patch"];

                if (test.count("error") == 0)
                {
                    // if an expected value is given, use it; use doc otherwise
                    const auto& expected = test.value("expected", doc);
                    CHECK(doc.patch(patch) == expected);
                }
                else
                {
                    CHECK_THROWS(doc.patch(patch));
                }
            }
        }
    }
}
