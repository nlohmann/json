//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <map>
#include <sstream>

TEST_CASE("JSON pointers")
{
    SECTION("errors")
    {
        CHECK_THROWS_WITH_AS(json::json_pointer("foo"),
                             "[json.exception.parse_error.107] parse error at byte 1: JSON pointer must be empty or begin with '/' - was: 'foo'", json::parse_error&);

        CHECK_THROWS_WITH_AS(json::json_pointer("/~~"),
                             "[json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'", json::parse_error&);

        CHECK_THROWS_WITH_AS(json::json_pointer("/~"),
                             "[json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'", json::parse_error&);

        json::json_pointer p;
        CHECK_THROWS_WITH_AS(p.top(),
                             "[json.exception.out_of_range.405] JSON pointer has no parent", json::out_of_range&);
        CHECK_THROWS_WITH_AS(p.pop_back(),
                             "[json.exception.out_of_range.405] JSON pointer has no parent", json::out_of_range&);

        SECTION("array index error")
        {
            json v = {1, 2, 3, 4};
            json::json_pointer const ptr("/10e");
            CHECK_THROWS_WITH_AS(v[ptr],
                                 "[json.exception.out_of_range.404] unresolved reference token '10e'", json::out_of_range&);
        }
    }

    SECTION("examples from RFC 6901")
    {
        SECTION("nonconst access")
        {
            json j = R"(
            {
                "foo": ["bar", "baz"],
                "": 0,
                "a/b": 1,
                "c%d": 2,
                "e^f": 3,
                "g|h": 4,
                "i\\j": 5,
                "k\"l": 6,
                " ": 7,
                "m~n": 8
            }
            )"_json;

            // the whole document
            CHECK(j[json::json_pointer()] == j);
            CHECK(j[json::json_pointer("")] == j);
            CHECK(j.contains(json::json_pointer()));
            CHECK(j.contains(json::json_pointer("")));

            // array access
            CHECK(j[json::json_pointer("/foo")] == j["foo"]);
            CHECK(j.contains(json::json_pointer("/foo")));
            CHECK(j[json::json_pointer("/foo/0")] == j["foo"][0]);
            CHECK(j[json::json_pointer("/foo/1")] == j["foo"][1]);
            CHECK(j["/foo/1"_json_pointer] == j["foo"][1]);
            CHECK(j.contains(json::json_pointer("/foo/0")));
            CHECK(j.contains(json::json_pointer("/foo/1")));
            CHECK(!j.contains(json::json_pointer("/foo/3")));
            CHECK(!j.contains(json::json_pointer("/foo/+")));
            CHECK(!j.contains(json::json_pointer("/foo/1+2")));
            CHECK(!j.contains(json::json_pointer("/foo/-")));

            // checked array access
            CHECK(j.at(json::json_pointer("/foo/0")) == j["foo"][0]);
            CHECK(j.at(json::json_pointer("/foo/1")) == j["foo"][1]);

            // empty string access
            CHECK(j[json::json_pointer("/")] == j[""]);
            CHECK(j.contains(json::json_pointer("")));
            CHECK(j.contains(json::json_pointer("/")));

            // other cases
            CHECK(j[json::json_pointer("/ ")] == j[" "]);
            CHECK(j[json::json_pointer("/c%d")] == j["c%d"]);
            CHECK(j[json::json_pointer("/e^f")] == j["e^f"]);
            CHECK(j[json::json_pointer("/g|h")] == j["g|h"]);
            CHECK(j[json::json_pointer("/i\\j")] == j["i\\j"]);
            CHECK(j[json::json_pointer("/k\"l")] == j["k\"l"]);

            // contains
            CHECK(j.contains(json::json_pointer("/ ")));
            CHECK(j.contains(json::json_pointer("/c%d")));
            CHECK(j.contains(json::json_pointer("/e^f")));
            CHECK(j.contains(json::json_pointer("/g|h")));
            CHECK(j.contains(json::json_pointer("/i\\j")));
            CHECK(j.contains(json::json_pointer("/k\"l")));

            // checked access
            CHECK(j.at(json::json_pointer("/ ")) == j[" "]);
            CHECK(j.at(json::json_pointer("/c%d")) == j["c%d"]);
            CHECK(j.at(json::json_pointer("/e^f")) == j["e^f"]);
            CHECK(j.at(json::json_pointer("/g|h")) == j["g|h"]);
            CHECK(j.at(json::json_pointer("/i\\j")) == j["i\\j"]);
            CHECK(j.at(json::json_pointer("/k\"l")) == j["k\"l"]);

            // escaped access
            CHECK(j[json::json_pointer("/a~1b")] == j["a/b"]);
            CHECK(j[json::json_pointer("/m~0n")] == j["m~n"]);
            CHECK(j.contains(json::json_pointer("/a~1b")));
            CHECK(j.contains(json::json_pointer("/m~0n")));

            // unescaped access to nonexisting values yield object creation
            CHECK(!j.contains(json::json_pointer("/a/b")));
            CHECK_NOTHROW(j[json::json_pointer("/a/b")] = 42);
            CHECK(j.contains(json::json_pointer("/a/b")));
            CHECK(j["a"]["b"] == json(42));

            CHECK(!j.contains(json::json_pointer("/a/c/1")));
            CHECK_NOTHROW(j[json::json_pointer("/a/c/1")] = 42);
            CHECK(j["a"]["c"] == json({nullptr, 42}));
            CHECK(j.contains(json::json_pointer("/a/c/1")));

            CHECK(!j.contains(json::json_pointer("/a/d/-")));
            CHECK_NOTHROW(j[json::json_pointer("/a/d/-")] = 42);
            CHECK(!j.contains(json::json_pointer("/a/d/-")));
            CHECK(j["a"]["d"] == json::array({42}));
            // "/a/b" works for JSON {"a": {"b": 42}}
            CHECK(json({{"a", {{"b", 42}}}})[json::json_pointer("/a/b")] == json(42));

            // unresolved access
            json j_primitive = 1;
            CHECK_THROWS_WITH_AS(j_primitive["/foo"_json_pointer],
                                 "[json.exception.out_of_range.404] unresolved reference token 'foo'", json::out_of_range&);
            CHECK_THROWS_WITH_AS(j_primitive.at("/foo"_json_pointer),
                                 "[json.exception.out_of_range.404] unresolved reference token 'foo'", json::out_of_range&);
            CHECK(!j_primitive.contains(json::json_pointer("/foo")));
        }

        SECTION("const access")
        {
            const json j = R"(
            {
                "foo": ["bar", "baz"],
                "": 0,
                "a/b": 1,
                "c%d": 2,
                "e^f": 3,
                "g|h": 4,
                "i\\j": 5,
                "k\"l": 6,
                " ": 7,
                "m~n": 8
            }
            )"_json;

            // the whole document
            CHECK(j[json::json_pointer()] == j);
            CHECK(j[json::json_pointer("")] == j);

            // array access
            CHECK(j[json::json_pointer("/foo")] == j["foo"]);
            CHECK(j[json::json_pointer("/foo/0")] == j["foo"][0]);
            CHECK(j[json::json_pointer("/foo/1")] == j["foo"][1]);
            CHECK(j["/foo/1"_json_pointer] == j["foo"][1]);

            // checked array access
            CHECK(j.at(json::json_pointer("/foo/0")) == j["foo"][0]);
            CHECK(j.at(json::json_pointer("/foo/1")) == j["foo"][1]);

            // empty string access
            CHECK(j[json::json_pointer("/")] == j[""]);

            // other cases
            CHECK(j[json::json_pointer("/ ")] == j[" "]);
            CHECK(j[json::json_pointer("/c%d")] == j["c%d"]);
            CHECK(j[json::json_pointer("/e^f")] == j["e^f"]);
            CHECK(j[json::json_pointer("/g|h")] == j["g|h"]);
            CHECK(j[json::json_pointer("/i\\j")] == j["i\\j"]);
            CHECK(j[json::json_pointer("/k\"l")] == j["k\"l"]);

            // checked access
            CHECK(j.at(json::json_pointer("/ ")) == j[" "]);
            CHECK(j.at(json::json_pointer("/c%d")) == j["c%d"]);
            CHECK(j.at(json::json_pointer("/e^f")) == j["e^f"]);
            CHECK(j.at(json::json_pointer("/g|h")) == j["g|h"]);
            CHECK(j.at(json::json_pointer("/i\\j")) == j["i\\j"]);
            CHECK(j.at(json::json_pointer("/k\"l")) == j["k\"l"]);

            // escaped access
            CHECK(j[json::json_pointer("/a~1b")] == j["a/b"]);
            CHECK(j[json::json_pointer("/m~0n")] == j["m~n"]);
#if JSON_DIAGNOSTIC_POSITIONS
            // unescaped access
            CHECK_THROWS_WITH_AS(j.at(json::json_pointer("/a/b")),
                                 "[json.exception.out_of_range.403] (bytes 13-297) key 'a' not found", json::out_of_range&);
#else
            // unescaped access
            CHECK_THROWS_WITH_AS(j.at(json::json_pointer("/a/b")),
                                 "[json.exception.out_of_range.403] key 'a' not found", json::out_of_range&);
#endif
            // unresolved access
            const json j_primitive = 1;
            CHECK_THROWS_WITH_AS(j_primitive["/foo"_json_pointer],
                                 "[json.exception.out_of_range.404] unresolved reference token 'foo'", json::out_of_range&);
            CHECK_THROWS_WITH_AS(j_primitive.at("/foo"_json_pointer),
                                 "[json.exception.out_of_range.404] unresolved reference token 'foo'", json::out_of_range&);
        }

        SECTION("user-defined string literal")
        {
            json j = R"(
            {
                "foo": ["bar", "baz"],
                "": 0,
                "a/b": 1,
                "c%d": 2,
                "e^f": 3,
                "g|h": 4,
                "i\\j": 5,
                "k\"l": 6,
                " ": 7,
                "m~n": 8
            }
            )"_json;

            // the whole document
            CHECK(j[""_json_pointer] == j);
            CHECK(j.contains(""_json_pointer));

            // array access
            CHECK(j["/foo"_json_pointer] == j["foo"]);
            CHECK(j["/foo/0"_json_pointer] == j["foo"][0]);
            CHECK(j["/foo/1"_json_pointer] == j["foo"][1]);
            CHECK(j.contains("/foo"_json_pointer));
            CHECK(j.contains("/foo/0"_json_pointer));
            CHECK(j.contains("/foo/1"_json_pointer));
            CHECK(!j.contains("/foo/-"_json_pointer));
        }
    }

    SECTION("array access")
    {
        SECTION("nonconst access")
        {
            json j = {1, 2, 3};
            const json j_const = j;

            // check reading access
            CHECK(j["/0"_json_pointer] == j[0]);
            CHECK(j["/1"_json_pointer] == j[1]);
            CHECK(j["/2"_json_pointer] == j[2]);

            // assign to existing index
            j["/1"_json_pointer] = 13;
            CHECK(j[1] == json(13));

            // assign to nonexisting index
            j["/3"_json_pointer] = 33;
            CHECK(j[3] == json(33));

            // assign to nonexisting index (with gap)
            j["/5"_json_pointer] = 55;
            CHECK(j == json({1, 13, 3, 33, nullptr, 55}));

            // error with leading 0
            CHECK_THROWS_WITH_AS(j["/01"_json_pointer],
                                 "[json.exception.parse_error.106] parse error: array index '01' must not begin with '0'", json::parse_error&);
            CHECK_THROWS_WITH_AS(j_const["/01"_json_pointer],
                                 "[json.exception.parse_error.106] parse error: array index '01' must not begin with '0'", json::parse_error&);
            CHECK_THROWS_WITH_AS(j.at("/01"_json_pointer),
                                 "[json.exception.parse_error.106] parse error: array index '01' must not begin with '0'", json::parse_error&);
            CHECK_THROWS_WITH_AS(j_const.at("/01"_json_pointer),
                                 "[json.exception.parse_error.106] parse error: array index '01' must not begin with '0'", json::parse_error&);

            CHECK(!j.contains("/01"_json_pointer));
            CHECK(!j.contains("/01"_json_pointer));
            CHECK(!j_const.contains("/01"_json_pointer));
            CHECK(!j_const.contains("/01"_json_pointer));

            // error with incorrect numbers
            CHECK_THROWS_WITH_AS(j["/one"_json_pointer] = 1,
                                 "[json.exception.parse_error.109] parse error: array index 'one' is not a number", json::parse_error&);
            CHECK_THROWS_WITH_AS(j_const["/one"_json_pointer] == 1,
                                 "[json.exception.parse_error.109] parse error: array index 'one' is not a number", json::parse_error&);

            CHECK_THROWS_WITH_AS(j.at("/one"_json_pointer) = 1,
                                 "[json.exception.parse_error.109] parse error: array index 'one' is not a number", json::parse_error&);
            CHECK_THROWS_WITH_AS(j_const.at("/one"_json_pointer) == 1,
                                 "[json.exception.parse_error.109] parse error: array index 'one' is not a number", json::parse_error&);

            CHECK_THROWS_WITH_AS(j["/+1"_json_pointer] = 1,
                                 "[json.exception.parse_error.109] parse error: array index '+1' is not a number", json::parse_error&);
            CHECK_THROWS_WITH_AS(j_const["/+1"_json_pointer] == 1,
                                 "[json.exception.parse_error.109] parse error: array index '+1' is not a number", json::parse_error&);

            CHECK_THROWS_WITH_AS(j["/1+1"_json_pointer] = 1,
                                 "[json.exception.out_of_range.404] unresolved reference token '1+1'", json::out_of_range&);
            CHECK_THROWS_WITH_AS(j_const["/1+1"_json_pointer] == 1,
                                 "[json.exception.out_of_range.404] unresolved reference token '1+1'", json::out_of_range&);

            {
                auto too_large_index = std::to_string((std::numeric_limits<unsigned long long>::max)()) + "1";
                json::json_pointer const jp(std::string("/") + too_large_index);
                std::string const throw_msg = std::string("[json.exception.out_of_range.404] unresolved reference token '") + too_large_index + "'";

                CHECK_THROWS_WITH_AS(j[jp] = 1, throw_msg.c_str(), json::out_of_range&);
                CHECK_THROWS_WITH_AS(j_const[jp] == 1, throw_msg.c_str(), json::out_of_range&);
            }

            // on some machines, the check below is not constant
            DOCTEST_MSVC_SUPPRESS_WARNING_PUSH
            DOCTEST_MSVC_SUPPRESS_WARNING(4127)

            if (sizeof(typename json::size_type) < sizeof(unsigned long long))
            {
                auto size_type_max_uul = static_cast<unsigned long long>((std::numeric_limits<json::size_type>::max)());
                auto too_large_index = std::to_string(size_type_max_uul);
                json::json_pointer const jp(std::string("/") + too_large_index);
                std::string const throw_msg = std::string("[json.exception.out_of_range.410] array index ") + too_large_index + " exceeds size_type";

                CHECK_THROWS_WITH_AS(j[jp] = 1, throw_msg.c_str(), json::out_of_range&);
                CHECK_THROWS_WITH_AS(j_const[jp] == 1, throw_msg.c_str(), json::out_of_range&);
            }

            DOCTEST_MSVC_SUPPRESS_WARNING_POP

            CHECK_THROWS_WITH_AS(j.at("/one"_json_pointer) = 1,
                                 "[json.exception.parse_error.109] parse error: array index 'one' is not a number", json::parse_error&);
            CHECK_THROWS_WITH_AS(j_const.at("/one"_json_pointer) == 1,
                                 "[json.exception.parse_error.109] parse error: array index 'one' is not a number", json::parse_error&);

            CHECK(!j.contains("/one"_json_pointer));
            CHECK(!j.contains("/one"_json_pointer));
            CHECK(!j_const.contains("/one"_json_pointer));
            CHECK(!j_const.contains("/one"_json_pointer));

            CHECK_THROWS_WITH_AS(json({{"/list/0", 1}, {"/list/1", 2}, {"/list/three", 3}}).unflatten(),
            "[json.exception.parse_error.109] parse error: array index 'three' is not a number", json::parse_error&);

            // assign to "-"
            j["/-"_json_pointer] = 99;
            CHECK(j == json({1, 13, 3, 33, nullptr, 55, 99}));

            // error when using "-" in const object
            CHECK_THROWS_WITH_AS(j_const["/-"_json_pointer],
                                 "[json.exception.out_of_range.402] array index '-' (3) is out of range", json::out_of_range&);
            CHECK(!j_const.contains("/-"_json_pointer));

            // error when using "-" with at
            CHECK_THROWS_WITH_AS(j.at("/-"_json_pointer),
                                 "[json.exception.out_of_range.402] array index '-' (7) is out of range", json::out_of_range&);
            CHECK_THROWS_WITH_AS(j_const.at("/-"_json_pointer),
                                 "[json.exception.out_of_range.402] array index '-' (3) is out of range", json::out_of_range&);
            CHECK(!j_const.contains("/-"_json_pointer));
        }

        SECTION("const access")
        {
            const json j = {1, 2, 3};

            // check reading access
            CHECK(j["/0"_json_pointer] == j[0]);
            CHECK(j["/1"_json_pointer] == j[1]);
            CHECK(j["/2"_json_pointer] == j[2]);

            // assign to nonexisting index
            CHECK_THROWS_WITH_AS(j.at("/3"_json_pointer),
                                 "[json.exception.out_of_range.401] array index 3 is out of range", json::out_of_range&);
            CHECK(!j.contains("/3"_json_pointer));

            // assign to nonexisting index (with gap)
            CHECK_THROWS_WITH_AS(j.at("/5"_json_pointer),
                                 "[json.exception.out_of_range.401] array index 5 is out of range", json::out_of_range&);
            CHECK(!j.contains("/5"_json_pointer));

            // assign to "-"
            CHECK_THROWS_WITH_AS(j["/-"_json_pointer],
                                 "[json.exception.out_of_range.402] array index '-' (3) is out of range", json::out_of_range&);
            CHECK_THROWS_WITH_AS(j.at("/-"_json_pointer),
                                 "[json.exception.out_of_range.402] array index '-' (3) is out of range", json::out_of_range&);
            CHECK(!j.contains("/-"_json_pointer));
        }
    }

    SECTION("flatten")
    {
        json j =
        {
            {"pi", 3.141},
            {"happy", true},
            {"name", "Niels"},
            {"nothing", nullptr},
            {
                "answer", {
                    {"everything", 42}
                }
            },
            {"list", {1, 0, 2}},
            {
                "object", {
                    {"currency", "USD"},
                    {"value", 42.99},
                    {"", "empty string"},
                    {"/", "slash"},
                    {"~", "tilde"},
                    {"~1", "tilde1"}
                }
            }
        };

        json j_flatten =
        {
            {"/pi", 3.141},
            {"/happy", true},
            {"/name", "Niels"},
            {"/nothing", nullptr},
            {"/answer/everything", 42},
            {"/list/0", 1},
            {"/list/1", 0},
            {"/list/2", 2},
            {"/object/currency", "USD"},
            {"/object/value", 42.99},
            {"/object/", "empty string"},
            {"/object/~1", "slash"},
            {"/object/~0", "tilde"},
            {"/object/~01", "tilde1"}
        };

        // check if flattened result is as expected
        CHECK(j.flatten() == j_flatten);

        // check if unflattened result is as expected
        CHECK(j_flatten.unflatten() == j);

        // error for nonobjects
        CHECK_THROWS_WITH_AS(json(1).unflatten(),
                             "[json.exception.type_error.314] only objects can be unflattened", json::type_error&);

        // error for nonprimitve values
#if JSON_DIAGNOSTICS
        CHECK_THROWS_WITH_AS(json({{"/1", {1, 2, 3}}}).unflatten(), "[json.exception.type_error.315] (/~11) values in object must be primitive", json::type_error&);
#else
        CHECK_THROWS_WITH_AS(json({{"/1", {1, 2, 3}}}).unflatten(), "[json.exception.type_error.315] values in object must be primitive", json::type_error&);
#endif

        // error for conflicting values
        json const j_error = {{"", 42}, {"/foo", 17}};
        CHECK_THROWS_WITH_AS(j_error.unflatten(),
                             "[json.exception.type_error.313] invalid value to unflatten", json::type_error&);

        // explicit roundtrip check
        CHECK(j.flatten().unflatten() == j);

        // roundtrip for primitive values
        json j_null;
        CHECK(j_null.flatten().unflatten() == j_null);
        json j_number = 42;
        CHECK(j_number.flatten().unflatten() == j_number);
        json j_boolean = false;
        CHECK(j_boolean.flatten().unflatten() == j_boolean);
        json j_string = "foo";
        CHECK(j_string.flatten().unflatten() == j_string);

        // roundtrip for empty structured values (will be unflattened to null)
        json const j_array(json::value_t::array);
        CHECK(j_array.flatten().unflatten() == json());
        json const j_object(json::value_t::object);
        CHECK(j_object.flatten().unflatten() == json());
    }

    SECTION("string representation")
    {
        for (const auto* ptr_str :
                {"", "/foo", "/foo/0", "/", "/a~1b", "/c%d", "/e^f", "/g|h", "/i\\j", "/k\"l", "/ ", "/m~0n"
                })
        {
            json::json_pointer const ptr(ptr_str);
            std::stringstream ss;
            ss << ptr;
            CHECK(ptr.to_string() == ptr_str);
            CHECK(std::string(ptr) == ptr_str);
            CHECK(ss.str() == ptr_str);
        }
    }

    SECTION("conversion")
    {
        SECTION("array")
        {
            json j;
            // all numbers -> array
            j["/12"_json_pointer] = 0;
            CHECK(j.is_array());
        }

        SECTION("object")
        {
            json j;
            // contains a number, but is not a number -> object
            j["/a12"_json_pointer] = 0;
            CHECK(j.is_object());
        }
    }

    SECTION("empty, push, pop and parent")
    {
        const json j =
        {
            {"", "Hello"},
            {"pi", 3.141},
            {"happy", true},
            {"name", "Niels"},
            {"nothing", nullptr},
            {
                "answer", {
                    {"everything", 42}
                }
            },
            {"list", {1, 0, 2}},
            {
                "object", {
                    {"currency", "USD"},
                    {"value", 42.99},
                    {"", "empty string"},
                    {"/", "slash"},
                    {"~", "tilde"},
                    {"~1", "tilde1"}
                }
            }
        };

        // empty json_pointer returns the root JSON-object
        auto ptr = ""_json_pointer;
        CHECK(ptr.empty());
        CHECK(j[ptr] == j);

        // simple field access
        ptr.push_back("pi");
        CHECK(!ptr.empty());
        CHECK(j[ptr] == j["pi"]);

        ptr.pop_back();
        CHECK(ptr.empty());
        CHECK(j[ptr] == j);

        // object and children access
        const std::string answer("answer");
        ptr.push_back(answer);
        ptr.push_back("everything");
        CHECK(!ptr.empty());
        CHECK(j[ptr] == j["answer"]["everything"]);

        // check access via const pointer
        const auto cptr = ptr;
        CHECK(cptr.back() == "everything");

        ptr.pop_back();
        ptr.pop_back();
        CHECK(ptr.empty());
        CHECK(j[ptr] == j);

        // push key which has to be encoded
        ptr.push_back("object");
        ptr.push_back("/");
        CHECK(j[ptr] == j["object"]["/"]);
        CHECK(ptr.to_string() == "/object/~1");

        CHECK(j[ptr.parent_pointer()] == j["object"]);
        ptr = ptr.parent_pointer().parent_pointer();
        CHECK(ptr.empty());
        CHECK(j[ptr] == j);
        // parent-pointer of the empty json_pointer is empty
        ptr = ptr.parent_pointer();
        CHECK(ptr.empty());
        CHECK(j[ptr] == j);

        CHECK_THROWS_WITH(ptr.pop_back(),
                          "[json.exception.out_of_range.405] JSON pointer has no parent");
    }

    SECTION("operators")
    {
        const json j =
        {
            {"", "Hello"},
            {"pi", 3.141},
            {"happy", true},
            {"name", "Niels"},
            {"nothing", nullptr},
            {
                "answer", {
                    {"everything", 42}
                }
            },
            {"list", {1, 0, 2}},
            {
                "object", {
                    {"currency", "USD"},
                    {"value", 42.99},
                    {"", "empty string"},
                    {"/", "slash"},
                    {"~", "tilde"},
                    {"~1", "tilde1"}
                }
            }
        };

        // empty json_pointer returns the root JSON-object
        auto ptr = ""_json_pointer;
        CHECK(j[ptr] == j);

        // simple field access
        ptr = ptr / "pi";
        CHECK(j[ptr] == j["pi"]);

        ptr.pop_back();
        CHECK(j[ptr] == j);

        // object and children access
        const std::string answer("answer");
        ptr /= answer;
        ptr = ptr / "everything";
        CHECK(j[ptr] == j["answer"]["everything"]);

        ptr.pop_back();
        ptr.pop_back();
        CHECK(j[ptr] == j);

        CHECK(ptr / ""_json_pointer == ptr);
        CHECK(j["/answer"_json_pointer / "/everything"_json_pointer] == j["answer"]["everything"]);

        // list children access
        CHECK(j["/list"_json_pointer / 1] == j["list"][1]);

        // push key which has to be encoded
        ptr /= "object";
        ptr = ptr / "/";
        CHECK(j[ptr] == j["object"]["/"]);
        CHECK(ptr.to_string() == "/object/~1");
    }

    SECTION("equality comparison")
    {
        const char* ptr_cpstring = "/foo/bar";
        const char ptr_castring[] = "/foo/bar"; // NOLINT(misc-const-correctness,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
        std::string ptr_string{"/foo/bar"};
        auto ptr1 = json::json_pointer(ptr_string);
        auto ptr2 = json::json_pointer(ptr_string);

        // build with C++20 to test rewritten candidates
        // JSON_HAS_CPP_20

        CHECK(ptr1 == ptr2);

        CHECK(ptr1 == "/foo/bar");
        CHECK(ptr1 == ptr_cpstring);
        CHECK(ptr1 == ptr_castring);
        CHECK(ptr1 == ptr_string);

        CHECK("/foo/bar" == ptr1);
        CHECK(ptr_cpstring == ptr1);
        CHECK(ptr_castring == ptr1);
        CHECK(ptr_string == ptr1);

        CHECK_FALSE(ptr1 != ptr2);

        CHECK_FALSE(ptr1 != "/foo/bar");
        CHECK_FALSE(ptr1 != ptr_cpstring);
        CHECK_FALSE(ptr1 != ptr_castring);
        CHECK_FALSE(ptr1 != ptr_string);

        CHECK_FALSE("/foo/bar" != ptr1);
        CHECK_FALSE(ptr_cpstring != ptr1);
        CHECK_FALSE(ptr_castring != ptr1);
        CHECK_FALSE(ptr_string != ptr1);

        SECTION("exceptions")
        {
            CHECK_THROWS_WITH_AS(ptr1 == "foo",
                                 "[json.exception.parse_error.107] parse error at byte 1: JSON pointer must be empty or begin with '/' - was: 'foo'", json::parse_error&);
            CHECK_THROWS_WITH_AS("foo" == ptr1,
                                 "[json.exception.parse_error.107] parse error at byte 1: JSON pointer must be empty or begin with '/' - was: 'foo'", json::parse_error&);
            CHECK_THROWS_WITH_AS(ptr1 == "/~~",
                                 "[json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'", json::parse_error&);
            CHECK_THROWS_WITH_AS("/~~" == ptr1,
                                 "[json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'", json::parse_error&);
        }
    }

    SECTION("less-than comparison")
    {
        auto ptr1 = json::json_pointer("/foo/a");
        auto ptr2 = json::json_pointer("/foo/b");

        CHECK(ptr1 < ptr2);
        CHECK_FALSE(ptr2 < ptr1);

        // build with C++20
        // JSON_HAS_CPP_20
#if JSON_HAS_THREE_WAY_COMPARISON
        CHECK((ptr1 <=> ptr2) == std::strong_ordering::less); // *NOPAD*
        CHECK(ptr2 > ptr1);
#endif
    }

    SECTION("usable as map key")
    {
        auto ptr = json::json_pointer("/foo");
        std::map<json::json_pointer, int> m;

        m[ptr] = 42;

        CHECK(m.find(ptr) != m.end());
    }

    SECTION("backwards compatibility and mixing")
    {
        json j = R"(
        {
            "foo": ["bar", "baz"]
        }
        )"_json;

        using nlohmann::ordered_json;
        using json_ptr_str = nlohmann::json_pointer<std::string>;
        using json_ptr_j = nlohmann::json_pointer<json>;
        using json_ptr_oj = nlohmann::json_pointer<ordered_json>;

        CHECK(std::is_same<json_ptr_str::string_t, json::json_pointer::string_t>::value);
        CHECK(std::is_same<json_ptr_str::string_t, ordered_json::json_pointer::string_t>::value);
        CHECK(std::is_same<json_ptr_str::string_t, json_ptr_j::string_t>::value);
        CHECK(std::is_same<json_ptr_str::string_t, json_ptr_oj::string_t>::value);

        std::string const ptr_string{"/foo/0"};
        json_ptr_str ptr{ptr_string};
        json_ptr_j ptr_j{ptr_string};
        json_ptr_oj ptr_oj{ptr_string};

        CHECK(j.contains(ptr));
        CHECK(j.contains(ptr_j));
        CHECK(j.contains(ptr_oj));

        CHECK(j.at(ptr) == j.at(ptr_j));
        CHECK(j.at(ptr) == j.at(ptr_oj));

        CHECK(j[ptr] == j[ptr_j]);
        CHECK(j[ptr] == j[ptr_oj]);

        CHECK(j.value(ptr, "x") == j.value(ptr_j, "x"));
        CHECK(j.value(ptr, "x") == j.value(ptr_oj, "x"));

        CHECK(ptr == ptr_j);
        CHECK(ptr == ptr_oj);
        CHECK_FALSE(ptr != ptr_j);
        CHECK_FALSE(ptr != ptr_oj);

        SECTION("equality comparison")
        {
            // build with C++20 to test rewritten candidates
            // JSON_HAS_CPP_20

            CHECK(ptr == ptr_j);
            CHECK(ptr == ptr_oj);
            CHECK(ptr_j == ptr);
            CHECK(ptr_j == ptr_oj);
            CHECK(ptr_oj == ptr_j);
            CHECK(ptr_oj == ptr);

            CHECK_FALSE(ptr != ptr_j);
            CHECK_FALSE(ptr != ptr_oj);
            CHECK_FALSE(ptr_j != ptr);
            CHECK_FALSE(ptr_j != ptr_oj);
            CHECK_FALSE(ptr_oj != ptr_j);
            CHECK_FALSE(ptr_oj != ptr);
        }
    }
}
