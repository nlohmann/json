//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json_view.hpp>
using nlohmann::json;
using nlohmann::json_document;
using nlohmann::json_editable_document;
using nlohmann::json_editable_view;

#include "json_view_test_helpers.hpp"
#if !defined(JSON_NOEXCEPTION)
    using json_view_test::exception_of_call;
#endif

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

// These tests were split off unit-json_view_edit.cpp, whose object file got too
// large for the MinGW linker (see json_view_test_helpers.hpp).

TEST_CASE("json_view edits: views and values")
{
    SECTION("a value that is no longer part of the document")
    {
        json_editable_document d = json_editable_document::parse("[[[1,2]]]");
        const json_editable_view inner = d.root()[0][0];
        d.set(d.root()[0], json::array({7}));
        d.set(inner, 5);
        CHECK(d.root().dump() == "[[7]]");
        CHECK(inner.get<int>() == 5);
    }

    SECTION("views keep referring to their value")
    {
        json_editable_document d = json_editable_document::parse(R"({"a": [10, 20, 30], "b": {"c": "text"}})");
        const json_editable_view a = d.root()["a"];
        const json_editable_view twenty = a[1];
        const json_editable_view c = d.root()["b"]["c"];
        d.insert(a, 0, 5);
        d.push_back(a, 40);
        CHECK(twenty.get<int>() == 20);
        CHECK(a[2].get<int>() == 20);
        d.erase(a, 2);
        CHECK(twenty.get<int>() == 20); // an erased value keeps its last value
        d.set(c, 7);
        CHECK(c.get<int>() == 7); // a held view sees an assignment
        d.set(d.root()["b"], json::array({1, 2}));
        CHECK(d.root()["b"].dump() == "[1,2]");
        CHECK(d.root().dump() == R"({"a":[5,10,30,40],"b":[1,2]})");
        CHECK(d.root()["a"][0].source_offset() == static_cast<std::size_t>(-1)); // a new value
        CHECK(d.root()["a"][1].source_offset() != static_cast<std::size_t>(-1));
    }

    SECTION("strings stay valid while more edits come")
    {
        json_editable_document d = json_editable_document::parse("[]");
        const auto first = d.push_back(d.root(), std::string(100, 'x')).get_string();
        for (int i = 0; i < 1000; ++i)
        {
            d.push_back(d.root(), std::string(static_cast<std::size_t>(i % 50), 'y'));
        }
        CHECK(std::string(first.data(), first.size()) == std::string(100, 'x'));
        CHECK(d.root().size() == 1001);
    }

    SECTION("numbers")
    {
        json_editable_document d = json_editable_document::parse(R"([1.50, 1E2, 3])");
        d.set(d.root(), 2, 0.1);
        d.push_back(d.root(), std::numeric_limits<double>::quiet_NaN());
        d.push_back(d.root(), -std::numeric_limits<double>::infinity());
        d.push_back(d.root(), (std::numeric_limits<std::uint64_t>::max)());
        d.push_back(d.root(), (std::numeric_limits<std::int64_t>::min)());
        CHECK(d.root().dump() == "[1.5,100.0,0.1,null,null,18446744073709551615,-9223372036854775808]");
        CHECK(d.root().dump(-1, ' ', false, json_editable_view::number_format::source) == "[1.50,1E2,0.1,null,null,18446744073709551615,-9223372036854775808]");
        CHECK(std::isnan(d.root()[3].get<double>()));
        CHECK(std::isinf(d.root()[4].get<double>()));
        CHECK(d.root()[2].number_token() == "0.1");
        CHECK(d.root()[5].get<std::uint64_t>() == 18446744073709551615u);
        CHECK(d.root()[6].number_token() == "-9223372036854775808");
        CHECK(d.root().materialize().dump() == json::parse(R"([1.5, 100.0, 0.1, null, null, 18446744073709551615, -9223372036854775808])").dump());
    }

    SECTION("numbers of other float types")
    {
        // doubles have their own path to the output; other float types are
        // written as basic_json writes them, non-finite values as null
        using json_float = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;
        using document_float = nlohmann::basic_json_document<json_float, true>;
        document_float d = document_float::parse("[1.5]");
        d.push_back(d.root(), std::numeric_limits<float>::quiet_NaN());
        d.push_back(d.root(), -std::numeric_limits<float>::infinity());
        CHECK(d.root().dump() == "[1.5,null,null]");
        CHECK(d.root().dump(2) == json_float::parse("[1.5, null, null]").dump(2));
    }

    SECTION("nulls become containers, and the root can be replaced")
    {
        json_editable_document d = json_editable_document::parse("[null, null]");
        d.set(d.root()[0], "k", 1);
        d.push_back(d.root()[1], true);
        CHECK(d.root().dump() == R"([{"k":1},[true]])");
        d.set(d.root(), "scalar");
        CHECK(d.root().dump() == R"("scalar")");
        d.set(d.root(), json{{"x", {1, 2}}});
        d.set(json::json_pointer("/x/-"), 3);
        d.set(json::json_pointer("/x/3"), 4); // the size of the array appends too
        d.set(json::json_pointer("/y"), false);
        CHECK(d.root().dump() == R"({"x":[1,2,3,4],"y":false})");
        CHECK(d.erase(json::json_pointer("/x/0")) == 1);
        CHECK(d.erase(json::json_pointer("/y")) == 1);
        CHECK(d.erase(json::json_pointer("/nothing")) == 0);
        CHECK(d.root().dump() == R"({"x":[2,3,4]})");
    }

    SECTION("duplicate keys")
    {
        json_editable_document d = json_editable_document::parse(R"({"a": 1, "b": 2, "a": 3})");
        d.set(d.root(), "a", 4); // the first member is assigned, the others dropped
        CHECK(d.root().dump() == R"({"a":4,"b":2})");
        d = json_editable_document::parse(R"({"a": 1, "b": 2, "a": 3})");
        CHECK(d.erase(d.root(), "a") == 2);
        CHECK(d.root().dump() == R"({"b":2})");
    }

    SECTION("values from other documents")
    {
        const json_document source = json_document::parse(R"({"list": [1, "two", {"three": 3.5}], "text": "a\nb"})");
        json_editable_document edited = json_editable_document::parse("[0]");
        edited.set(edited.root(), 0, json{{"inner", {1, 2}}});
        json_editable_document d = json_editable_document::parse("{}");
        d.set(d.root(), "copy", source.root()["list"]);
        d.set(d.root(), "text", source.root()["text"]);
        d.set(d.root(), "edited", edited.root()[0]);
        d.set(d.root(), "self", d.root()["copy"]);
        // (a raw string with a backslash must not be a macro argument: MSVC C2017)
        const std::string expected = R"({"copy":[1,"two",{"three":3.5}],"text":"a\nb","edited":{"inner":[1,2]},"self":[1,"two",{"three":3.5}]})";
        CHECK(d.root().dump() == expected);
        CHECK(d.root()["copy"] == source.root()["list"]);
        CHECK(source.root()["list"] == d.root()["self"]);
        CHECK(d.root() != source.root());
    }

    SECTION("large objects")
    {
        std::string text = "{";
        for (int i = 0; i < 200; ++i)
        {
            text += (i != 0 ? ",\"k" : "\"k") + std::to_string(i) + "\":" + std::to_string(i);
        }
        text += '}';
        json_editable_document d = json_editable_document::parse(text);
        d.set(d.root(), "k7", "seven"); // assigned in place: the index stays in use
        CHECK(d.root()["k7"].get_string() == "seven");
        d.set(d.root(), "new", 1); // appended: the members move, the lookup is linear
        CHECK(d.root()["new"].get<int>() == 1);
        CHECK(d.root()["k199"].get<int>() == 199);
        d.erase(d.root(), "k0");
        CHECK(!d.root().contains("k0"));
        CHECK(d.root().size() == 200);
    }

    SECTION("reuse and memory")
    {
        json_editable_document d = json_editable_document::parse("[1, 2, 3]");
        const std::size_t before = d.memory_usage();
        for (int i = 0; i < 100; ++i)
        {
            d.push_back(d.root(), "some text");
        }
        CHECK(d.memory_usage() > before);
        const json_editable_view first = d.root()[0];
        d.shrink_to_fit(); // (with edits, the index stays in place)
        CHECK(first.get<int>() == 1);
        d.read(std::string("[true]"));
        CHECK(d.root().dump() == "[true]");
        d.push_back(d.root(), false);
        CHECK(d.root().dump() == "[true,false]");
    }
}

TEST_CASE("json_view edits: deeply nested values")
{
    // copying a value into a document must not recurse per nesting level
    const std::size_t depth = 100000;
    const std::string brackets = std::string(depth, '[') + std::string(depth, ']');
    std::string braces;
    for (std::size_t i = 0; i < depth; ++i)
    {
        braces += "{\"a\":";
    }
    braces += '1';
    braces += std::string(depth, '}');

    SECTION("a view of a read-only document")
    {
        const json_document source = json_document::parse(brackets);
        json_editable_document d = json_editable_document::parse("[]");
        d.push_back(d.root(), source.root());
        CHECK(d.root().dump() == "[" + brackets + "]");
    }

    SECTION("a view of an editable document")
    {
        const json_editable_document source = json_editable_document::parse(braces);
        json_editable_document d = json_editable_document::parse("{}");
        d.set(d.root(), "deep", source.root());
        CHECK(d.root().dump() == "{\"deep\":" + braces + "}");
    }

    SECTION("a view of an edited document (values behind links)")
    {
        const json_document source = json_document::parse(brackets);
        json_editable_document edited = json_editable_document::parse("[[]]");
        edited.push_back(edited.root()[0], source.root());
        edited.push_back(edited.root(), source.root());
        json_editable_document d = json_editable_document::parse("null");
        d.set(d.root(), edited.root());
        CHECK(d.root().dump() == "[[" + brackets + "]," + brackets + "]");
    }

    SECTION("a basic_json value")
    {
        json deep = json::array();
        json* inner = &deep;
        for (std::size_t i = 1; i < depth; ++i)
        {
            inner->push_back(json::array());
            inner = &inner->back();
        }
        json_editable_document d = json_editable_document::parse("[]");
        d.push_back(d.root(), deep);
        CHECK(d.root().dump() == "[" + brackets + "]");
    }

    SECTION("a basic_json value with objects")
    {
        json deep = 1;
        for (std::size_t i = 0; i < depth; ++i)
        {
            json outer = json::object();
            outer["a"] = std::move(deep);
            deep = std::move(outer);
        }
        json_editable_document d = json_editable_document::parse("{}");
        d.set(d.root(), "deep", deep);
        CHECK(d.root().dump() == "{\"deep\":" + braces + "}");
    }
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("json_view edits: pointers below a null value")
{
    // a null value on the way becomes what basic_json makes of it: an array
    // for "-" and for digits, an object otherwise
    struct test_case
    {
        const char* document;
        const char* pointer;
    };
    const std::array<test_case, 16> cases =
    {
        {
            {R"({"a":null})", "/a/0"},
            {R"({"a":null})", "/a/-"},
            {R"({"a":null})", "/a/3"},
            {R"({"a":null})", "/a/x"},
            {R"({"a":null})", "/a/+1"},
            {R"({"a":null})", "/a/01"},
            {R"({"a":null})", "/a/"},
            {R"({"a":{"b":null}})", "/a/b/1"},
            {R"({"a":{"b":null}})", "/a/b/-"},
            {R"({"a":[null]})", "/a/0/0"},
            {R"({"a":[null,null]})", "/a/1/k"},
            {R"([null])", "/0"},
            {"null", "/0"},
            {"null", "/-"},
            {"null", "/k"},
            {"null", ""},
        }
    };
    for (const test_case& c : cases)
    {
        CAPTURE(c.document)
        CAPTURE(c.pointer)
        json expected = json::parse(c.document);
        const std::string error = exception_of_call([&]
        {
            expected[json::json_pointer(c.pointer)] = 1;
        });
        json_editable_document d = json_editable_document::parse(c.document);
        if (error.empty())
        {
            d.set(json::json_pointer(c.pointer), 1);
            CHECK(d.root().dump() == expected.dump());
            CHECK(d.root().materialize() == expected);
        }
        else
        {
            // the same error, and the document is not changed
            CHECK(exception_of_call([&] { d.set(json::json_pointer(c.pointer), 1); }) == error);
            CHECK(d.root().dump() == json::parse(c.document).dump());
        }
    }
}

TEST_CASE("json_view edits: strings of other documents are checked")
{
    // A document borrows the text it was parsed from, and sees later changes
    // of the text: a way to get ill-formed UTF-8 into a view. Copying it into
    // an editable document is an error, as for any other string.
    std::string text = R"({"key":"abc","list":["abc"]})";
    const json_document source = json_document::parse(text);
    const auto message_of = [](const std::string & bad)
    {
        return exception_of_call([&]
        {
            const std::string dumped = json(bad).dump();
            static_cast<void>(dumped);
        });
    };
    json_editable_document d = json_editable_document::parse("[1]");
    d.push_back(d.root(), source.root());
    CHECK(d.root().dump() == R"([1,{"key":"abc","list":["abc"]}])");

    text[text.find("abc") + 1] = '\xC3'; // "a\xC3c"
    text[text.rfind("abc") + 1] = '\xC3';
    const std::string bad_value = message_of(std::string("a\xC3" "c"));
    CHECK(!bad_value.empty());
    CHECK(exception_of_call([&] { d.push_back(d.root(), source.root()["key"]); }) == bad_value);
    CHECK(exception_of_call([&] { d.set(d.root()[0], source.root()["list"][0]); }) == bad_value);
    CHECK(exception_of_call([&] { d.set(d.root(), 0, source.root()["list"]); }) == bad_value);
    CHECK(exception_of_call([&] { d.set(d.root(), 0, source.root()); }) == bad_value);

    text[text.find("key") + 1] = '\xC3'; // a key is checked as well
    const std::string bad_key = message_of(std::string("k\xC3" "y"));
    CHECK(exception_of_call([&] { d.set(d.root(), 0, source.root()); }) == bad_key);
    CHECK(exception_of_call([&] { d.push_back(d.root(), source.root()); }) == bad_key);

    // nothing of the failed edits is visible
    CHECK(d.root().dump() == R"([1,{"key":"abc","list":["abc"]}])");
}
#endif
