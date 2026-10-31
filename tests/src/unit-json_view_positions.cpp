//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// source positions of materialize() (JSON_DIAGNOSTIC_POSITIONS, #5864)

#include "doctest_compatibility.h"

#ifndef JSON_DIAGNOSTICS
    #define JSON_DIAGNOSTICS 1
#endif
#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json_view.hpp>
using nlohmann::json;
using nlohmann::ordered_json;
using nlohmann::json_document;
using nlohmann::json_editable_document;

#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "json_view_test_helpers.hpp"
#include <test_data.hpp>

namespace
{
// not constexpr: VS 2015 does not accept std::string::npos in a constant expression (C2131)
const std::size_t npos = std::string::npos;

// whether every value of a has the source positions of the value of b at the
// same place (a and b are equal; shallow test documents only)
template<typename BasicJsonType>
bool same_positions(const BasicJsonType& a, const BasicJsonType& b)
{
    if (a.start_pos() != b.start_pos() || a.end_pos() != b.end_pos() || a.type() != b.type() || a.size() != b.size())
    {
        return false;
    }
    if (a.is_object())
    {
        for (auto it = a.begin(); it != a.end(); ++it)
        {
            if (!same_positions(it.value(), b.at(it.key())))
            {
                return false;
            }
        }
    }
    else if (a.is_array())
    {
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (!same_positions(a[i], b[i]))
            {
                return false;
            }
        }
    }
    return true;
}

// the materialized root of text has the positions of parse()
template<typename BasicJsonType>
bool positions_as_parse(const std::string& text, bool comments = false, bool trailing_commas = false)
{
    const auto j = BasicJsonType::parse(text, nullptr, true, comments, trailing_commas);
    const auto d = nlohmann::basic_json_document<BasicJsonType>::parse(text, true, comments, trailing_commas);
    const auto e = nlohmann::basic_json_document<BasicJsonType, nlohmann::view_mode::editable>::parse(text, true, comments, trailing_commas);
    return same_positions(d.root().materialize(), j) && same_positions(e.root().materialize(), j);
}

std::string range(const json& j)
{
    return j.start_pos() == npos && j.end_pos() == npos ? "none" : std::to_string(j.start_pos()) + "-" + std::to_string(j.end_pos());
}

#if !defined(JSON_NOEXCEPTION)
using json_view_test::exception_of_call;

// the exceptions about every value of v are those about the value at the same
// place in j, a value of the whole document from parse() or materialize() (so
// that its parents and positions are set); members whose key repeats are
// skipped (the view finds the first one, j holds the last)
template<typename View>
void check_exceptions(const View& v, const json& j)
{
    CAPTURE(j.dump())
    if (!v.is_number())
    {
        CHECK(exception_of_call([&] { static_cast<void>(v.template get<int>()); }) == exception_of_call([&] { static_cast<void>(j.get<int>()); }));
    }
    if (!v.is_string())
    {
        CHECK(exception_of_call([&] { static_cast<void>(v.template get<std::string>()); }) == exception_of_call([&] { static_cast<void>(j.get<std::string>()); }));
    }
    if (!v.is_array())
    {
        CHECK(exception_of_call([&] { static_cast<void>(v.template get<std::vector<int>>()); }) == exception_of_call([&] { static_cast<void>(j.get<std::vector<int>>()); }));
    }
    CHECK(exception_of_call([&] { static_cast<void>(v.at("missing")); }) == exception_of_call([&] { static_cast<void>(j.at("missing")); }));
    CHECK(exception_of_call([&] { static_cast<void>(v.at(1000)); }) == exception_of_call([&] { static_cast<void>(j.at(1000)); }));
    CHECK(exception_of_call([&] { static_cast<void>(v.at(json::json_pointer("/missing"))); }) == exception_of_call([&] { static_cast<void>(j.at(json::json_pointer("/missing"))); }));
    CHECK(exception_of_call([&] { static_cast<void>(v.at(json::json_pointer("/-"))); }) == exception_of_call([&] { static_cast<void>(j.at(json::json_pointer("/-"))); }));
    CHECK(exception_of_call([&] { static_cast<void>(v.value("k", 0)); }) == exception_of_call([&] { static_cast<void>(j.value("k", 0)); }));
    if (!v.is_object())
    {
        CHECK(exception_of_call([&] { static_cast<void>(v["k"]); }) == exception_of_call([&] { static_cast<void>(j["k"]); }));
        // (without the context of basic_json: view iterators do not know the value they iterate over)
        CHECK(exception_of_call([&] { static_cast<void>(v.begin().key()); }) == "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators");
    }
    if (!v.is_array())
    {
        CHECK(exception_of_call([&] { static_cast<void>(v[0]); }) == exception_of_call([&] { static_cast<void>(j[0]); }));
    }
    if (v.is_null())
    {
        CHECK(exception_of_call([&] { static_cast<void>(v.front()); }) == exception_of_call([&] { static_cast<void>(j.front()); }));
    }
    if (v.is_object())
    {
        for (auto it = v.begin(); it != v.end(); ++it)
        {
            const std::string key(it.key().data(), it.key().size());
            if (v.count(key) == 1)
            {
                check_exceptions(it.value(), j.at(key));
            }
        }
    }
    else if (v.is_array())
    {
        for (std::size_t i = 0; i < v.size(); ++i)
        {
            check_exceptions(v[i], j[i]);
        }
    }
}

// as check_exceptions, for edits that fail (they change neither d nor j)
void check_edit_exceptions(json_editable_document& d, const json_editable_document::view_type& v, json& j)
{
    CAPTURE(j.dump())
    if (!v.is_object() && !v.is_null())
    {
        CHECK(exception_of_call([&] { d.set(v, "k", 1); }) == exception_of_call([&] { j["k"] = 1; }));
        CHECK(exception_of_call([&] { d.erase(v, "k"); }) == exception_of_call([&] { j.erase("k"); }));
    }
    if (!v.is_array() && !v.is_null())
    {
        CHECK(exception_of_call([&] { d.set(v, 0, 1); }) == exception_of_call([&] { j[0] = 1; }));
        CHECK(exception_of_call([&] { d.push_back(v, 1); }) == exception_of_call([&] { j.push_back(1); }));
    }
    if (!v.is_array())
    {
        CHECK(exception_of_call([&] { d.insert(v, 0, 1); }) == exception_of_call([&] { j.insert(j.cbegin(), 1); }));
        CHECK(exception_of_call([&] { d.erase(v, 0); }) == exception_of_call([&] { j.erase(0); }));
    }
    else
    {
        CHECK(exception_of_call([&] { d.erase(v, 1000); }) == exception_of_call([&] { j.erase(1000); }));
    }
    if (v.is_object())
    {
        for (auto it = v.begin(); it != v.end(); ++it)
        {
            const std::string key(it.key().data(), it.key().size());
            if (v.count(key) == 1)
            {
                check_edit_exceptions(d, it.value(), j.at(key));
            }
        }
    }
    else if (v.is_array())
    {
        for (std::size_t i = 0; i < v.size(); ++i)
        {
            check_edit_exceptions(d, v[i], j[i]);
        }
    }
}
#endif
} // namespace

TEST_CASE("json_view materialize() source positions")
{
    SECTION("as parse()")
    {
        const std::vector<std::string> texts =
        {
            "null", "true", "false", "0", "-12", "3.25e-2", "18446744073709551615", "-9223372036854775809", R"("a")",
            R"("\n")", R"("\u00e9")", R"("\ud83d\ude00")", "\"\xf0\x9f\x98\x80\"", R"("a\"b\\")", R"("x\\")",
            "  [ ]  ", "{}", "[[[]]]", R"({"a":{"b":[1,{"c":[]}]}})",
            R"({"\u0041": "v\n", "k": "\"", "\t":[ "\/" ]})",
            R"([1, 2.5, true, false, null, "s", "\u0000", -0])",
            "\n\t[\r\n  1 ,\n  {\n    \"a\" : [ ]\n  }\n]\n",
            "\xef\xbb\xbf[1, {\"a\": \"b\"}]", "\xef\xbb\xbf\"\\n\"",
        };
        for (const auto& text : texts)
        {
            CAPTURE(text)
            CHECK(positions_as_parse<json>(text));
            CHECK(positions_as_parse<ordered_json>(text));
        }
    }

    SECTION("comments and trailing commas")
    {
        const std::vector<std::string> texts =
        {
            "[1 /* ] */]", "[1 // ]\n]", "{\"a\": 1 /* } */ , }", "[1, 2, ]", "[[1,],[2 , /**/ ] , ]",
            "{\"a\": [] // }\n, \"b\": {} /* } ] */ }", "[ /* empty */ ]", "{ // }\n}", "/* a */ [1] // b",
            R"(["\n" /* " */ , ])",
        };
        for (const auto& text : texts)
        {
            CAPTURE(text)
            CHECK(positions_as_parse<json>(text, true, true));
        }
    }

    SECTION("generated documents")
    {
        json_view_test::generator gen;
        for (int i = 0; i < 300; ++i)
        {
            std::string text;
            gen.value(text, 0);
            CAPTURE(text)
            CHECK(positions_as_parse<json>(text));
            CHECK(positions_as_parse<ordered_json>(text));
        }
    }

    SECTION("test data")
    {
        for (const char* name :
                {
                    "/json_testsuite/sample.json", "/nativejson-benchmark/canada.json", "/nativejson-benchmark/citm_catalog.json",
                    "/nativejson-benchmark/twitter.json", "/json_tests/pass1.json"
                })
        {
            CAPTURE(name)
            const std::ifstream f(std::string(TEST_DATA_DIRECTORY) + name, std::ios::binary);
            std::stringstream ss;
            ss << f.rdbuf();
            CHECK(positions_as_parse<json>(ss.str()));
        }
    }

    SECTION("subtrees")
    {
        const std::string text = R"({"a": [1, "\n", {"b": null}], "s": "x\ty", "n": -1.5})";
        const json j = json::parse(text);
        const json_document d = json_document::parse(text);
        CHECK(same_positions(d.root()["a"].materialize(), j["a"]));
        CHECK(same_positions(d.root()["a"][2].materialize(), j["a"][2]));
        CHECK(same_positions(d.root()["a"][1].materialize(), j["a"][1]));
        CHECK(same_positions(d.root()["s"].materialize(), j["s"]));
        CHECK(same_positions(d.root()["n"].materialize(), j["n"]));
        CHECK(range(d.root()["a"][1].materialize()) == "10-14");
        CHECK(range(d.root()["s"].materialize()) == "35-41");
    }

#if !defined(JSON_NOEXCEPTION)
    SECTION("exception messages")
    {
        const std::string text = "{\n  \"address\": {\"street\": \"Fake\\tStreet\", \"housenumber\": \"1\"},\n  \"list\": [1, [true]]\n}";
        const json j = json::parse(text);
        const json_document d = json_document::parse(text);
        const json m = d.root().materialize();
        const std::string expected = json_view_test::exception_of_call([&]
        {
            static_cast<void>(j.at("address").at("housenumber").get<int>());
        });
        CHECK(expected.find("(bytes ") != std::string::npos);
        CHECK(json_view_test::exception_of_call([&]
        {
            static_cast<void>(m.at("address").at("housenumber").get<int>());
        }) == expected);
        CHECK(json_view_test::exception_of_call([&]
        {
            static_cast<void>(m.at("address").at("street").get<int>());
        }) == json_view_test::exception_of_call([&]
        {
            static_cast<void>(j.at("address").at("street").get<int>());
        }));
        CHECK(json_view_test::exception_of_call([&]
        {
            static_cast<void>(m.at("list").at(1).get<int>());
        }) == json_view_test::exception_of_call([&]
        {
            static_cast<void>(j.at("list").at(1).get<int>());
        }));
    }
#endif

    SECTION("edited documents")
    {
        const std::string text = R"({"a": [1, 2], "b": {"c": "\n", "d": true}, "e": [3, [4]], "f": "x"})";
        const json j = json::parse(text);

        SECTION("new scalars have none")
        {
            json_editable_document d = json_editable_document::parse(text);
            d.set(d.root()["f"], 5);
            d.set(d.root()["b"]["d"], "s");
            const json m = d.root().materialize();
            CHECK(range(m["f"]) == "none");
            CHECK(range(m["b"]["d"]) == "none");
            // the object whose last member is new has none; the others keep theirs
            CHECK(range(m) == "none");
            CHECK(range(m["b"]) == "none");
            CHECK(same_positions(m["a"], j["a"]));
            CHECK(same_positions(m["e"], j["e"]));
            CHECK(same_positions(m["b"]["c"], j["b"]["c"]));
        }

        SECTION("containers whose elements change have none")
        {
            json_editable_document d = json_editable_document::parse(text);
            d.push_back(d.root()["a"], 7);
            d.erase(d.root()["e"], 0);
            const json m = d.root().materialize();
            CHECK(range(m["a"]) == "none");
            CHECK(range(m["a"][2]) == "none");
            CHECK(range(m["e"]) == "none");
            // the elements kept keep theirs
            CHECK(range(m["a"][0]) == range(j["a"][0]));
            CHECK(range(m["a"][1]) == range(j["a"][1]));
            CHECK(same_positions(m["e"][0], j["e"][1]));
            CHECK(same_positions(m["b"], j["b"]));
            // the root's elements did not change
            CHECK(range(m) == range(j));
        }

        SECTION("new containers have none")
        {
            json_editable_document d = json_editable_document::parse(text);
            d.set(d.root()["b"], json::parse(R"({"x": [1]})"));
            const json m = d.root().materialize();
            CHECK(range(m["b"]) == "none");
            CHECK(range(m["b"]["x"]) == "none");
            CHECK(range(m["b"]["x"][0]) == "none");
            CHECK(range(m) == range(j));
        }

        SECTION("copies of scalars of the document keep theirs")
        {
            // (a copy of an array or object is a new one; its scalars are the
            // parsed ones)
            json_editable_document d = json_editable_document::parse(text);
            d.set(d.root()["f"], d.root()["e"]);
            d.set(d.root()["a"], d.root()["b"]["c"]);
            const json m = d.root().materialize();
            CHECK(range(m["a"]) == range(j["b"]["c"]));
            CHECK(range(m["f"]) == "none");
            CHECK(range(m["f"][1]) == "none");
            CHECK(range(m["f"][0]) == range(j["e"][0]));
            CHECK(range(m["f"][1][0]) == range(j["e"][1][0]));
        }
    }

#if !(defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    SECTION("images")
    {
        const std::string text = R"({"a\n": ["\u00e9", 1.5, {"b": [true, null]}], "c": "d"})";
        const json j = json::parse(text);

        SECTION("round trip")
        {
            const json_document d = json_document::load(json_document::parse(text).save());
            CHECK(same_positions(d.root().materialize(), j));
        }

        SECTION("edited")
        {
            json_editable_document e = json_editable_document::parse(text);
            e.set(e.root()["c"], 1);
            e.push_back(e.root()[std::string("a") + '\n'], false);
            e.set(e.root()[std::string("a") + '\n'][2]["b"][0], "\"");
            const json_document d = json_document::load(e.save());
            const json m = d.root().materialize();
            CHECK(range(m["c"]) == "none");
            CHECK(range(m) == "none");
            const json& a = m[std::string("a") + '\n'];
            const json& ja = j[std::string("a") + '\n'];
            CHECK(range(a) == "none");
            CHECK(range(a[3]) == "none");
            CHECK(range(a[0]) == range(ja[0]));
            CHECK(range(a[1]) == range(ja[1]));
            CHECK(range(a[2]["b"][0]) == "none");
            CHECK(range(a[2]["b"][1]) == range(ja[2]["b"][1]));
            // the last element of b is still the parsed one
            CHECK(range(a[2]["b"]) == range(ja[2]["b"]));
            CHECK(range(a[2]) == range(ja[2]));
        }

        SECTION("without positions")
        {
            // an image saved without JSON_DIAGNOSTIC_POSITIONS: next is 0 for
            // the strings with escapes
            std::vector<std::uint8_t> image = json_document::parse(text).save();
            std::uint64_t count = 0;
            std::memcpy(&count, image.data() + 8, sizeof(count));
            for (std::size_t i = 0; i < count; ++i)
            {
                nlohmann::detail::view::node n{};
                std::memcpy(&n, image.data() + 64 + (i * sizeof(n)), sizeof(n));
                if (n.kind == nlohmann::detail::view::node_kind::string)
                {
                    n.next = 0;
                }
                std::memcpy(image.data() + 64 + (i * sizeof(n)), &n, sizeof(n));
            }
            const json_document d = json_document::load(image);
            const json m = d.root().materialize();
            CHECK(range(m[std::string("a") + '\n'][0]) == "none");
            CHECK(range(m["c"]) == range(j["c"]));
            CHECK(same_positions(m[std::string("a") + '\n'][2], j[std::string("a") + '\n'][2]));
        }

#if !defined(JSON_NOEXCEPTION)
        SECTION("a decoded string's position must be within the text")
        {
            std::vector<std::uint8_t> image = json_document::parse(R"(["\n"])").save();
            nlohmann::detail::view::node n{};
            std::memcpy(&n, image.data() + 64 + sizeof(n), sizeof(n));
            REQUIRE(n.next == 2);
            n.next = 7;
            std::memcpy(image.data() + 64 + sizeof(n), &n, sizeof(n));
            const auto load_image = [&image]
            {
                // GCC ignores a cast to void for [[nodiscard]]-like results, so keep the document
                const json_document d = json_document::load(image);
                static_cast<void>(d);
            };
            CHECK_THROWS_AS(load_image(), json::parse_error&);
            // without the check, the position is out of bounds and ignored
            const json_document d = json_document::load(image, json_document::image_check::none);
            CHECK(range(d.root()[0].materialize()) == "none");
        }
#endif
    }
#endif
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("json_view exceptions name the path and the bytes of the value")
{
    SECTION("as those of basic_json")
    {
        const std::vector<std::string> texts =
        {
            "null", "true", "42", "\"s\"", "[]", "{}", "[1, [2, [3, []]]]", R"({"a": {"b": [1, {"c": null}]}, "d": "e"})",
            R"({"a/b": {"~": [1]}, "\u0041\n": {"x": "\t"}, "": [{}]})",
            R"([1 /* ] */, {"a": [] // }
, "b": {} } , ])",
            "\n\t[\r\n  1 ,\n  {\n    \"a\" : [ ]\n  }\n]\n",
        };
        for (const auto& text : texts)
        {
            CAPTURE(text)
            const json j = json::parse(text, nullptr, true, true, true);
            const json_document d = json_document::parse(text, true, true, true);
            check_exceptions(d.root(), j);
            json_editable_document e = json_editable_document::parse(text, true, true, true);
            check_exceptions(e.root(), j);
            json m = e.root().materialize();
            check_edit_exceptions(e, e.root(), m);
        }
    }

    SECTION("generated documents")
    {
        json_view_test::generator gen;
        for (int i = 0; i < 100; ++i)
        {
            std::string text;
            gen.value(text, 0);
            CAPTURE(text)
            const json_document d = json_document::parse(text);
            check_exceptions(d.root(), json::parse(text));
        }
    }

    SECTION("edited documents: as those of materialize()")
    {
        const std::string text = R"({"a": [1, 2], "b": {"c": "\n", "d": true}, "e": [3, [4]], "f": "x"})";
        json_editable_document d = json_editable_document::parse(text);
        d.set(d.root()["f"], 5);
        d.push_back(d.root()["a"], json::parse(R"({"n": [null]})"));
        d.erase(d.root()["e"], 0);
        d.set(d.root()["b"], "c2", d.root()["e"]);
        d.insert(d.root()["e"], 0, "new");
        json m = d.root().materialize();
        check_exceptions(d.root(), m);
        check_edit_exceptions(d, d.root(), m);
        // (a value inside a new container: a path, but no bytes)
        std::string expected = "[json.exception.type_error.302] ";
#if JSON_DIAGNOSTICS
        expected += "(/a/2/n/0) ";
#endif
        expected += "type must be number, but is null";
        CHECK(exception_of_call([&] { static_cast<void>(d.root()["a"][2]["n"][0].get<int>()); }) == expected);
    }

    SECTION("deep documents with siblings after every nested container")
    {
        // the search for the path pushes and pops one frame per level (the
        // stack reallocates while it grows, and shrinks again at every
        // sibling): run under a sanitizer, a reference to a popped or moved
        // frame would show here
        std::string text = "7";
        for (int level = 0; level < 40; ++level)
        {
            text = R"([[1, [2]], )" + text + R"(, {"k": [3, {"l": [4]}]}, [5, [6, [7]]]])";
        }
        CAPTURE(text)
        const json j = json::parse(text);
        const json_document d = json_document::parse(text);
        check_exceptions(d.root(), j);
        json_editable_document e = json_editable_document::parse(text);
        e.set(e.root()[0][0], 9);
        check_exceptions(e.root(), e.root().materialize());
    }

    SECTION("examples")
    {
        const std::string text = R"({"people": [{"name": "a", "age": 1}, {"name": "c", "age": "x"}], "o": {"k": 1}})";
        const json_document d = json_document::parse(text);
        std::string expected_age = "[json.exception.type_error.302] ";
#if JSON_DIAGNOSTICS
        expected_age += "(/people/1/age) ";
#endif
        expected_age += "(bytes 58-61) type must be number, but is string";
        CHECK(exception_of_call([&] { static_cast<void>(d.root()["people"][1]["age"].get<int>()); }) == expected_age);

        std::string expected_zz = "[json.exception.out_of_range.403] ";
#if JSON_DIAGNOSTICS
        expected_zz += "(/people/0) ";
#endif
        expected_zz += "(bytes 12-35) key 'zz' not found";
        CHECK(exception_of_call([&] { static_cast<void>(d.root().at(json::json_pointer("/people/0/zz"))); }) == expected_zz);

        // the root has no path, and with JSON_DIAGNOSTICS then no bytes either (as basic_json)
        std::string expected_missing = "[json.exception.out_of_range.403] ";
#if !JSON_DIAGNOSTICS
        expected_missing += "(bytes 0-79) ";
#endif
        expected_missing += "key 'missing' not found";
        CHECK(exception_of_call([&] { static_cast<void>(d.root().at("missing")); }) == expected_missing);
    }

    SECTION("duplicate keys: the value the view finds")
    {
        const json_document d = json_document::parse(R"({"x": "1", "x": "22"})");
        std::string expected = "[json.exception.type_error.302] ";
#if JSON_DIAGNOSTICS
        expected += "(/x) ";
#endif
        expected += "(bytes 6-9) type must be number, but is string";
        CHECK(exception_of_call([&] { static_cast<void>(d.root()["x"].get<int>()); }) == expected);
    }
}
#endif
