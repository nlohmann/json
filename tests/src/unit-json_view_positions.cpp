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
constexpr std::size_t npos = std::string::npos;

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
            "[1, 2.5, true, false, null, \"s\", \"\\u0000\", -0]",
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
            "[\"\\n\" /* \" */ , ]",
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
            CHECK_THROWS_AS(json_document::load(image), json::parse_error&);
            // without the check, the position is out of bounds and ignored
            const json_document d = json_document::load(image, json_document::image_check::none);
            CHECK(range(d.root()[0].materialize()) == "none");
        }
#endif
    }
#endif
}
