//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_DIAGNOSTICS 1
#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json.hpp>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;

TEST_CASE("Better diagnostics with positions")
{
    SECTION("invalid type")
    {
        const std::string json_invalid_string = R"(
        {
            "address": {
                "street": "Fake Street",
                "housenumber": "1"
            }
        }
        )";
        json j = json::parse(json_invalid_string);
        CHECK_THROWS_WITH_AS(j.at("address").at("housenumber").get<int>(),
                             "[json.exception.type_error.302] (/address/housenumber) (bytes 108-111) type must be number, but is string", json::type_error);
    }

    SECTION("invalid type without positions")
    {
        const json j = "foo";
        CHECK_THROWS_WITH_AS(j.get<int>(),
                             "[json.exception.type_error.302] type must be number, but is string", json::type_error);
    }

    SECTION("positions of strings containing escape sequences")
    {
        // escape sequences make the token longer than the string it parses to,
        // so the positions must not be derived from the parsed value's length
        const auto check = [](const std::string & text, const std::string & token)
        {
            CAPTURE(text)
            CAPTURE(token)
            const json j = json::parse(text);
            const json& v = j.at("a");
            CHECK(text.substr(v.start_pos(), v.end_pos() - v.start_pos()) == token);
        };

        check(R"({"a":"plain"})", R"("plain")");
        check(R"({"a":"tab\there"})", R"("tab\there")");
        check(R"({"a":"\n\n\n\n\n\n"})", R"("\n\n\n\n\n\n")");
        check(R"({"a":"\""})", R"("\"")");
        check(R"({"a":"\\"})", R"("\\")");
        check(R"({"a":"é"})", R"("é")");
        check(R"({"a":"🌞"})", R"("🌞")");
        check("{\"a\":\"\xc3\xa9\"}", "\"\xc3\xa9\"");  // multi-byte UTF-8, no escapes

        // a string at the root, where an escape would otherwise push the
        // reported start position past the opening quote
        const std::string root = R"("a\tb")";
        const json j = json::parse(root);
        CHECK(j.start_pos() == 0);
        CHECK(j.end_pos() == root.size());
    }

    SECTION("JSON patch add to primitive parent (#4292)")
    {
        // the JSON Patch "add" target /foo/bar/baz has a string parent
        // (/foo/bar); the position of that parent is reported in the message
        const json doc = json::parse(R"({"foo":{"bar":"a string"}})");
        const json patch = json::parse(R"([{"op":"add","path":"/foo/bar/baz","value":1}])");
        CHECK_THROWS_WITH_AS(doc.patch(patch),
                             "[json.exception.out_of_range.411] (/foo/bar) (bytes 14-24) cannot add value: the JSON Patch 'add' target's parent is of type string, but must be an object or array", json::out_of_range);
    }

    SECTION("copy constructor keeps start/end positions")
    {
        const std::string text = R"({"a":1,"b":[2]})";
        json a = json::parse(text);
        const auto child_start = a.at("a").start_pos();
        const auto child_end = a.at("a").end_pos();
        const json b = a;
        // mutate the original so the copy is an independent snapshot
        a["a"] = 42;
        CHECK(b.at("a").start_pos() == child_start);
        CHECK(b.at("a").end_pos() == child_end);
        CHECK(text.substr(b.at("a").start_pos(), b.at("a").end_pos() - b.at("a").start_pos()) == "1");
        CHECK(a.at("a").start_pos() == std::string::npos);
        CHECK(a.at("a").end_pos() == std::string::npos);
    }

    SECTION("move constructor resets the source positions to npos")
    {
        const std::string text = R"({"a":1})";
        json a = json::parse(text);
        const auto start = a.start_pos();
        const auto end = a.end_pos();
        const json b = std::move(a);
        CHECK(b.start_pos() == start);
        CHECK(b.end_pos() == end);
        // The move constructor is specified to reset the source to npos.
        // NOLINTBEGIN(clang-analyzer-cplusplus.Move)
        CHECK(a.start_pos() == std::string::npos);
        CHECK(a.end_pos() == std::string::npos);
        // NOLINTEND(clang-analyzer-cplusplus.Move)
    }

    SECTION("swap exchanges positions")
    {
        json a = json::parse(R"({"a":1})");
        json b = json::parse(R"({"bb":22})");
        const auto a_start = a.start_pos();
        const auto a_end = a.end_pos();
        const auto b_start = b.start_pos();
        const auto b_end = b.end_pos();
        using std::swap;
        swap(a, b);
        CHECK(a.start_pos() == b_start);
        CHECK(a.end_pos() == b_end);
        CHECK(b.start_pos() == a_start);
        CHECK(b.end_pos() == a_end);

        a.swap(b);
        CHECK(a.start_pos() == a_start);
        CHECK(a.end_pos() == a_end);
        CHECK(b.start_pos() == b_start);
        CHECK(b.end_pos() == b_end);
    }

    SECTION("type-specific swap leaves positions on the basic_json object")
    {
        json j = json::parse("[1,2]");
        const auto start = j.start_pos();
        const auto end = j.end_pos();
        json::array_t other = {3, 4};
        j.swap(other);
        CHECK(j == json::array({3, 4}));
        CHECK(j.start_pos() == start);
        CHECK(j.end_pos() == end);
    }

    SECTION("mutation does not update parent or sibling positions")
    {
        const std::string text = R"({"a":1,"b":[2,3]})";
        json j = json::parse(text);
        const auto root_start = j.start_pos();
        const auto root_end = j.end_pos();
        const auto b_start = j.at("b").start_pos();
        const auto b_end = j.at("b").end_pos();
        const auto b0_start = j.at("b").at(0).start_pos();
        const auto b0_end = j.at("b").at(0).end_pos();
        const auto b1_start = j.at("b").at(1).start_pos();
        const auto b1_end = j.at("b").at(1).end_pos();

        j["a"] = 42;
        CHECK(j.at("a").start_pos() == std::string::npos);
        CHECK(j.at("a").end_pos() == std::string::npos);
        CHECK(j.start_pos() == root_start);
        CHECK(j.end_pos() == root_end);
        CHECK(j.at("b").start_pos() == b_start);
        CHECK(j.at("b").end_pos() == b_end);

        j["c"] = 5;
        CHECK(j.at("c").start_pos() == std::string::npos);
        CHECK(j.start_pos() == root_start);
        CHECK(j.end_pos() == root_end);

        j["b"].push_back(4);
        CHECK(j.at("b").back().start_pos() == std::string::npos);
        CHECK(j.at("b").back().end_pos() == std::string::npos);
        CHECK(j.at("b").start_pos() == b_start);
        CHECK(j.at("b").end_pos() == b_end);
        CHECK(j.at("b").at(0).start_pos() == b0_start);
        CHECK(j.at("b").at(0).end_pos() == b0_end);

        j["b"].erase(0);
        CHECK(j.at("b").at(0).start_pos() == b1_start);
        CHECK(j.at("b").at(0).end_pos() == b1_end);
        CHECK(j.at("b").start_pos() == b_start);
        CHECK(j.at("b").end_pos() == b_end);
        CHECK(j.start_pos() == root_start);
        CHECK(j.end_pos() == root_end);
    }

    SECTION("input adapters record the same UTF-8 byte offsets")
    {
        const std::string text = R"({"a":1})";
        const json expected = json::parse(text);
        const auto check_same = [&](const json & actual)
        {
            CHECK(actual == expected);
            CHECK(actual.start_pos() == expected.start_pos());
            CHECK(actual.end_pos() == expected.end_pos());
            CHECK(actual.at("a").start_pos() == expected.at("a").start_pos());
            CHECK(actual.at("a").end_pos() == expected.at("a").end_pos());
        };

        {
            std::istringstream ss(text);
            check_same(json::parse(ss));
        }

        check_same(json::parse(text.begin(), text.end()));

        {
            const std::vector<std::uint8_t> v(text.begin(), text.end());
            check_same(json::parse(v));
            check_same(json::parse(v.begin(), v.end()));
        }

        {
            const char* path = "nlohmann_json_diag_pos_5420.json";
            {
                std::ofstream out(path, std::ios::binary | std::ios::trunc);
                out << text;
                REQUIRE(out.good());
            }
            {
                std::ifstream in(path, std::ios::binary);
                REQUIRE(in.good());
                check_same(json::parse(in));
            }
            static_cast<void>(::remove(path));
        }
    }

    SECTION("BOM-prefixed input counts the three BOM bytes")
    {
        const std::string text = "\xEF\xBB\xBF{\"a\":1}";
        const json j = json::parse(text);
        CHECK(j.start_pos() == 3);
        CHECK(j.end_pos() == text.size());
        CHECK(text.substr(j.start_pos(), j.end_pos() - j.start_pos()) == "{\"a\":1}");

        std::istringstream ss(text);
        const json from_stream = json::parse(ss);
        CHECK(from_stream.start_pos() == 3);
        CHECK(from_stream.end_pos() == text.size());
    }

    SECTION("wide-string positions index the transcoded UTF-8 stream")
    {
        const std::string ascii = R"({"a":1})";
        const json from_utf8 = json::parse(ascii);

        const std::u16string u16_ascii(ascii.begin(), ascii.end());
        const json from_u16_ascii = json::parse(u16_ascii);
        CHECK(from_u16_ascii.start_pos() == from_utf8.start_pos());
        CHECK(from_u16_ascii.end_pos() == from_utf8.end_pos());

        const std::u32string u32_ascii(ascii.begin(), ascii.end());
        const json from_u32_ascii = json::parse(u32_ascii);
        CHECK(from_u32_ascii.start_pos() == from_utf8.start_pos());
        CHECK(from_u32_ascii.end_pos() == from_utf8.end_pos());

#ifndef __INTEL_COMPILER
        // "ä" is one code unit in UTF-16/32 and two UTF-8 bytes, so the
        // reported offsets cannot index the original wide string.
        const std::string utf8 = "[\"ä\"]";
        const json from_utf8_umlaut = json::parse(utf8);
        const std::u16string u16 = u"[\"ä\"]";
        const json from_u16 = json::parse(u16);
        CHECK(from_u16.start_pos() == 0);
        CHECK(from_u16.end_pos() == utf8.size());
        CHECK(from_u16.end_pos() == from_utf8_umlaut.end_pos());
        CHECK(u16.size() != from_u16.end_pos());
        CHECK(from_u16.at(0).end_pos() - from_u16.at(0).start_pos() == std::string("\"ä\"").size());

        const std::u32string u32 = U"[\"ä\"]";
        const json from_u32 = json::parse(u32);
        CHECK(from_u32.end_pos() == utf8.size());
        CHECK(u32.size() != from_u32.end_pos());
#endif
    }

    SECTION("binary formats leave positions as npos")
    {
        const json src = {{"a", 1}};
        const auto check_npos = [](const json & j)
        {
            CHECK(j.start_pos() == std::string::npos);
            CHECK(j.end_pos() == std::string::npos);
            CHECK(j.at("a").start_pos() == std::string::npos);
            CHECK(j.at("a").end_pos() == std::string::npos);
        };

        const json cbor = json::from_cbor(json::to_cbor(src));
        CHECK(cbor == src);
        check_npos(cbor);

        const json msgpack = json::from_msgpack(json::to_msgpack(src));
        CHECK(msgpack == src);
        check_npos(msgpack);

        const json ubjson = json::from_ubjson(json::to_ubjson(src));
        CHECK(ubjson == src);
        check_npos(ubjson);

        const json bjdata = json::from_bjdata(json::to_bjdata(src));
        CHECK(bjdata == src);
        check_npos(bjdata);

        const json bson = json::from_bson(json::to_bson(src));
        CHECK(bson == src);
        check_npos(bson);
    }

    SECTION("user-constructed SAX DOM parser yields npos")
    {
        const std::string text = R"({"a":1})";
        json j_sax;
        nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type> sdp(j_sax);
        CHECK(json::sax_parse(text, &sdp));
        CHECK(j_sax == json::parse(text));
        CHECK(j_sax.start_pos() == std::string::npos);
        CHECK(j_sax.end_pos() == std::string::npos);
        CHECK(j_sax.at("a").start_pos() == std::string::npos);
        CHECK(j_sax.at("a").end_pos() == std::string::npos);
    }

    SECTION("trailing commas are included in end_pos when ignored")
    {
        const std::string array_with_comma = "[1, 2, ]";
        const json ja = json::parse(array_with_comma, nullptr, true, false, true);
        CHECK(ja == json::array({1, 2}));
        CHECK(ja.start_pos() == 0);
        CHECK(ja.end_pos() == array_with_comma.size());
        CHECK(array_with_comma.substr(ja.at(0).start_pos(), ja.at(0).end_pos() - ja.at(0).start_pos()) == "1");
        CHECK(array_with_comma.substr(ja.at(1).start_pos(), ja.at(1).end_pos() - ja.at(1).start_pos()) == "2");

        const std::string object_with_comma = "{\"a\": 1, }";
        const json jo = json::parse(object_with_comma, nullptr, true, false, true);
        CHECK(jo == json({{"a", 1}}));
        CHECK(jo.start_pos() == 0);
        CHECK(jo.end_pos() == object_with_comma.size());
        CHECK(object_with_comma.substr(jo.at("a").start_pos(), jo.at("a").end_pos() - jo.at("a").start_pos()) == "1");
    }
}
