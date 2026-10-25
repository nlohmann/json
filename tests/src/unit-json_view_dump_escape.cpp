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
using nlohmann::ordered_json;
using nlohmann::json_document;
using nlohmann::ordered_json_editable_document;
using nlohmann::json_view;
using nlohmann::ordered_json_document;
using nlohmann::ordered_json_view;

#include "json_view_test_helpers.hpp"
using json_view_test::generator;
using json_view_test::has_duplicate_keys;

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// These tests were split off unit-json_view_dump.cpp, whose object file got too large for the MinGW
// linker (see json_view_test_helpers.hpp). Like that file, this one is also built
// with C++17, as it mentions JSON_HAS_CPP_17.

TEST_CASE("json_view dump: escaping, nesting, and output buffers")
{
    SECTION("members in document order, all of them")
    {
        const json_document d = json_document::parse(R"({"b": 1, "a": 2, "b": 3})");
        CHECK(d.root().dump() == R"({"b":1,"a":2,"b":3})");
        CHECK(d.root().dump(1) == "{\n \"b\": 1,\n \"a\": 2,\n \"b\": 3\n}");
        // dump() writes all members, though the lookup finds the first
        CHECK(d.root()["b"].dump() == "1");
    }

    SECTION("deep nesting")
    {
        const std::string deep = std::string(100000, '[') + std::string(100000, ']');
        const json_document deep_document = json_document::parse(deep);
        CHECK(deep_document.root().dump() == deep);
    }

    SECTION("ensure_ascii: a character that needs an escape at each position of a string")
    {
        // string lengths around the width of the vector steps, in a string value, a key, and a value near the end of the text
        for (const char* const special :
                {
                    "\xC3\xA9", "\xE4\xB8\xAD", "\xF0\x9F\x98\x80", "\x7F", "\\n", "\\u0001", "\\\"", "\\\\"
                })
        {
            for (std::size_t length = 0; length <= 40; ++length)
            {
                for (std::size_t position = 0; position <= length; ++position)
                {
                    std::string content(length, 'a');
                    content.insert(position, special);
                    const std::array<std::string, 3> texts =
                    {
                        {
                            "\"" + content + "\"",
                            "[\"" + content + "\"]",
                            "{\"" + content + "\":1}",
                        }
                    };
                    for (const std::string& text : texts)
                    {
                        CAPTURE(text)
                        const ordered_json_document d = ordered_json_document::parse(text);
                        const ordered_json j = ordered_json::parse(text);
                        CHECK(d.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
                        CHECK(d.root().dump(2, ' ', true) == j.dump(2, ' ', true));
                        CHECK(d.root().dump() == j.dump());
                    }
                }
            }
        }
    }

    SECTION("ensure_ascii: every character of the Basic Multilingual Plane and some beyond")
    {
        // (the two- and three-byte sequences, including the ranges that need a check: E0, ED, EF BF BF)
        std::string text = "[";
        std::size_t in_chunk = 0;
        const auto append = [&](std::uint32_t cp)
        {
            if (cp < 0x80)
            {
                if (cp < 0x20 || cp == '"' || cp == '\\')
                {
                    return;
                }
                text += static_cast<char>(cp);
            }
            else if (cp < 0x800)
            {
                text += static_cast<char>(0xC0 | (cp >> 6));
                text += static_cast<char>(0x80 | (cp & 0x3F));
            }
            else if (cp < 0x10000)
            {
                text += static_cast<char>(0xE0 | (cp >> 12));
                text += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                text += static_cast<char>(0x80 | (cp & 0x3F));
            }
            else
            {
                text += static_cast<char>(0xF0 | (cp >> 18));
                text += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                text += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                text += static_cast<char>(0x80 | (cp & 0x3F));
            }
        };
        for (std::uint32_t cp = 0x20; cp < 0x10400; ++cp)
        {
            if (cp >= 0xD800 && cp < 0xE000)
            {
                continue;
            }
            if (in_chunk == 0)
            {
                text += text.size() > 1 ? ",\"" : "\"";
            }
            append(cp);
            if (++in_chunk == 37)
            {
                text += "\"";
                in_chunk = 0;
            }
        }
        text += in_chunk != 0 ? "\"]" : "]";
        const ordered_json_document d = ordered_json_document::parse(text);
        const ordered_json j = ordered_json::parse(text);
        CHECK(d.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
        CHECK(d.root().dump(2, ' ', true) == j.dump(2, ' ', true));
        CHECK(d.root().dump() == j.dump());
        CHECK(d.root().dump(2) == j.dump(2));
    }

    SECTION("deep nesting, indented")
    {
        // indentations of up to and beyond the width of the writer's fixed-size copy
        for (const int depth :
                {
                    1, 5, 20, 70, 300
                })
        {
            std::string text;
            for (int i = 0; i < depth; ++i)
            {
                text += i % 2 == 0 ? "[1," : R"({"k":2,"\u00e9":)";
            }
            text += "[]";
            for (int i = depth - 1; i >= 0; --i)
            {
                text += i % 2 == 0 ? "]" : "}";
            }
            const ordered_json_document d = ordered_json_document::parse(text);
            const ordered_json j = ordered_json::parse(text);
            for (const int indent :
                    {
                        0, 1, 2, 3, 8
                    })
            {
                CHECK(d.root().dump(indent) == j.dump(indent));
                CHECK(d.root().dump(indent, '\t') == j.dump(indent, '\t'));
            }
        }
    }

    SECTION("the output buffer of a small value is small")
    {
        // an escaped key after the value: its node lies in the arena, so the
        // source extent of the value cannot be read from the next node
        const std::string big(100000, 'a');
        const std::string text = R"({"small":1,"list":[1,2,3],"k\n":")" + big + R"("})";
        const json_document d = json_document::parse(text);
        const auto small = d.root()["small"].dump();
        CHECK(small == "1");
        CHECK(small.capacity() < 4096);
        const auto list = d.root()["list"].dump();
        CHECK(list == "[1,2,3]");
        CHECK(list.capacity() < 4096);
        CHECK(d.root()["list"].dump(2).capacity() < 4096);

        // the whole document and the large value are unaffected
        CHECK(d.root().dump() == ordered_json::parse(text).dump());
        CHECK(d.root()["k\n"].dump() == "\"" + big + "\"");
    }

    SECTION("output that outgrows the estimate")
    {
        // ensure_ascii writes six bytes for each two-byte character
        std::string chars;
        for (int i = 0; i < 5000; ++i)
        {
            chars += "\xC3\xA9";
        }
        const json_document d = json_document::parse(R"({"a":")" + chars + R"(","k\n":1})");
        const json expected = json::parse("\"" + chars + "\"");
        CHECK(d.root()["a"].dump(-1, ' ', true) == expected.dump(-1, ' ', true));
        CHECK(d.root()["a"].dump(-1, ' ', true).size() == 2 + (5000 * 6));
    }

    SECTION("ensure_ascii with strings of the source, decoded strings, and edited strings")
    {
        // plain ASCII, non-ASCII, escaped (decoded), and mixed strings, as values and as keys;
        // the second text has a DEL, which ensure_ascii writes as an escape
        for (const char* const del :
                {"", "\x7F"
                })
        {
            const std::string text = std::string("{\"plain\":\"abc\",\"caf\xC3\xA9\":\"\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80\",")
                                     + "\"esc\\n\\\"\":\"a\\tb\\u00e4\\ud83d\\ude00\",\"del\":\"a" + del + "b\",\"\":\"\"," // NOLINT(modernize-raw-string-literal)
                                     + "\"list\":[\"x\",\"\xC3\xBC\",\"\\\\\",\"long ASCII string with more than thirty-two bytes in it\","
                                     + "\"long string with more than thirty-two bytes and one non-ASCII byte \xC3\xB6\"],"
                                     + "\"n\":[1,2.5,-0,true,null]}";
            const ordered_json j = ordered_json::parse(text);
            const ordered_json_document d = ordered_json_document::parse(text);
            CHECK(d.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
            CHECK(d.root().dump(4, ' ', true) == j.dump(4, ' ', true));
            CHECK(d.root().dump() == j.dump());
            CHECK(d.root()["list"].dump(-1, ' ', true) == j["list"].dump(-1, ' ', true));
            CHECK(d.root()["del"].dump(-1, ' ', true) == j["del"].dump(-1, ' ', true));

            // strings that an edit wrote (the source strings that they replace were plain)
            ordered_json_editable_document e = ordered_json_editable_document::parse(text);
            ordered_json k = j;
            e.set(e.root()["plain"], std::string("\xC3\xA4gypten"));
            k["plain"] = "\xC3\xA4gypten";
            e.set(e.root()["list"][0], std::string("ascii after edit"));
            k["list"][0] = "ascii after edit";
            e.set(e.root()["list"][1], std::string("\xC3\xA4"));
            k["list"][1] = "\xC3\xA4";
            e.set(e.root()["del"], std::string("tab\there"));
            k["del"] = "tab\there";
            CHECK(e.root().dump(-1, ' ', true) == k.dump(-1, ' ', true));
            CHECK(e.root().dump(2, ' ', true) == k.dump(2, ' ', true));
            CHECK(e.root().dump() == k.dump());

            // strings that were edited from or to ASCII text
            e.set(e.root()["list"][2], std::string("\xC3\xA4"));
            k["list"][2] = "\xC3\xA4";
            e.set(e.root()["list"][4], std::string("plain again"));
            k["list"][4] = "plain again";
            CHECK(e.root().dump(-1, ' ', true) == k.dump(-1, ' ', true));
        }
    }

    SECTION("ensure_ascii with DEL or a non-ASCII character at every position")
    {
        // the check whether a string of the source has no byte >= 0x7F reads
        // eight bytes at a time and then the rest one by one
        for (std::size_t length = 1; length <= 20; ++length)
        {
            for (std::size_t pos = 0; pos < length; ++pos)
            {
                for (const char* const c :
                        {
                            "\x7F", "\x7E", "\xC3\xA4", "\xC3\xBF" // NOLINT(modernize-raw-string-literal)
                        })
                {
                    const std::string s = std::string(pos, 'a') + c + std::string(length - pos - 1, 'b');
                    std::string text = "[\"";
                    text.append(s).append("\",{\"").append(s).append("\":1}]");
                    const json_document d = json_document::parse(text);
                    const json j = json::parse(text);
                    CHECK(d.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
                    CHECK(d.root().dump(1, ' ', true) == j.dump(1, ' ', true));
                }
            }
        }
    }

    SECTION("streams and discarded views")
    {
        const json_document d = json_document::parse(R"({"a": [1, 2]})");
        std::ostringstream compact;
        compact << d.root();
        CHECK(compact.str() == R"({"a":[1,2]})");
        std::ostringstream pretty;
        pretty << std::setw(2) << std::setfill('.') << d.root() << d.root()["a"];
        CHECK(pretty.str() == "{\n..\"a\": [\n....1,\n....2\n..]\n}[1,2]");
        CHECK(json_view().dump() == json(json::value_t::discarded).dump());
    }
}
