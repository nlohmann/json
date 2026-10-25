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

// These tests were split off unit-json_view.cpp, whose object file got too large
// for the MinGW linker (see json_view_test_helpers.hpp). Like that file, this one
// is also built with C++17, as it mentions JSON_HAS_CPP_17.

TEST_CASE("json_view dump")
{
    SECTION("the output of ordered_json::dump()")
    {
        generator g;
        for (int i = 0; i < 2000; ++i)
        {
            std::string text;
            g.value(text, 0);
            const ordered_json_document d = ordered_json_document::parse(text);
            if (has_duplicate_keys(d.root()))
            {
                continue;
            }
            CAPTURE(text)
            const ordered_json j = ordered_json::parse(text);
            for (const int indent :
                    {
                        -1, 0, 2
                    })
            {
                for (const bool ensure_ascii :
                        {
                            false, true
                        })
                {
                    CHECK(d.root().dump(indent, i % 2 == 0 ? ' ' : '\t', ensure_ascii) == j.dump(indent, i % 2 == 0 ? ' ' : '\t', ensure_ascii));
                }
            }
            // also of each element
            for (const ordered_json_view e : d.root())
            {
                CHECK(e.dump() == e.materialize().dump());
            }
        }
    }

    SECTION("strings")
    {
        const std::string text = R"(["plain", "\u0000\u0001\u001f\u007f\u0080é€￿😀", "\"\\\/\b\f\n\r\t", "aéあ😀b", "long text beyond the eight bytes of a word \n with an escape in the middle"])";
        const ordered_json_document d = ordered_json_document::parse(text);
        const ordered_json j = ordered_json::parse(text);
        CHECK(d.root().dump() == j.dump());
        CHECK(d.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
        CHECK(d.root().dump(4, ' ', true) == j.dump(4, ' ', true));
        const std::string key_text = R"({"é\n": {"\"": [], "": {}}})";
        const ordered_json_document keys = ordered_json_document::parse(key_text);
        const ordered_json key_json = ordered_json::parse(key_text);
        CHECK(keys.root().dump(2, ' ', true) == key_json.dump(2, ' ', true));
    }

    SECTION("numbers")
    {
        const std::string text = "[1.50, 1E2, -0, -0.0, 123456789012345678901234567890, 18446744073709551615, -9223372036854775808, 0.1, 1e-7, 5e-324]";
        const json_document d = json_document::parse(text);
        CHECK(d.root().dump() == json::parse(text).dump());
        CHECK(d.root().dump() == "[1.5,100.0,0,-0.0,1.2345678901234568e+29,18446744073709551615,-9223372036854775808,0.1,1e-07,5e-324]");
        CHECK(d.root().dump(-1, ' ', false, json_view::number_format::source) == "[1.50,1E2,-0,-0.0,123456789012345678901234567890,18446744073709551615,-9223372036854775808,0.1,1e-7,5e-324]");
        // also indented, and with ensure_ascii
        CHECK(d.root().dump(0, ' ', false, json_view::number_format::source) == "[\n1.50,\n1E2,\n-0,\n-0.0,\n123456789012345678901234567890,\n18446744073709551615,\n-9223372036854775808,\n0.1,\n1e-7,\n5e-324\n]");
        CHECK(d.root().dump(-1, ' ', true, json_view::number_format::source) == "[1.50,1E2,-0,-0.0,123456789012345678901234567890,18446744073709551615,-9223372036854775808,0.1,1e-7,5e-324]");

        // float tokens of up to 17 significant digits in every spelling: those
        // of at most 15 digits are written from their digits, the others
        // through the conversion; both as dump() writes them
        {
            std::mt19937_64 tokens(1170); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
            // a number below n; the remainder is a std::uint64_t, which is
            // std::size_t on some platforms and wider on others
            const auto draw = [&tokens](std::size_t n)
            {
                const std::uint64_t r = tokens() % n;
                return static_cast<std::size_t>(r);
            };
            std::string many_tokens = "[";
            for (int i = 0; i < 20000; ++i)
            {
                const std::size_t length = 1 + draw(17);
                std::string digits(1, static_cast<char>('1' + draw(9)));
                for (std::size_t k = 1; k < length; ++k)
                {
                    digits += static_cast<char>('0' + draw(10));
                }
                digits += std::string(draw(4), '0'); // trailing zeros
                std::string token = draw(3) == 0 ? "-" : "";
                const std::size_t point = draw(digits.size() + 1);
                if (point == 0)
                {
                    token += "0." + std::string(draw(5), '0') + digits;
                }
                else
                {
                    token += digits.substr(0, point) + (point < digits.size() ? "." + digits.substr(point) : "");
                }
                // an exponent that keeps the value between about 1e-320 and 1e300
                const int exponent = static_cast<int>(draw(600)) - 300 - static_cast<int>(point);
                if (draw(4) != 0)
                {
                    token += (draw(2) == 0 ? "e" : "E") + std::string(exponent >= 0 && draw(2) == 0 ? "+" : "") + std::to_string(exponent);
                }
                else if (point == digits.size())
                {
                    token += ".0"; // (a float, not an integer)
                }
                many_tokens += (i != 0 ? "," : "") + token;
            }
            many_tokens += ']';
            const json_document many_doc = json_document::parse(many_tokens);
            CHECK(many_doc.root().dump() == json::parse(many_tokens).dump());
        }

        // tokens of 16 and 17 digits without an exponent (like GeoJSON
        // coordinates), which dump() converts in batches: doubles exactly
        // halfway between two candidates for the shortest digits, random
        // digits, and digits near a shorter decimal (...99999997,
        // ...00000003), whose rounding carries; in pairs and among other
        // values, so that the batches are interrupted; the last token near the
        // end of the text
        {
            std::mt19937_64 tokens(5627); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
            const auto draw = [&tokens](std::size_t n)
            {
                const std::uint64_t r = tokens() % n;
                return static_cast<std::size_t>(r);
            };
            std::string coordinates = "[754570942.33984373,257769445.56835938,858106901.94921875,97944964.876953125,"
                                      "[0.5,1e-7],[1.5,-0.0,2.5],[1E2,12.5,0.1,3.25,4.5,5.75,6.125,7.0,8.5],[],[1.5],[1,2.5],[2.5,\"x\"],[[1.5],2.5],";
            for (int i = 0; i < 20000; ++i)
            {
                const std::size_t length = 16 + draw(2);
                std::string digits(1, static_cast<char>('1' + draw(9)));
                const std::size_t kept = draw(3) == 0 ? length : 2 + draw(length - 3);
                for (std::size_t k = 1; k < kept; ++k)
                {
                    digits += static_cast<char>('0' + draw(10));
                }
                digits += std::string(length - kept, draw(2) == 0 ? '9' : '0');
                digits.back() = static_cast<char>('0' + draw(10));
                const std::size_t point = 1 + draw(9);
                const std::string token = (draw(2) == 0 ? "-" : "") + digits.substr(0, point) + "." + digits.substr(point);
                coordinates += (i != 0 ? "," : "") + (draw(8) == 0 ? "{\"x\":" + token + ",\"s\":\"a\"}" : "[" + token + "," + token + "]");
            }
            coordinates += ",-65.613616999999977]";
            const json_document parsed = json_document::parse(coordinates);
            const ordered_json j = ordered_json::parse(coordinates);
            CHECK(parsed.root().dump() == j.dump());
            CHECK(parsed.root().dump(1) == j.dump(1));
            CHECK(parsed.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
            CHECK(parsed.root().back().get<double>() == j.back().get<double>());
            CHECK(parsed.root().back().dump() == "-65.61361699999998");
            std::size_t i = 0;
            for (const json_view v : parsed.root())
            {
                const ordered_json& e = j[i++];
                CHECK(v.dump() == e.dump());
                if (v.is_array() && v.size() != 0 && v[0].is_number())
                {
                    CHECK(v[0].get<double>() == e[0].get<double>());
                }
            }

            // an editable document: edits move some arrays, so that the walk
            // leaves the order of the parsed nodes
            ordered_json_editable_document editable = ordered_json_editable_document::parse(coordinates);
            ordered_json expected = j;
            for (std::size_t k = 0; k < 20000; k += 97)
            {
                if (expected[k].is_array())
                {
                    editable.push_back(editable.root()[k], ordered_json(1.5));
                    expected[k].push_back(1.5);
                }
            }
            CHECK(editable.root().dump() == expected.dump());
        }

        // random doubles, written as parse() and dump() would
        std::mt19937_64 rng(1170); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
        std::string many = "[";
        for (int i = 0; i < 5000; ++i)
        {
            const std::uint64_t bits = rng();
            double x = 0;
            std::memcpy(&x, &bits, sizeof(x));
            if (std::isfinite(x))
            {
                many += (many.size() > 1 ? "," : "") + json(x).dump();
            }
        }
        many += ']';
        const json_document many_document = json_document::parse(many);
        CHECK(many_document.root().dump() == json::parse(many).dump());

        using json_float = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;
        const nlohmann::basic_json_document<json_float> float_document = nlohmann::basic_json_document<json_float>::parse("[0.1, 1.5e10, 3.4028235e38]");
        CHECK(float_document.root().dump() == json_float::parse("[0.1, 1.5e10, 3.4028235e38]").dump());
    }

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

TEST_CASE("json_view comparison")
{
    SECTION("equality of the values parse() produces")
    {
        generator g;
        std::vector<std::string> texts;
        for (int i = 0; i < 600; ++i)
        {
            std::string text;
            g.value(text, 0);
            texts.push_back(text);
            // the same value written differently: sorted keys, canonical numbers
            texts.push_back(json::parse(text).dump(1));
        }
        for (std::size_t i = 0; i + 2 < texts.size(); ++i)
        {
            for (std::size_t k = i; k < i + 3; ++k)
            {
                CAPTURE(texts[i])
                CAPTURE(texts[k])
                const json_document a = json_document::parse(texts[i]);
                const json_document b = json_document::parse(texts[k]);
                const json ja = json::parse(texts[i]);
                const json jb = json::parse(texts[k]);
                CHECK((a.root() == b.root()) == (ja == jb));
                CHECK((a.root() != b.root()) == (ja != jb));
                CHECK((a.root() == jb) == (ja == jb));
                CHECK((jb == a.root()) == (ja == jb));
                CHECK((a.root() != jb) == (ja != jb));
                CHECK((jb != a.root()) == (ja != jb));

                // ordered_json compares members in order
                const ordered_json_document oa = ordered_json_document::parse(texts[i]);
                const ordered_json_document ob = ordered_json_document::parse(texts[k]);
                const ordered_json oja = ordered_json::parse(texts[i]);
                const ordered_json ojb = ordered_json::parse(texts[k]);
                CHECK((oa.root() == ob.root()) == (oja == ojb));
                CHECK((oa.root() == ojb) == (oja == ojb));
            }
        }
    }

    SECTION("numbers, duplicate keys, member order")
    {
        const auto same = [](const char* x, const char* y)
        {
            const json_document dx = json_document::parse(x);
            const json_document dy = json_document::parse(y);
            return dx.root() == dy.root();
        };
        CHECK(same("1", "1.0"));
        CHECK(same("[1, -1, 2.5]", "[1.0, -1.0, 25e-1]"));
        CHECK(!same("1", "1.5"));
        CHECK(same("18446744073709551615", "18446744073709551615"));
        CHECK(same(R"({"a": 1, "a": 2})", R"({"a": 2})"));
        CHECK(!same(R"({"a": 1, "a": 2})", R"({"a": 1})"));
        CHECK(same(R"({"a": 1, "b": 2})", R"({"b": 2, "a": 1})"));
        CHECK(!same(R"({"a": 1})", R"({"a": 1, "b": 2})"));
        CHECK(!same("[1, 2]", "[2, 1]"));
        CHECK(!same("\"a\"", "\"b\""));
        CHECK(same("\"\\u00e9\"", "\"\xc3\xa9\""));
        CHECK(!same("null", "false"));
        CHECK(!same("[]", "{}"));
        const ordered_json_document dup = ordered_json_document::parse(R"({"a": 1, "b": 2, "a": 3})");
        const ordered_json_document last = ordered_json_document::parse(R"({"a": 3, "b": 2})");
        CHECK(dup.root() == last.root());
        // (== compares as parse() resolves duplicates, a lookup finds the first)
        CHECK(dup.root()["a"].materialize() == 1);
        CHECK(dup.root()["a"] != last.root()["a"]);
        const ordered_json_document ab = ordered_json_document::parse(R"({"a": 1, "b": 2})");
        const ordered_json_document ba = ordered_json_document::parse(R"({"b": 2, "a": 1})");
        CHECK(ab.root() != ba.root());

        // discarded values compare as basic_json's do
        const json discarded(json::value_t::discarded);
        CHECK((json_view() == json_view()) == (discarded == discarded)); // NOLINT(readability-container-size-empty): operator== is tested
        CHECK((json_view() == discarded) == (discarded == discarded)); // NOLINT(readability-container-size-empty)
        const json_document null_document = json_document::parse("null");
        CHECK(!(json_view() == null_document.root())); // NOLINT(readability-container-size-empty)
        CHECK(!(null_document.root() == discarded));
    }

    SECTION("deep nesting")
    {
        const std::string deep = std::string(100000, '[') + std::string(100000, ']');
        const json_document a = json_document::parse(deep);
        const json_document b = json_document::parse(deep);
        CHECK(a.root() == b.root());
        CHECK(a.root() == json::parse(deep));
        const std::string other = std::string(100000, '[') + "1" + std::string(100000, ']');
        const json_document c = json_document::parse(other);
        CHECK(a.root() != c.root());
    }
}

TEST_CASE("json_view large objects")
{
    // objects with 128 members or more are looked up with a hash index
    for (const std::size_t members :
            {
                127u, 128u, 129u, 10000u
            })
    {
        CAPTURE(members)
        std::string text = "{";
        for (std::size_t i = 0; i < members; ++i)
        {
            text += (i != 0 ? ",\"" : "\"") + std::string(i % 23, 'k') + std::to_string(i) + (i % 7 == 0 ? "\\n" : "") + "\":" + std::to_string(i);
        }
        text += R"(,"":"empty key","k1":"a duplicate of an earlier key"})";
        const json_document d = json_document::parse(text);
        const json_view v = d.root();
        const json j = json::parse(text);
        for (std::size_t i = 0; i < members; ++i)
        {
            const std::string key = std::string(i % 23, 'k') + std::to_string(i) + (i % 7 == 0 ? "\n" : "");
            CHECK(v[key].get<std::size_t>() == i);
            CHECK(v.contains(key));
            CHECK(v.find(key).key() == key);
            CHECK(v.at(key).get<std::size_t>() == i);
            CHECK(!v.contains(key + "x"));
        }
        CHECK(v[""].get_string() == "empty key");
        CHECK(v["k1"].get<int>() == 1); // the first of duplicate keys, as for small objects
        CHECK(!v.contains("missing"));
        CHECK_THROWS_WITH_AS(v.at("missing"), "[json.exception.out_of_range.403] key 'missing' not found", json::out_of_range&);
        CHECK(v == j);
        CHECK(v.materialize() == j);
    }

    SECTION("duplicate keys: the first member wins, with and without a table")
    {
        // an object of `total` members: the keys "k0".."k<n-1>" in order, then
        // three keys repeated twice more (one copy in the middle, one at the
        // end), and two keys repeated once; the value of a member is its
        // position, so that the first member of a key can be told apart
        struct member
        {
            std::string key;
            std::size_t position;
        };
        const auto make_members = [](std::size_t total)
        {
            std::vector<std::string> keys;
            for (std::size_t i = 0; i + 8 < total; ++i)
            {
                keys.push_back("k" + std::to_string(i));
            }
            const std::size_t n = keys.size();
            const std::array<std::size_t, 3> triple = {{3, 17, n - 1}};
            const std::array<std::size_t, 2> twice = {{5, n / 2}};
            std::vector<std::string> ordered = keys;
            for (const std::size_t i : triple)
            {
                ordered.insert(ordered.begin() + static_cast<std::ptrdiff_t>(ordered.size() / 2), keys[i]);
            }
            for (const std::size_t i : twice)
            {
                ordered.insert(ordered.begin() + static_cast<std::ptrdiff_t>(ordered.size() / 3), keys[i]);
            }
            for (const std::size_t i : triple)
            {
                ordered.push_back(keys[i]);
            }
            std::vector<member> result;
            result.reserve(ordered.size());
            for (std::size_t i = 0; i < ordered.size(); ++i)
            {
                result.push_back({ordered[i], i});
            }
            return result;
        };

        // 100 and 127 members: no table; 128 members and more: a table
        for (const std::size_t total :
                {
                    100u, 127u, 128u, 200u, 5000u
                })
        {
            CAPTURE(total)
            const std::vector<member> members = make_members(total);
            REQUIRE(members.size() >= total);
            REQUIRE(members.size() >= 100);
            std::string text = "{";
            std::map<std::string, std::size_t> first;
            std::map<std::string, std::size_t> last;
            std::map<std::string, std::size_t> occurrences;
            for (const member& m : members)
            {
                text += (text.size() > 1 ? ",\"" : "\"") + m.key + "\":" + std::to_string(m.position);
                first.insert({m.key, m.position});
                last[m.key] = m.position;
                ++occurrences[m.key];
            }
            text += '}';
            REQUIRE(first.size() < members.size());

            const json_document d = json_document::parse(text);
            const json_view v = d.root();
            const json j = json::parse(text);
            CHECK(v.size() == members.size()); // every occurrence is visited
            const json m = v.materialize();
            for (const auto& entry : first)
            {
                CAPTURE(entry.first)
                const std::size_t expected = entry.second;
                CHECK(v[entry.first].get<std::size_t>() == expected);
                CHECK(v.at(entry.first).get<std::size_t>() == expected);
                CHECK(v.find(entry.first).value().get<std::size_t>() == expected);
                CHECK(v.value(entry.first, std::size_t{0}) == expected);
                CHECK(v.contains(entry.first));
                CHECK(v.count(entry.first) == occurrences[entry.first]);
                const std::string pointer = "/" + entry.first;
                CHECK(v[json::json_pointer(pointer)].get<std::size_t>() == expected);
                CHECK(v.at(json::json_pointer(pointer)).get<std::size_t>() == expected);
                CHECK(v.value(json::json_pointer(pointer), std::size_t{0}) == expected);
                CHECK(v.contains(json::json_pointer(pointer)));
                // materialize() and parse() keep the last value instead
                CHECK(j[entry.first].get<std::size_t>() == last.at(entry.first));
                CHECK(m[entry.first].get<std::size_t>() == last.at(entry.first));
            }
            CHECK(!v.contains("k"));
            CHECK(v["missing"].is_discarded());
            CHECK(v.materialize() == j);
            CHECK(v == j);
        }
    }

    SECTION("colliding keys")
    {
        // the hash is not seeded, so keys that all land in one place must not
        // make the table build quadratic: such an object gets no table and is
        // searched linearly
        constexpr std::size_t members = 300;
        constexpr std::size_t table_size = 1024; // the table size for 300 members: the next power of two >= 600
        std::vector<std::string> colliding;
        std::vector<std::string> spread;
        for (std::uint64_t counter = 0; colliding.size() < members || spread.size() < members; ++counter)
        {
            std::string key(8, 'a');
            std::uint64_t x = counter;
            for (std::size_t i = 0; i < 8; ++i, x /= 26)
            {
                key[i] = static_cast<char>('a' + (x % 26));
            }
            const bool lands_in_slot_zero = (nlohmann::detail::view::key_hash(key.data(), key.size()) & (table_size - 1)) == 0;
            if (lands_in_slot_zero && colliding.size() < members)
            {
                colliding.push_back(key);
            }
            else if (!lands_in_slot_zero && spread.size() < members)
            {
                spread.push_back(key);
            }
        }

        const auto make_text = [](const std::vector<std::string>& keys)
        {
            std::string text = "{";
            for (std::size_t i = 0; i < keys.size(); ++i)
            {
                text += (i != 0 ? ",\"" : "\"") + keys[i] + "\":" + std::to_string(i % 10);
            }
            return text + "}";
        };
        const std::string colliding_text = make_text(colliding);
        const std::string spread_text = make_text(spread);

        json_document with_collisions = json_document::parse(colliding_text);
        json_document without_collisions = json_document::parse(spread_text);
        for (const auto* pair :
                {
                    &colliding, &spread
                })
        {
            const json_view v = (pair == &colliding ? with_collisions : without_collisions).root();
            for (std::size_t i = 0; i < members; ++i)
            {
                CAPTURE(i)
                CHECK(v[(*pair)[i]].get<std::size_t>() == i % 10);
                CHECK(v.at((*pair)[i]).get<std::size_t>() == i % 10);
                CHECK(v.find((*pair)[i]).key() == (*pair)[i]);
                CHECK(!v.contains((*pair)[i] + "x"));
            }
            CHECK(!v.contains("missing"));
        }
        CHECK(with_collisions.root() == json::parse(colliding_text));

        // only the object with the spread keys got a table (both texts have the
        // same length, so the tables are the only difference)
        with_collisions.shrink_to_fit();
        without_collisions.shrink_to_fit();
        CHECK(without_collisions.memory_usage() >= with_collisions.memory_usage() + (table_size * sizeof(std::uint32_t)));
    }

    SECTION("keys that differ in their last bytes are spread over the table")
    {
        // The hash must spread the usual families of keys (numbered names, hex
        // strings, dates, short names): a key farther than index_max_displacement
        // from its home slot would leave the object without a table. The keys
        // are placed with linear probing, as the table does.
        const auto max_displacement = [](const std::vector<std::string>& keys)
        {
            std::size_t slots = 16;
            while (slots < 2 * keys.size())
            {
                slots *= 2;
            }
            std::vector<bool> used(slots, false);
            std::size_t farthest = 0;
            for (const std::string& key : keys)
            {
                std::size_t i = nlohmann::detail::conditional_static_cast<std::size_t>(nlohmann::detail::view::key_hash(key.data(), key.size())) & (slots - 1);
                std::size_t distance = 0;
                while (used[i])
                {
                    i = (i + 1) & (slots - 1);
                    ++distance;
                }
                used[i] = true;
                farthest = (std::max)(farthest, distance);
            }
            return farthest;
        };
        // the keys of a printf-like pattern with one %d, %0Nd or %0Nx, formatted with a stream
        // (a format string that is not a literal is a Flawfinder error)
        const auto numbered = [](const char* format, int count, int step)
        {
            const std::string pattern(format);
            const std::size_t percent = pattern.find('%');
            std::size_t conversion = percent + 1;
            std::size_t width = 0;
            while (pattern[conversion] >= '0' && pattern[conversion] <= '9')
            {
                width = (width * 10) + static_cast<std::size_t>(pattern[conversion] - '0');
                ++conversion;
            }
            const bool hex = pattern[conversion] == 'x';
            std::vector<std::string> keys;
            for (int i = 0; i < count; ++i)
            {
                std::ostringstream key;
                key << pattern.substr(0, percent) << std::setfill('0') << std::setw(static_cast<int>(width))
                    << (hex ? std::hex : std::dec) << (i * step) << pattern.substr(conversion + 1);
                keys.push_back(key.str());
            }
            return keys;
        };
        for (const char* format :
                {"key%d", "%d", "item_%04d", "a%05d", "%03dxyz", "id%d", "user_%d", "%d_suffix", "0x%04x", "A%07d", "12345678%d", "1234567%d", "123456789%d",
                 "configuration_parameter_value_%04d_extra", "2026-01-%02dT00:00:00Z"
                })
        {
            CAPTURE(format)
            CHECK(max_displacement(numbered(format, std::string(format).find("%02d") != std::string::npos ? 60 : 1000, 1)) < nlohmann::detail::view::index_max_displacement); // NOLINT(abseil-string-find-str-contains)
            CHECK(max_displacement(numbered(format, 600, 7)) < nlohmann::detail::view::index_max_displacement);
        }
        std::mt19937_64 rng(7); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
        for (const std::size_t length :
                {
                    std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{5}, std::size_t{7}, std::size_t{8}, std::size_t{9}, std::size_t{12}, std::size_t{16}, std::size_t{17}, std::size_t{33}
                })
        {
            CAPTURE(length)
            std::set<std::string> distinct;
            // (there are 26 and 676 keys of one and two letters)
            std::size_t wanted = 700;
            if (length == 1)
            {
                wanted = 26;
            }
            else if (length == 2)
            {
                wanted = 500;
            }
            while (distinct.size() < wanted)
            {
                std::string key(length, 'a');
                for (char& c : key)
                {
                    c = static_cast<char>('a' + (rng() % 26));
                }
                distinct.insert(key);
            }
            CHECK(max_displacement(std::vector<std::string>(distinct.begin(), distinct.end())) < nlohmann::detail::view::index_max_displacement);
        }
    }

    SECTION("keys of every length that differ in one byte")
    {
        // In a large object, a key is found by comparing its bytes with those of the member the
        // table points to: up to 16 bytes as two overlapping words, longer ones with memcmp.
        // Keys of every length from 0 to 40, and keys that differ from them in one byte.
        std::mt19937_64 rng(2026); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
        std::vector<std::string> keys;
        std::set<std::string> distinct;
        for (std::size_t length = 0; length <= 40; ++length)
        {
            for (int copy = 0; copy < 5; ++copy)
            {
                std::string key(length, 'a');
                for (char& c : key)
                {
                    c = static_cast<char>('a' + (rng() % 26));
                }
                if (distinct.insert(key).second)
                {
                    keys.push_back(key);
                }
            }
        }
        std::string text = "{";
        for (std::size_t i = 0; i < keys.size(); ++i)
        {
            text += (i != 0 ? ",\"" : "\"") + keys[i] + "\":" + std::to_string(i);
        }
        text += "}";
        REQUIRE(keys.size() >= 128); // (a table is built for 128 members)
        const json_document d = json_document::parse(text);
        const json_view v = d.root();
        for (std::size_t i = 0; i < keys.size(); ++i)
        {
            CAPTURE(keys[i])
            CHECK(v[keys[i]].get<std::size_t>() == i);
            CHECK(v.at(keys[i]).get<std::size_t>() == i);
            CHECK(v.contains(keys[i]));
            for (std::size_t at = 0; at < keys[i].size(); ++at)
            {
                std::string other = keys[i];
                other[at] = other[at] == 'z' ? 'y' : 'z';
                CAPTURE(other)
                CHECK(v.contains(other) == (distinct.count(other) != 0));
            }
            CHECK(v.contains(keys[i] + "a") == (distinct.count(keys[i] + "a") != 0));
            if (!keys[i].empty())
            {
                CHECK(v.contains(keys[i].substr(1)) == (distinct.count(keys[i].substr(1)) != 0));
            }
        }
    }

    SECTION("shrink_to_fit releases the tables' spare capacity")
    {
        const auto make_text = [](int objects, int members)
        {
            std::string text = "[";
            for (int object = 0; object < objects; ++object)
            {
                text += object != 0 ? ",{" : "{";
                for (int i = 0, n = members + object; i < n; ++i)
                {
                    text += (i != 0 ? ",\"" : "\"") + std::to_string(i) + "\":" + std::to_string(i);
                }
                text += '}';
            }
            return text + "]";
        };
        const std::string small_text = make_text(5, 150);
        const std::string big_text = make_text(40, 400);

        // reading a big text, and then a small one, leaves the spare capacity
        // of the big one: shrink_to_fit() brings the document to the size of
        // one parsed from the small text alone
        json_document d = json_document::parse(big_text);
        const std::size_t big = d.memory_usage();
        d.read(small_text);
        CHECK(d.memory_usage() >= big);
        d.shrink_to_fit();
        json_document fresh = json_document::parse(small_text);
        fresh.shrink_to_fit();
        CHECK(d.memory_usage() == fresh.memory_usage());
        CHECK(d.memory_usage() < big / 2);
        CHECK(d.root() == json::parse(small_text));
        for (int object = 0; object < 5; ++object)
        {
            const json_view v = d.root()[static_cast<std::size_t>(object)];
            for (int i = 0, n = 150 + object; i < n; ++i)
            {
                CHECK(v[std::to_string(i)].get<int>() == i);
            }
        }
    }

    SECTION("nested, reused, and in arrays")
    {
        std::string inner = "{";
        for (int i = 0; i < 300; ++i)
        {
            inner += (i != 0 ? ",\"m" : "\"m") + std::to_string(i) + "\":" + std::to_string(i);
        }
        inner += '}';
        const std::string text = "[" + inner + ",{\"x\":" + inner + "}," + inner + "]";
        json_document d = json_document::parse(text);
        CHECK(d.root()[0]["m299"].get<int>() == 299);
        CHECK(d.root()[1]["x"]["m150"].get<int>() == 150);
        CHECK(d.root()[2]["m0"].get<int>() == 0);
        const std::size_t with_index = d.memory_usage();
        d.read(std::string("{\"small\": 1}"));
        CHECK(d.root()["small"].get<int>() == 1);
        d.read(text);
        CHECK(d.root()[2]["m7"].get<int>() == 7);
        CHECK(d.memory_usage() >= with_index / 2);
    }
}
