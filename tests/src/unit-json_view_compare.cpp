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

#include "json_view_test_helpers.hpp"
using json_view_test::generator;

#include <array>
#include <cstddef>
#include <string>
#include <vector>

// These tests were split off unit-json_view_dump.cpp, whose object file got too
// large for the MinGW assembler ("file too big"). Like that file, this one is
// also built with C++17, as it mentions JSON_HAS_CPP_17.

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

    SECTION("objects whose first keys differ or repeat")
    {
        const std::array<const char*, 17> texts =
        {
            {
                R"({"a":1,"b":2})", R"({"a":1,"c":2})", R"({"b":1,"a":2})", R"({"a":1,"a":2,"b":3})", R"({"a":2,"b":3})",
                R"({"a":1,"b":1,"a":2})", R"({"a":2,"b":1})", R"({"a":1,"a":2})", R"({"b":1})", R"({"a":1,"b":2,"c":3,"d":4,"e":5})",
                R"({"a":1,"b":2,"c":3,"d":4,"f":5})", R"({"a":1,"b":2,"c":3,"a":4,"e":5})", R"({"a":4,"b":2,"c":3,"e":5})",
                R"({"\u0061":1,"b":2})", R"({})", R"([{"a":1,"b":2}])", R"([{"a":1,"c":2}])"
            }
        };
        for (const char* const x : texts)
        {
            for (const char* const y : texts)
            {
                CAPTURE(x)
                CAPTURE(y)
                const ordered_json_document dx = ordered_json_document::parse(x);
                const ordered_json_document dy = ordered_json_document::parse(y);
                const ordered_json_editable_document ex = ordered_json_editable_document::parse(x);
                const ordered_json jx = ordered_json::parse(x);
                const ordered_json jy = ordered_json::parse(y);
                CHECK((dx.root() == dy.root()) == (jx == jy));
                CHECK((dx.root() == jy) == (jx == jy));
                CHECK((ex.root() == dy.root()) == (jx == jy));
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

    SECTION("values that are the same text, or the same value written differently, at any depth")
    {
        // nested arrays and objects around depths where the walk over equal text gives up
        for (const int depth :
                {
                    1, 5, 47, 48, 49, 50, 60, 300
                })
        {
            CAPTURE(depth)
            std::string head;
            std::string tail;
            for (int i = 0; i < depth; ++i)
            {
                head += i % 2 == 0 ? R"({"k":[1,"s",{"x":true},)" : R"([null,2.5,{"y":)";
                tail.insert(0, i % 2 == 0 ? "]}" : "}]");
            }
            // the same text, one number changed, and one number written differently
            const auto with_number = [&](const char* number)
            {
                std::string result = head;
                result += number;
                result += tail;
                return result;
            };
            const std::string text = with_number("7");
            const std::string changed = with_number("8");
            const std::string spelled = with_number("7.0");
            const json_document a = json_document::parse(text);
            const json_document b = json_document::parse(text);
            const json_document c = json_document::parse(changed);
            const json_document d = json_document::parse(spelled);
            CHECK(a.root() == b.root());
            CHECK(a.root() != c.root());
            CHECK(c.root() != a.root());
            CHECK(a.root() == d.root());
            CHECK(d.root() == a.root());
            CHECK(a.root() == json::parse(text));
            CHECK(a.root() != json::parse(changed));
            CHECK(json::parse(spelled) == a.root());
            const nlohmann::json_editable_document e = nlohmann::json_editable_document::parse(text);
            CHECK(a.root() == e.root());
            CHECK(e.root() == a.root());
            CHECK(c.root() != e.root());
            CHECK(e.root() == e.root());
            const ordered_json_document oa = ordered_json_document::parse(text);
            const ordered_json_document oc = ordered_json_document::parse(changed);
            CHECK(oa.root() != oc.root());
            CHECK(oa.root() == ordered_json::parse(text));
            CHECK(oc.root() != ordered_json::parse(text));
        }

        // not the same text, but the same value
        const auto same = [](const char* x, const char* y)
        {
            const json_document dx = json_document::parse(x);
            const json_document dy = json_document::parse(y);
            const bool equal = dx.root() == dy.root();
            CHECK(equal == (json::parse(x) == json::parse(y)));
            CHECK(equal == (dx.root() == json::parse(y)));
            return equal;
        };
        CHECK(same(R"({"a":1,"a":2})", R"({"a":3,"a":2})"));
        CHECK(same(R"({"a":1,"b":[1,{"c":2,"c":3}]})", R"({"b":[1,{"c":9,"c":3}],"a":1})"));
        CHECK(!same(R"({"a":1,"a":2})", R"({"a":2,"a":3})"));
        CHECK(same("[1.0,-0,0,1e2]", "[1.00,0,-0,100.0]"));
        CHECK(same(R"(["\u00e9","\n"])", "[\"\xc3\xa9\",\"\\n\"]"));
        CHECK(!same(R"({"a":[1,2,{"b":null}]})", R"({"a":[1,2,{"b":false}]})"));
        CHECK(!same(R"({"a":[1,2,{"b":null}]})", R"({"a":[1,2,{"c":null}]})"));
        CHECK(!same(R"({"a":[1,2,{"b":null}]})", R"({"a":[1,2,{"b":null,"c":1}]})"));

        // edited documents: moved sequences, links, and values of new nodes
        nlohmann::json_editable_document edited = nlohmann::json_editable_document::parse(R"({"a":[1,2,3],"b":{"c":"d"},"e":0.5})");
        const json_document plain = json_document::parse(R"({"a":[1,2,3,4],"b":{"c":"x","y":null},"e":0.5,"z":[]})");
        edited.push_back(edited.root()["a"], 4);
        edited.set(edited.root()["b"], "c", "x");
        edited.set(edited.root()["b"], "y", nullptr);
        edited.set(edited.root(), "z", json::array());
        CHECK(edited.root() == plain.root());
        CHECK(plain.root() == edited.root());
        edited.erase(edited.root()["a"], 0);
        CHECK(edited.root() != plain.root());
        CHECK(edited.root()["a"] == json::parse("[2,3,4]"));
        const json_document tail = json_document::parse("[2,3,4]");
        CHECK(edited.root()["a"] == tail.root());
    }

    SECTION("large documents, with a difference at any place")
    {
        const auto make = [](std::size_t count, std::size_t changed, bool swap_members)
        {
            std::string text = R"({"b":1,"list":[)";
            for (std::size_t i = 0; i < count; ++i)
            {
                text += (i != 0 ? "," : "");
                const std::string id = std::to_string(i == changed ? i + 1 : i);
                if (swap_members && i % 3 == 0)
                {
                    text += R"({"v":[1.5,"s",{"k":)";
                    text += id;
                    text += R"(}],"id":)";
                    text += id;
                    text += "}";
                }
                else
                {
                    text += R"({"id":)";
                    text += id;
                    text += R"(,"v":[1.5,"s",{"k":)";
                    text += id;
                    text += "}]}";
                }
            }
            return text + R"(],"a":{"y":2,"x":3}})";
        };
        const std::size_t count = 3000;
        for (const std::size_t changed :
                {
                    count, std::size_t{0}, std::size_t{1}, count / 2, count - 1
                })
        {
            for (const bool swap :
                    {
                        false, true
                    })
            {
                CAPTURE(changed)
                CAPTURE(swap)
                const std::string text_a = make(count, count, false);
                const std::string text_b = make(count, changed, swap);
                const json_document a = json_document::parse(text_a);
                const json_document b = json_document::parse(text_b);
                const bool equal = changed == count;
                CHECK((a.root() == b.root()) == equal);
                CHECK((b.root() == a.root()) == equal);
                CHECK((a.root() == json::parse(text_b)) == equal);
                CHECK((json::parse(text_b) == a.root()) == equal);
                CHECK((a.root()["list"] == b.root()["list"]) == equal);
                const ordered_json_document oa = ordered_json_document::parse(text_a);
                const ordered_json_document ob = ordered_json_document::parse(text_b);
                CHECK((oa.root() == ob.root()) == (equal && !swap));
                CHECK((oa.root() == ordered_json::parse(text_b)) == (equal && !swap));
            }
        }
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
