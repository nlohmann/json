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
using nlohmann::json_view;
using nlohmann::ordered_json_document;
using nlohmann::ordered_json_view;

#include "json_view_test_helpers.hpp"
using json_view_test::generator;
using json_view_test::has_duplicate_keys;

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <map>
#include <random>
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
            for (const member& m : members)
            {
                text += (text.size() > 1 ? ",\"" : "\"") + m.key + "\":" + std::to_string(m.position);
                first.insert({m.key, m.position});
                last[m.key] = m.position;
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
                CHECK(v.count(entry.first) == 1);
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
        constexpr std::size_t slots = 1024; // the table size for 300 members: the next power of two >= 600
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
            const bool lands_in_slot_zero = (nlohmann::detail::view::key_hash(key.data(), key.size()) & (slots - 1)) == 0;
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
        CHECK(without_collisions.memory_usage() >= with_collisions.memory_usage() + (slots * sizeof(std::uint32_t)));
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
