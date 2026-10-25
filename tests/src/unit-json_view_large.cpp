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
