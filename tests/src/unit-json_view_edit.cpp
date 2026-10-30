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
using nlohmann::json_editable_document;
using nlohmann::json_editable_view;
using nlohmann::ordered_json_document;
using nlohmann::ordered_json_editable_document;
using nlohmann::ordered_json_editable_view;
using ptr_t = ordered_json::json_pointer;

#include "json_view_test_helpers.hpp"
#if !defined(JSON_NOEXCEPTION)
    using json_view_test::exception_of_call;
#endif

#include <array>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace
{
std::uint32_t rng()
{
    static std::mt19937 generator(5295); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed): reproducible
    // result_type is std::uint_fast32_t, which may be wider than 32 bits
    const std::mt19937::result_type value = generator();
    return static_cast<std::uint32_t>(value);
}

int r(int n)
{
    return static_cast<int>(rng() % static_cast<unsigned>(n));
}

int counter = 0;

std::uint64_t bits(double x)
{
    std::uint64_t b = 0;
    std::memcpy(&b, &x, sizeof(b));
    return b;
}

std::string random_string()
{
    static const std::array<const char*, 15> pieces = {{"a", "Z", " ", "~", "\n", "\"", "\\", "/", "\xc3\xa9", "\xe3\x81\x82", "\xf0\x9f\x98\x80", "\x7f", "\x1f", "0", "key"}};
    std::string s;
    for (int i = r(3) == 0 ? r(30) : r(6); i > 0; --i)
    {
        s += pieces[static_cast<std::size_t>(r(15))];
    }
    return s;
}

ordered_json random_scalar()
{
    switch (r(9))
    {
        case 0:
            return nullptr;
        case 1:
            return r(2) == 0;
        case 2:
            return static_cast<std::int64_t>(rng()) - 2147483648LL;
        case 3:
            return (static_cast<std::uint64_t>(rng()) * 4294967296ULL) + rng();
        case 4:
            return static_cast<double>(static_cast<std::int32_t>(rng())) / (1 + r(1000));
        case 5:
            return r(2) == 0 ? 1e300 * (r(2) == 0 ? 1 : -1) : 5e-324;
        case 6:
            return -0.0;
        default:
            return random_string();
    }
}

ordered_json random_value(int depth)
{
    const int k = depth > 3 ? 4 : r(7);
    if (k == 0)
    {
        ordered_json o = ordered_json::object();
        for (int i = r(5); i > 0; --i)
        {
            o[random_string() + "#" + std::to_string(counter++)] = random_value(depth + 1);
        }
        return o;
    }
    if (k == 1)
    {
        ordered_json a = ordered_json::array();
        for (int i = r(5); i > 0; --i)
        {
            a.push_back(random_value(depth + 1));
        }
        return a;
    }
    return random_scalar();
}

void collect(const ordered_json& j, const ptr_t& p, std::vector<ptr_t>& out)
{
    out.push_back(p);
    if (j.is_object())
    {
        for (const auto& kv : j.items())
        {
            collect(kv.value(), p / kv.key(), out);
        }
    }
    else if (j.is_array())
    {
        for (std::size_t i = 0; i < j.size(); ++i)
        {
            collect(j[i], p / i, out);
        }
    }
}


// the edited view and the ordered_json value read the same through the whole
// read API
void compare(const ordered_json_editable_view& v, const ordered_json& j)
{
    REQUIRE(v.type() == j.type());
    REQUIRE(v.size() == j.size());
    if (j.is_object())
    {
        auto jt = j.begin();
        for (auto it = v.begin(); it != v.end(); ++it, ++jt)
        {
            CHECK(std::string(it.key().data(), it.key().size()) == jt.key());
            CHECK(v[jt.key()].dump() == jt.value().dump());
            CHECK(v.contains(jt.key()));
            compare(*it, jt.value());
        }
    }
    else if (j.is_array())
    {
        for (std::size_t i = 0; i < j.size(); ++i)
        {
            CHECK(v[i].dump() == j[i].dump());
        }
        std::size_t i = 0;
        for (const auto e : v)
        {
            compare(e, j[i++]);
        }
        if (!j.empty())
        {
            CHECK(v.back().dump() == j.back().dump());
        }
    }
    else if (j.is_string())
    {
        CHECK(v.get<std::string>() == j.get<std::string>());
    }
    else if (j.is_number_float())
    {
        CHECK(bits(v.get<double>()) == bits(j.get<double>()));
    }
    else if (j.is_number_integer())
    {
        CHECK(v.get<std::int64_t>() == j.get<std::int64_t>());
        CHECK(v.get<std::uint64_t>() == j.get<std::uint64_t>());
    }
}

// the text of j, in which some objects repeat a key of theirs after their
// members: lookups of the edited document find the first member of a key, so
// j (the first members) is what they must agree with, while parse() would
// keep the last value
std::string text_with_duplicates(const ordered_json& j)
{
    if (j.is_object())
    {
        std::vector<std::string> keys;
        for (const auto& kv : j.items())
        {
            keys.push_back(kv.key());
        }
        const auto repeated = [&keys]()
        {
            return ordered_json(keys[static_cast<std::size_t>(r(static_cast<int>(keys.size())))]).dump() + ":" + random_value(2).dump();
        };
        std::string text = "{";
        bool first = true;
        for (const auto& kv : j.items())
        {
            text += (first ? "" : ",") + ordered_json(kv.key()).dump() + ":" + text_with_duplicates(kv.value());
            first = false;
        }
        for (int i = keys.empty() ? 0 : r(3); i > 0; --i)
        {
            text += "," + repeated();
        }
        return text + "}";
    }
    if (j.is_array())
    {
        std::string text = "[";
        for (std::size_t i = 0; i < j.size(); ++i)
        {
            text += (i != 0 ? "," : "") + text_with_duplicates(j[i]);
        }
        return text + "]";
    }
    return j.dump();
}

// the number of members of an object view with this key, by iteration
std::size_t occurrences(const ordered_json_editable_view& v, const std::string& key)
{
    std::size_t result = 0;
    for (const auto& item : v.items())
    {
        result += std::string(item.key().data(), item.key().size()) == key ? 1u : 0u;
    }
    return result;
}

// every lookup of the edited view finds the first member of its key, which
// the iteration of the view shows
void check_lookups(const ordered_json_editable_view& v)
{
    if (v.is_object())
    {
        std::set<std::string> seen;
        for (const auto item : v.items())
        {
            const std::string key(item.key().data(), item.key().size());
            if (!seen.insert(key).second)
            {
                continue; // (not the first member of the key)
            }
            const ptr_t ptr = ptr_t() / key;
            CAPTURE(key)
            const ordered_json expected = item.value().materialize();
            const ordered_json_editable_view m = v[key];
            REQUIRE(!m.is_discarded());
            CHECK(m.materialize() == expected);
            CHECK(v.at(key).materialize() == expected);
            CHECK(v[ptr].materialize() == expected);
            CHECK(v.at(ptr).materialize() == expected);
            CHECK(v.contains(key));
            CHECK(v.contains(ptr));
            CHECK(v.count(key) == occurrences(v, key));
            const auto it = v.find(key);
            REQUIRE(it != v.end());
            CHECK((*it).materialize() == expected);
            CHECK(v.value(ptr, ordered_json(nullptr)) == expected);
            if (expected.is_string())
            {
                CHECK(v.value(key, std::string("-")) == expected.get<std::string>());
            }
            check_lookups(m);
        }
        CHECK(v["missing#key"].is_discarded());
        CHECK(!v.contains("missing#key"));
        CHECK(v.find("missing#key") == v.end());
    }
    else if (v.is_array())
    {
        for (std::size_t i = 0; i < v.size(); ++i) // NOLINT(modernize-loop-convert): both v[i] and v.at(i) are tested
        {
            check_lookups(v[i]);
            check_lookups(v.at(i));
        }
    }
}

// every lookup of the edited view finds what the first members of j hold
void check_first_members(const ordered_json_editable_view& v, const ordered_json& j)
{
    REQUIRE(v.type() == j.type());
    if (j.is_object())
    {
        for (const auto& kv : j.items())
        {
            const std::string& key = kv.key();
            const ptr_t ptr = ptr_t() / key;
            CAPTURE(key)
            REQUIRE(v.contains(key));
            CHECK(v.contains(ptr));
            CHECK(v.count(key) == occurrences(v, key));
            CHECK(v.find(key) != v.end());
            CHECK(v.at(ptr).type() == kv.value().type());
            check_first_members(v[key], kv.value());
            check_first_members(v.at(key), kv.value());
            check_first_members(v[ptr], kv.value());
        }
        CHECK(!v.contains("missing#key"));
    }
    else if (j.is_array())
    {
        REQUIRE(v.size() == j.size());
        for (std::size_t i = 0; i < j.size(); ++i)
        {
            check_first_members(v[i], j[i]);
        }
    }
    else
    {
        CHECK(v.materialize() == j);
    }
}

// (for documents whose objects repeat keys: j holds the first members, the
// lookups must find them; dump(), size(), and iteration list all members, but
// materialize() keeps the last value of a key, as parse() does of the dump)
void check_duplicates(const ordered_json_editable_document& d, const ordered_json& j)
{
    check_first_members(d.root(), j);
    check_lookups(d.root());
    CHECK(d.root().materialize() == ordered_json::parse(d.root().dump()));
}

void check_all(const ordered_json_editable_document& d, const ordered_json& j, bool deep)
{
    const std::string text = d.root().dump();
    REQUIRE(text == j.dump());
    CHECK(d.root().materialize() == j);
    if (deep)
    {
        CHECK(d.root().dump(2) == j.dump(2));
        CHECK(d.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
        CHECK(d.root() == j);
        compare(d.root(), j);
        // a fresh document of the text reads the same
        const ordered_json_document fresh = ordered_json_document::parse(text);
        CHECK(fresh.root() == d.root());
    }
}
} // namespace

TEST_CASE("json_view edits: differential")
{
    // random edits are applied to an ordered_json_editable_document and to the
    // ordered_json parse() produces; after every edit both must serialize,
    // materialize, and read back the same
    for (int n = 0; n < 250; ++n)
    {
        // the last 100 documents repeat keys in some of their objects; j then
        // holds the first member of each key, which the edits address
        const bool duplicates = n >= 150;
        ordered_json j = random_value(0);
        if (r(4) == 0)
        {
            j = ordered_json::object({{"a", random_value(1)}, {"b", random_value(1)}});
        }
        if (duplicates)
        {
            j = ordered_json::parse(j.dump()); // (normalized as the document reads it)
        }
        const std::string text = duplicates ? text_with_duplicates(j) : j.dump(r(2) == 0 ? -1 : 2);
        CAPTURE(text)
        ordered_json_editable_document d = ordered_json_editable_document::parse(text);
        if (!duplicates)
        {
            j = ordered_json::parse(text);
        }
        const ordered_json_document other = ordered_json_document::parse(random_value(0).dump());
        const int edits = 30;
        for (int e = 0; e < edits; ++e)
        {
            std::vector<ptr_t> paths;
            collect(j, ptr_t(), paths);
            const ptr_t p = paths[static_cast<std::size_t>(r(static_cast<int>(paths.size())))];
            const ordered_json& target = j[p];
            const ordered_json_editable_view tv = d.root().at(p);
            const int op = r(12);
            {
                if (op == 0) // assign a scalar
                {
                    const ordered_json v = random_scalar();
                    if (v.is_string() && r(2) == 0)
                    {
                        d.set(tv, v.get<std::string>());
                    }
                    else if (v.is_number_unsigned() && r(2) == 0)
                    {
                        d.set(tv, v.get<std::uint64_t>());
                    }
                    else
                    {
                        d.set(tv, v);
                    }
                    j[p] = v;
                }
                else if (op == 1) // assign a new array/object (or anything), sometimes via the pointer API
                {
                    const ordered_json v = random_value(2);
                    if (r(2) == 0)
                    {
                        d.set(p, v);
                    }
                    else
                    {
                        d.set(tv, v);
                    }
                    j[p] = v;
                }
                else if (op == 2) // copy a value of the same document
                {
                    const ptr_t& q = paths[static_cast<std::size_t>(r(static_cast<int>(paths.size())))];
                    const ordered_json v = j[q];
                    d.set(tv, d.root().at(q));
                    j[p] = v;
                }
                else if (op == 3) // copy a value of another document
                {
                    d.set(tv, other.root());
                    j[p] = other.root().materialize();
                }
                else if ((op == 4 || op == 5) && target.is_object()) // set a member (new or existing)
                {
                    std::string key = random_string() + "#" + std::to_string(counter++);
                    if (op == 5 && !target.empty())
                    {
                        key = std::next(target.begin(), r(static_cast<int>(target.size()))).key();
                    }
                    const ordered_json v = random_value(2);
                    d.set(tv, key, v);
                    j[p][key] = v;
                }
                else if (op == 6 && target.is_object() && !target.empty()) // erase a member
                {
                    const std::string key = std::next(target.begin(), r(static_cast<int>(target.size()))).key();
                    if (r(2) == 0)
                    {
                        d.erase(tv, key);
                    }
                    else
                    {
                        d.erase(p / key);
                    }
                    j[p].erase(key);
                }
                else if (op == 7 && (target.is_array() || target.is_null())) // push_back
                {
                    const ordered_json v = random_value(2);
                    d.push_back(tv, v);
                    j[p].push_back(v);
                }
                else if (op == 8 && target.is_array()) // insert
                {
                    const auto i = static_cast<std::size_t>(r(static_cast<int>(target.size()) + 1));
                    const ordered_json v = random_value(2);
                    d.insert(tv, i, v);
                    j[p].insert(j[p].begin() + static_cast<std::ptrdiff_t>(i), v);
                }
                else if (op == 9 && target.is_array() && !target.empty()) // erase an element
                {
                    const auto i = static_cast<std::size_t>(r(static_cast<int>(target.size())));
                    if (r(2) == 0)
                    {
                        d.erase(tv, i);
                    }
                    else
                    {
                        d.erase(p / i);
                    }
                    j[p].erase(i);
                }
                else if (op == 10 && target.is_array() && !target.empty()) // assign an element
                {
                    const auto i = static_cast<std::size_t>(r(static_cast<int>(target.size())));
                    const ordered_json v = random_value(2);
                    d.set(tv, i, v);
                    j[p][i] = v;
                }
                else if (op == 11) // a held view sees the assignment
                {
                    const ordered_json v = random_value(2);
                    const ordered_json_editable_view held = d.root().at(p);
                    d.set(p, v);
                    j[p] = v;
                    CHECK(held.dump() == v.dump());
                }
                else
                {
                    continue;
                }
            }
            CAPTURE(p.to_string())
            CAPTURE(op)
            if (duplicates)
            {
                check_duplicates(d, j);
            }
            else
            {
                check_all(d, j, e % 8 == 7 || e == edits - 1);
            }
        }
    }
}

TEST_CASE("json_view edits: errors")
{
    SECTION("an empty document")
    {
        json_editable_document d;
        CHECK_THROWS_WITH_AS(d.set(d.root(), 1), "[json.exception.invalid_iterator.202] view does not belong to this document", json::invalid_iterator&);
    }

    json_editable_document d = json_editable_document::parse(R"({"o": {"a": 1}, "a": [1, 2], "n": 1, "z": null})");
    const json_editable_view root = d.root();
    const json_document other = json_document::parse("[1]");
    json_editable_document other_editable = json_editable_document::parse("[1]");

    CHECK_THROWS_WITH_AS(d.set(other_editable.root(), 1), "[json.exception.invalid_iterator.202] view does not belong to this document", json::invalid_iterator&);
    CHECK_THROWS_WITH_AS(d.set(json_editable_view(), 1), "[json.exception.invalid_iterator.202] view does not belong to this document", json::invalid_iterator&);
    CHECK_THROWS_WITH_AS(d.set(root["a"], "k", 1), json_view_test::message("type_error.305", "/a", 21, 27, "cannot use operator[] with a string argument with array").c_str(), json::type_error&);
    CHECK_THROWS_WITH_AS(d.set(root["o"], 0, 1), json_view_test::message("type_error.305", "/o", 6, 14, "cannot use operator[] with a numeric argument with object").c_str(), json::type_error&);
    CHECK_THROWS_WITH_AS(d.set(root["a"], 2, 1), json_view_test::message("out_of_range.401", "/a", 21, 27, "array index 2 is out of range").c_str(), json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.set(root["a"], -1, 1), json_view_test::message("out_of_range.401", "/a", 21, 27, "array index -1 is out of range").c_str(), json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.push_back(root["o"], 1), json_view_test::message("type_error.308", "/o", 6, 14, "cannot use push_back() with object").c_str(), json::type_error&);
    CHECK_THROWS_WITH_AS(d.insert(root["n"], 0, 1), json_view_test::message("type_error.309", "/n", 34, 35, "cannot use insert() with number").c_str(), json::type_error&);
    CHECK_THROWS_WITH_AS(d.insert(root["a"], 3, 1), json_view_test::message("out_of_range.401", "/a", 21, 27, "array index 3 is out of range").c_str(), json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.erase(root["n"], "k"), json_view_test::message("type_error.307", "/n", 34, 35, "cannot use erase() with number").c_str(), json::type_error&);
    CHECK_THROWS_WITH_AS(d.erase(root["o"], 0), json_view_test::message("type_error.307", "/o", 6, 14, "cannot use erase() with object").c_str(), json::type_error&);
    CHECK_THROWS_WITH_AS(d.erase(root["a"], 2), json_view_test::message("out_of_range.401", "/a", 21, 27, "array index 2 is out of range").c_str(), json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.erase(json::json_pointer("")), "[json.exception.out_of_range.405] JSON pointer has no parent", json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.erase(json::json_pointer("/missing/x")), json_view_test::message("out_of_range.403", "", 0, 47, "key 'missing' not found").c_str(), json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.set(json::json_pointer("/a/01"), 1), "[json.exception.parse_error.106] parse error: array index '01' must not begin with '0'", json::parse_error&);
    CHECK_THROWS_WITH_AS(d.set(root, json_editable_view()), "[json.exception.type_error.302] type must be a value, but is discarded", json::type_error&);
    CHECK_THROWS_WITH_AS(d.set(root, json::binary({1, 2})), "[json.exception.type_error.319] cannot store a binary value in a json_document", json::type_error&);

#if !defined(JSON_NOEXCEPTION)
    // invalid UTF-8 is rejected when it enters the document, with the error
    // basic_json::dump() reports for the same string
    for (const std::string bad :
            {"\xC3\x28", "a\xE2\x28\xA1", "\xF0\x28\x8C\xBC", "\xE2\x82", "x\xF0\x9F\x98", "\xFF", "\xED\xA0\x80", "\xC0\xAF"
            })
    {
        CAPTURE(bad)
        const std::string expected = exception_of_call([&]
        {
            const std::string text = json(bad).dump();
            static_cast<void>(text);
        });
        CHECK(!expected.empty());
        CHECK(exception_of_call([&] { d.set(root["z"], bad); }) == expected);
        CHECK(exception_of_call([&] { d.set(root["o"], bad, 1); }) == expected);
        CHECK(exception_of_call([&] { d.set(root["z"], json{{"k", bad}}); }) == expected);
    }
#endif
    // nothing of the failed edits is visible
    CHECK(root.dump() == R"({"o":{"a":1},"a":[1,2],"n":1,"z":null})");
    static_cast<void>(other);
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("json_view edits: the size of a text arena")
{
    using nlohmann::detail::view::text_capacity;
    constexpr std::size_t limit = 0xFFFFFFFFu;
    // grows by doubling, or to what is needed (plus some room)
    CHECK(text_capacity(0, 0, 10) == 266);
    CHECK(text_capacity(1000, 990, 20) == 2000);
    CHECK(text_capacity(100, 100, 5000) == 5356);
    // an arena beyond 2 GiB: doubling is clamped to 4 GiB - 1
    CHECK(text_capacity(0x90000000u, 0x8FFFFFFFu, 2) == limit);
    CHECK(text_capacity(limit, limit - 10, 10) == limit);
    // exactly what fits is accepted, without room to spare
    CHECK(text_capacity(100, 90, limit - 90) == limit);
    CHECK(text_capacity(limit - 100, limit - 100, 100) == limit);
    // what does not fit is an error
    CHECK_THROWS_WITH_AS(text_capacity(100, 90, limit - 89), "[json.exception.out_of_range.416] edits of 4 GiB or more are not supported by json_document", json::out_of_range&);
    CHECK_THROWS_WITH_AS(text_capacity(limit, limit, 1), "[json.exception.out_of_range.416] edits of 4 GiB or more are not supported by json_document", json::out_of_range&);
}
#endif

TEST_CASE("json_view edits: the chunks of new nodes")
{
    using nlohmann::detail::view::alloc_nodes;
    using nlohmann::detail::view::document_data;
    const std::unique_ptr<document_data, document_data::deleter> d(document_data::create(0));
    // the first chunk has room for 64 nodes, the next one for 128
    const nlohmann::detail::view::node* const first = alloc_nodes(*d, 10);
    CHECK(d->edits->chunks.size() == 1);
    // a request of half of the next chunk (128 nodes) or more gets a chunk of
    // its own
    const nlohmann::detail::view::node* const large = alloc_nodes(*d, 100);
    CHECK(d->edits->chunks.size() == 2);
    CHECK(large == d->edits->chunks.back().get());
    // and the rest of the first chunk is still used
    CHECK(alloc_nodes(*d, 50) == first + 10);
    CHECK(d->edits->chunks.size() == 2);
    // a smaller request that does not fit starts a new (doubled) chunk; the
    // call is a statement of its own, as the operands of == are unsequenced
    // and MSVC reads chunks.back() before the call adds the chunk
    const nlohmann::detail::view::node* const doubled = alloc_nodes(*d, 10);
    CHECK(doubled == d->edits->chunks.back().get());
    CHECK(d->edits->chunks.size() == 3);
    CHECK(d->edits->chunk_end - d->edits->chunk_cur == 128 - 10);
    CHECK(d->edits->bytes == (64 + 100 + 128) * sizeof(nlohmann::detail::view::node));
}

TEST_CASE("json_view edits: replacing arrays and objects by scalars")
{
    // the first assignment switches the parent to links; the later ones do
    // not need to look for the parent again
    std::string text = "[";
    json expected = json::array();
    for (int i = 0; i < 300; ++i)
    {
        text += (i != 0 ? ",[" : "[") + std::to_string(i) + ",{\"k\":" + std::to_string(i) + "}]";
        expected.push_back(json::array({i, json{{"k", i}}}));
    }
    text += ']';
    json_editable_document d = json_editable_document::parse(text);
    CHECK(d.root().dump() == expected.dump());
    for (int i = 0; i < 300; i += 2)
    {
        d.set(d.root()[static_cast<std::size_t>(i)], i);
        expected[static_cast<std::size_t>(i)] = i;
    }
    CHECK(d.root().dump() == expected.dump());
    for (int i = 1; i < 300; i += 2) // (elements that are still in the parsed layout of their parent)
    {
        d.set(d.root()[static_cast<std::size_t>(i)][1], "x"); // replaces an object
        expected[static_cast<std::size_t>(i)][1] = "x";
    }
    CHECK(d.root().dump() == expected.dump());

    // new values, and values in new values
    d.push_back(d.root(), json::parse(R"([[1,2],{"a":[3]}])"));
    expected.push_back(json::parse(R"([[1,2],{"a":[3]}])"));
    d.set(d.root()[300][0], 7);
    expected[300][0] = 7;
    d.insert(d.root(), 0, json::array({1, 2}));
    expected.insert(expected.begin(), json::array({1, 2}));
    d.set(d.root()[0], nullptr);
    expected[0] = nullptr;
    d.set(d.root()[301], 5);
    expected[301] = 5;
    CHECK(d.root().dump() == expected.dump());
    CHECK(d.root().materialize() == expected);
}

TEST_CASE("json_view edits: arrays whose elements have no subtrees")
{
    // such an array is indexed directly while it is in its parsed layout; edits
    // that replace elements by scalars keep it, others move it
    json_editable_document d = json_editable_document::parse("[10,20,30,40]");
    json expected = json::array({10, 20, 30, 40});
    const auto check = [&]
    {
        CHECK(d.root().size() == expected.size());
        for (std::size_t i = 0; i < expected.size(); ++i)
        {
            CHECK(d.root()[i].materialize() == expected[i]);
            CHECK(d.root().at(i).materialize() == expected[i]);
        }
        CHECK(d.root()[expected.size()].is_discarded());
        CHECK(d.root().back().materialize() == expected.back());
        CHECK(d.root().dump() == expected.dump());
    };
    check();
    d.set(d.root()[1], "x");
    expected[1] = "x";
    check();
    d.set(d.root()[3], 2.5);
    expected[3] = 2.5;
    check();
    d.set(d.root()[2], json::array({1, 2}));
    expected[2] = json::array({1, 2});
    check();
    d.push_back(d.root(), 50);
    expected.push_back(50);
    check();
    d.insert(d.root(), 0, true);
    expected.insert(expected.begin(), true);
    check();
    d.erase(d.root(), 1);
    expected.erase(expected.begin() + 1);
    check();
    d.set(d.root()[2], nullptr);
    expected[2] = nullptr;
    check();
}

TEST_CASE("json_view edits: materializing values nested deeper than the document was parsed")
{
    // the stack of open containers of materialize() is sized from the nesting of the parsed text;
    // a value added by an edit can be deeper than that (and than the stack that is local to the call)
    json_editable_document d = json_editable_document::parse("[1,[2]]");
    json expected = json::array({1, json::array({2})});
    json nested = 3;
    for (int level = 0; level < 40; ++level)
    {
        nested = json::array({nested, json{{"k", level}}});
    }
    d.push_back(d.root(), nested);
    expected.push_back(nested);
    CHECK(d.root().materialize() == expected);
    CHECK(d.root()[2].materialize() == nested);
    d.set(d.root()[1][0], nested);
    expected[1][0] = nested;
    CHECK(d.root().materialize() == expected);
    CHECK(d.root().get<json>() == expected);
}

TEST_CASE("json_view edits: an editable document before and after its first edit")
{
    // until the first edit, an editable document is read like a read-only one; views made before the edit
    // keep working after it
    const std::string text = R"({"a":[1,2,{"x":"y"},4],"b":{"c":true,"d":null},"e":"text","f":[]})";
    const json_document read_only = json_document::parse(text);
    json_editable_document d = json_editable_document::parse(text);
    const auto root = d.root();
    const auto same_as_read_only = [&]
    {
        CHECK(root.dump() == read_only.root().dump());
        CHECK(root.dump(2) == read_only.root().dump(2));
        CHECK(root.materialize() == read_only.root().materialize());
        CHECK(root["a"][2]["x"].get_string() == "y");
        CHECK(root["a"].at(3).get<int>() == 4);
        CHECK(root["a"].back().get<int>() == 4);
        CHECK(root.contains("b"));
        CHECK(!root.contains("zz"));
        CHECK(root.find("e")->get_string() == "text");
        CHECK(root.find("zz") == root.end());
        CHECK(root["b"]["c"].get<bool>());
        CHECK(root.value("e", "none") == "text");
        std::size_t count = 0;
        for (const auto m : root["a"])
        {
            CHECK(m.materialize() == read_only.root()["a"][count].materialize());
            ++count;
        }
        CHECK(count == 4);
    };
    same_as_read_only();
    // an edit that changes a scalar in place, then one that moves an array
    d.set(root["e"], "other");
    CHECK(root["e"].get_string() == "other");
    CHECK(root["a"][2]["x"].get_string() == "y");
    CHECK(root["a"].back().get<int>() == 4);
    d.push_back(root["f"], 7);
    CHECK(root["f"][0].get<int>() == 7);
    CHECK(root["f"].back().get<int>() == 7);
    CHECK(root.dump() == R"({"a":[1,2,{"x":"y"},4],"b":{"c":true,"d":null},"e":"other","f":[7]})");
    d.set(root["a"], 2, json::array({1, 2}));
    CHECK(root["a"][2][1].get<int>() == 2);
    CHECK(root["a"].dump() == "[1,2,[1,2],4]");
    CHECK(root.materialize() == json::parse(R"({"a":[1,2,[1,2],4],"b":{"c":true,"d":null},"e":"other","f":[7]})"));
}

namespace
{
// reads of "a" in an object that repeats it: the first member wins, however the
// object is stored
template<typename View>
void check_first_wins(const View& o, int expected)
{
    CAPTURE(expected)
    CHECK(o["a"].template get<int>() == expected);
    CHECK(o.at("a").template get<int>() == expected);
    CHECK(o.find("a")->template get<int>() == expected);
    CHECK(o.value("a", -1) == expected);
    CHECK(o[json::json_pointer("/a")].template get<int>() == expected);
    CHECK(o.at(json::json_pointer("/a")).template get<int>() == expected);
    CHECK(o.value(json::json_pointer("/a"), -1) == expected);
    CHECK(o.contains("a"));
    CHECK(o.contains(json::json_pointer("/a")));
    std::size_t members_a = 0;
    for (const auto& item : o.items())
    {
        members_a += std::string(item.key().data(), item.key().size()) == "a" ? 1u : 0u;
    }
    CHECK(o.count("a") == members_a); // every member, unlike the lookups
}
} // namespace

TEST_CASE("json_view edits: duplicate keys")
{
    SECTION("an object in its parsed layout, then moved by edits")
    {
        json_editable_document d = json_editable_document::parse(R"({"a": 1, "b": 2, "a": 3})");
        check_first_wins(d.root(), 1);
        CHECK(d.root().size() == 3);
        CHECK(d.root().dump() == R"({"a":1,"b":2,"a":3})");
        CHECK(d.root().materialize()["a"] == 3); // (parse() keeps the last value)

        // an edit of a value does not move the object
        d.set(d.root()["b"], 5);
        check_first_wins(d.root(), 1);
        d.set(d.root()["a"], 4); // the member that lookups find
        check_first_wins(d.root(), 4);
        CHECK(d.root().dump() == R"({"a":4,"b":5,"a":3})");

        // an appended member moves it
        d.set(d.root(), "c", true);
        check_first_wins(d.root(), 4);
        CHECK(d.root().size() == 4);
        CHECK(d.root().dump() == R"({"a":4,"b":5,"a":3,"c":true})");
        d.set(d.root()["a"], 6);
        check_first_wins(d.root(), 6);
        CHECK(d.root().dump() == R"({"a":6,"b":5,"a":3,"c":true})");
        d.set(json::json_pointer("/a"), 7);
        check_first_wins(d.root(), 7);
    }

    SECTION("set assigns the member that lookups find")
    {
        // the key stays where its first occurrence is, the later members are dropped
        ordered_json_editable_document d = ordered_json_editable_document::parse(R"({"a": 1, "b": 2, "a": 3, "c": 4, "a": 5})");
        const ordered_json_editable_view held = d.root()["a"];
        CHECK(held.get<int>() == 1);
        const ordered_json_editable_view assigned = d.set(d.root(), "a", "x");
        CHECK(held.get<std::string>() == "x");
        CHECK(assigned.get<std::string>() == "x");
        CHECK(d.root().dump() == R"({"a":"x","b":2,"c":4})");
        CHECK(d.root().materialize() == ordered_json::parse(R"({"a": "x", "b": 2, "c": 4})"));
        CHECK(d.root().size() == 3);

        // as for the object that parse() makes of the text
        ordered_json j = ordered_json::parse(R"({"a": 1, "b": 2, "a": 3, "c": 4, "a": 5})");
        j["a"] = "x";
        CHECK(d.root().materialize().dump() == j.dump());

        // through a pointer, below a duplicate
        d = ordered_json_editable_document::parse(R"({"a": {"x": 1}, "b": 2, "a": {"x": 3}})");
        d.set(ptr_t("/a/x"), 4);
        CHECK(d.root().dump() == R"({"a":{"x":4},"b":2,"a":{"x":3}})");
        d.set(ptr_t("/a"), 0);
        CHECK(d.root().dump() == R"({"a":0,"b":2})");
    }

    SECTION("erase removes every member")
    {
        json_editable_document d = json_editable_document::parse(R"({"a": 1, "b": 2, "a": 3})");
        d.set(d.root(), "c", 4);
        check_first_wins(d.root(), 1);
        CHECK(d.erase(d.root(), "a") == 2);
        CHECK(d.root().dump() == R"({"b":2,"c":4})");
        CHECK(!d.root().contains("a"));
        CHECK(d.root()["a"].is_discarded());
        CHECK(d.erase(d.root(), "a") == 0);
        d = json_editable_document::parse(R"({"a": 1, "b": 2, "a": 3})");
        CHECK(d.erase(json::json_pointer("/a")) == 2);
        CHECK(d.root().dump() == R"({"b":2})");
    }

    SECTION("a large object with an index")
    {
        std::string text = R"({"a":0,"k7":"first")";
        for (int i = 0; i < 200; ++i)
        {
            text += ",\"k" + std::to_string(i) + "\":" + std::to_string(i);
        }
        text += R"(,"a":1,"k7":"last","a":2})";
        json_editable_document d = json_editable_document::parse(text);
        check_first_wins(d.root(), 0);
        CHECK(d.root()["k7"].get_string() == "first");
        CHECK(d.root()["k199"].get<int>() == 199);

        // a value assigned in place: the index stays in use
        d.set(d.root()["a"], 3);
        check_first_wins(d.root(), 3);
        d.set(d.root()["k7"], "changed");
        CHECK(d.root()["k7"].get_string() == "changed");
        CHECK(d.root()["k199"].get<int>() == 199);

        // an appended member moves the members: the lookup scans them
        d.set(d.root(), "new", 1);
        check_first_wins(d.root(), 3);
        CHECK(d.root()["k7"].get_string() == "changed");
        CHECK(d.root()["k7"].get_string() == d.root().at("k7").get_string());
        CHECK(d.root()["k199"].get<int>() == 199);
        CHECK(d.root()["new"].get<int>() == 1);

        // a value replaced by a container, in an object that was not moved
        d = json_editable_document::parse(text);
        d.set(d.root()["a"], json{{"x", 1}});
        CHECK(d.root()["a"]["x"].get<int>() == 1);
        CHECK(d.root()["k7"].get_string() == "first");
        CHECK(d.erase(d.root(), "k7") == 3); // (the key occurs three times)
        CHECK(d.root()["k7"].is_discarded());
        CHECK(d.root()["a"]["x"].get<int>() == 1);
    }

    SECTION("objects in moved arrays and in new values")
    {
        json_editable_document d = json_editable_document::parse(R"([{"a": 1, "a": 2}, {"a": 3, "b": 0, "a": 4}])");
        check_first_wins(d.root()[0], 1);
        check_first_wins(d.root()[1], 3);
        d.insert(d.root(), 0, json::parse(R"({"a": 0})"));
        d.push_back(d.root(), json::parse(R"({"a": 5, "a": 6})")); // (a basic_json value has one member)
        check_first_wins(d.root()[1], 1);
        check_first_wins(d.root()[2], 3);
        CHECK(d.root()[3]["a"].get<int>() == 6);
        d.set(d.root()[1], "a", 8);
        check_first_wins(d.root()[1], 8);
        CHECK(d.root()[1].dump() == R"({"a":8})");
        d.erase(d.root(), 0);
        check_first_wins(d.root()[1], 3);
        CHECK(d.root().dump() == R"([{"a":8},{"a":3,"b":0,"a":4},{"a":6}])");
    }

    SECTION("values of other documents")
    {
        const json_document source = json_document::parse(R"({"list": [{"a": 1, "a": 2}], "o": {"b": {"a": 3, "a": 4}, "a": 5, "a": 6}})");
        json_editable_document d = json_editable_document::parse("{}");
        d.set(d.root(), "copy", source.root()["list"]);
        d.set(d.root(), "o", source.root()["o"]);
        // (the copies keep the repeated members)
        CHECK(d.root().dump() == R"({"copy":[{"a":1,"a":2}],"o":{"b":{"a":3,"a":4},"a":5,"a":6}})");
        check_first_wins(d.root()["copy"][0], 1);
        check_first_wins(d.root()["o"]["b"], 3);
        check_first_wins(d.root()["o"], 5);
        d.set(d.root()["o"]["b"], "c", 0);
        check_first_wins(d.root()["o"]["b"], 3);
        d.set(d.root()["o"], "d", 0);
        check_first_wins(d.root()["o"], 5);
        CHECK(d.root()["o"]["b"]["a"].get<int>() == 3);
        CHECK(d.root()["o"]["d"].get<int>() == 0);
    }
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("json_view edits: check_utf8 agrees with the byte-wise check")
{
    namespace dv = nlohmann::detail::view;

    // "ok" or the exception message
    const auto run = [](bool fast, const std::string & s) -> std::string
    {
        try
        {
            if (fast)
            {
                dv::check_utf8(s.data(), s.size());
            }
            else
            {
                dv::check_utf8_bytewise(reinterpret_cast<const unsigned char*>(s.data()), s.size(), 0);
            }
        }
        catch (const json::type_error& e)
        {
            return {e.what()};
        }
        return {"ok"};
    };
    std::size_t errors = 0;
    const auto same = [&](const std::string & s)
    {
        const std::string a = run(true, s);
        const std::string b = run(false, s);
        if (a != b)
        {
            INFO("fast: " << a << ", byte-wise: " << b << ", length " << s.size());
            CHECK(a == b);
        }
        errors += b != "ok" ? 1u : 0u;
    };

    const std::vector<std::string> pieces =
    {
        "a", "Z", " ", "\"", "\\", "\n", "\x01", "\x7f", "\xc3\xa4", "\xe4\xb8\xad", "\xf0\x9f\x98\x80",
        "\x80", "\xbf", "\xc0\x80", "\xc1\xbf", "\xc2", "\xe0\x80\x80", "\xe0\x9f\xbf", "\xed\xa0\x80", "\xed\xbf\xbf",
        "\xf0\x80\x80\x80", "\xf0\x8f\xbf\xbf", "\xf4\x90\x80\x80", "\xf4\x8f\xbf\xbf", "\xf5", "\xf8", "\xff", "\xfe",
        "\xe4\xb8", "\xf0\x9f\x98", "\xf0\x9f", "\xf0"
    };

    // every piece behind prefixes of every length, and followed by more bytes
    for (std::size_t prefix = 0; prefix <= 64; ++prefix)
    {
        for (const auto& piece : pieces)
        {
            same(std::string(prefix, 'x') + piece);
            same(std::string(prefix, 'x') + piece + "yz");
            same(std::string(prefix, '"') + piece);
            same(std::string(prefix, '\xc3') + piece);
            same(std::string(prefix / 2, '\xc3').append(prefix / 2, '\xa4') + piece);
            same(std::string(prefix, 'x') + "\xe4\xb8\xad" + piece);
        }
    }
    // an invalid byte at every position of valid strings of every length
    for (std::size_t len = 0; len <= 64; ++len)
    {
        const std::string ascii(len, 'a');
        std::string mixed;
        while (mixed.size() < len)
        {
            if (mixed.size() % 7 == 0)
            {
                mixed += "\xc3\xa4";
            }
            else if (mixed.size() % 11 == 0)
            {
                mixed += "\xf0\x9f\x98\x80";
            }
            else
            {
                mixed += "a";
            }
        }
        same(ascii);
        same(mixed);
        for (std::size_t pos = 0; pos < len; ++pos)
        {
            for (const char bad :
                    {'\x80', '\xc0', '\xc2', '\xe0', '\xf4', '\xff', '"', '\\', '\x1f'
                    })
            {
                std::string s = ascii;
                s[pos] = bad;
                same(s);
                s = mixed;
                s[pos] = bad;
                same(s);
            }
        }
    }
    // random bytes, biased to the interesting ones
    std::mt19937 gen(5869); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed): reproducible
    static const std::array<unsigned char, 23> interesting = {{0x00, 0x1f, 0x22, 0x5c, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc2, 0xdf, 0xe0, 0xe1, 0xed, 0xef, 0xf0, 0xf1, 0xf4, 0xf5, 0xff}};
    for (int i = 0; i < 100000; ++i)
    {
        std::string s(gen() % 80, 'a');
        for (auto& c : s)
        {
            const unsigned r = gen() % 8;
            if (r == 0)
            {
                c = static_cast<char>(gen() & 0xff);
            }
            else if (r == 1)
            {
                c = static_cast<char>(interesting[gen() % interesting.size()]);
            }
        }
        same(s);
    }
    CHECK(errors > 1000);
}
#endif
