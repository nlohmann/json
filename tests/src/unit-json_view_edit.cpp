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

#include <array>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <random>
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
    for (int n = 0; n < 150; ++n)
    {
        ordered_json j = random_value(0);
        if (r(4) == 0)
        {
            j = ordered_json::object({{"a", random_value(1)}, {"b", random_value(1)}});
        }
        const std::string text = j.dump(r(2) == 0 ? -1 : 2);
        CAPTURE(text)
        ordered_json_editable_document d = ordered_json_editable_document::parse(text);
        j = ordered_json::parse(text);
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
            check_all(d, j, e % 8 == 7 || e == edits - 1);
        }
    }
}

namespace
{
#if !defined(JSON_NOEXCEPTION)
// the exception a call throws, or "" if it throws none
std::string exception_of_call(const std::function<void()>& f)
{
    try
    {
        f();
    }
    catch (const json::exception& e)
    {
        return e.what();
    }
    return "";
}
#endif
} // namespace

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
    CHECK_THROWS_WITH_AS(d.set(root["a"], "k", 1), "[json.exception.type_error.305] cannot use operator[] with a string argument with array", json::type_error&);
    CHECK_THROWS_WITH_AS(d.set(root["o"], 0, 1), "[json.exception.type_error.305] cannot use operator[] with a numeric argument with object", json::type_error&);
    CHECK_THROWS_WITH_AS(d.set(root["a"], 2, 1), "[json.exception.out_of_range.401] array index 2 is out of range", json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.set(root["a"], -1, 1), "[json.exception.out_of_range.401] array index -1 is out of range", json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.push_back(root["o"], 1), "[json.exception.type_error.308] cannot use push_back() with object", json::type_error&);
    CHECK_THROWS_WITH_AS(d.insert(root["n"], 0, 1), "[json.exception.type_error.309] cannot use insert() with number", json::type_error&);
    CHECK_THROWS_WITH_AS(d.insert(root["a"], 3, 1), "[json.exception.out_of_range.401] array index 3 is out of range", json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.erase(root["n"], "k"), "[json.exception.type_error.307] cannot use erase() with number", json::type_error&);
    CHECK_THROWS_WITH_AS(d.erase(root["o"], 0), "[json.exception.type_error.307] cannot use erase() with object", json::type_error&);
    CHECK_THROWS_WITH_AS(d.erase(root["a"], 2), "[json.exception.out_of_range.401] array index 2 is out of range", json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.erase(json::json_pointer("")), "[json.exception.out_of_range.405] JSON pointer has no parent", json::out_of_range&);
    CHECK_THROWS_WITH_AS(d.erase(json::json_pointer("/missing/x")), "[json.exception.out_of_range.403] key 'missing' not found", json::out_of_range&);
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
        CHECK(d.root().dump() == R"({"copy":[1,"two",{"three":3.5}],"text":"a\nb","edited":{"inner":[1,2]},"self":[1,"two",{"three":3.5}]})");
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
