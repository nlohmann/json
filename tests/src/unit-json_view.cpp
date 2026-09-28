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

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <list>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifdef JSON_HAS_CPP_17
    #include <string_view>
#endif

namespace
{
#if !defined(JSON_NOEXCEPTION)
// the exception parse() throws for a text, or "" if it accepts it
std::string parse_exception(const std::string& text, bool comments = false, bool trailing_commas = false)
{
    try
    {
        const json j = json::parse(text, nullptr, true, comments, trailing_commas);
        static_cast<void>(j);
    }
    catch (const json::exception& e)
    {
        return e.what();
    }
    return "";
}

std::string view_exception(const std::string& text, bool comments = false, bool trailing_commas = false)
{
    try
    {
        const json_document d = json_document::parse(text, true, comments, trailing_commas);
        static_cast<void>(d);
    }
    catch (const json::exception& e)
    {
        return e.what();
    }
    return "";
}
#endif

// a small deterministic generator of documents
struct generator
{
    std::mt19937 rng{5295}; // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)

    int r(int n)
    {
        return static_cast<int>(rng() % static_cast<unsigned>(n));
    }

    void str(std::string& o)
    {
        static const char* const pieces[] = {"a", "Z", " ", "\\n", "\\\"", "\\u00e9", "\\ud83d\\ude00", "\xc3\xa9", "\xe3\x81\x82", "long text beyond the first sixteen bytes"}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        o += '"';
        for (int n = r(5); n > 0; --n)
        {
            o += pieces[r(10)];
        }
        o += '"';
    }

    void value(std::string& o, int depth)
    {
        static const char* const scalars[] = {"0", "-1", "123456789012", "18446744073709551615", "18446744073709551616", "-9223372036854775809", // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
                                              "1.5", "-2.25e-3", "1E2", "0.1", "true", "false", "null"
                                             };
        const int k = depth > 5 ? 2 + r(4) : r(6);
        if (k < 2)
        {
            const bool object = k == 0;
            o += object ? '{' : '[';
            for (int i = r(5); i > 0; --i)
            {
                if (object)
                {
                    str(o);
                    o += r(2) == 0 ? ":" : " : ";
                }
                value(o, depth + 1);
                o += i > 1 ? ", " : "";
            }
            o += object ? '}' : ']';
        }
        else if (k < 4)
        {
            str(o);
        }
        else
        {
            o += scalars[r(13)];
        }
    }
};
} // namespace

TEST_CASE("json_view")
{
    SECTION("types and capacity")
    {
        for (const char* text :
                {"null", "true", "false", "0", "-1", "18446744073709551615", "-9223372036854775808", "18446744073709551616", "1.5",
                 "\"\"", "\"text\"", "[]", "[1,2,3]", "{}", "{\"a\":1,\"b\":2}" // NOLINT(modernize-raw-string-literal)
                })
        {
            CAPTURE(text);
            const json j = json::parse(text);
            const json_document d = json_document::parse(text);
            const json_view v = d.root();
            CHECK(v.type() == j.type());
            CHECK(v.is_null() == j.is_null());
            CHECK(v.is_boolean() == j.is_boolean());
            CHECK(v.is_number() == j.is_number());
            CHECK(v.is_number_integer() == j.is_number_integer());
            CHECK(v.is_number_unsigned() == j.is_number_unsigned());
            CHECK(v.is_number_float() == j.is_number_float());
            CHECK(v.is_string() == j.is_string());
            CHECK(v.is_array() == j.is_array());
            CHECK(v.is_object() == j.is_object());
            CHECK(v.is_binary() == j.is_binary());
            CHECK(v.is_primitive() == j.is_primitive());
            CHECK(v.is_structured() == j.is_structured());
            CHECK(!v.is_discarded());
            CHECK(static_cast<bool>(v));
            CHECK(v.size() == j.size());
            CHECK(v.empty() == j.empty());
            CHECK(v.materialize() == j);
        }

        const json_view invalid{};
        CHECK(invalid.is_discarded());
        CHECK(!static_cast<bool>(invalid));
        CHECK(invalid.type() == json::value_t::discarded);
        CHECK(invalid.size() == 0);
        CHECK(invalid.empty());
        CHECK(invalid.materialize().is_discarded());
        CHECK(invalid.source_offset() == static_cast<std::size_t>(-1));
    }

    SECTION("materialize")
    {
        generator g;
        for (int i = 0; i < 2000; ++i)
        {
            std::string text;
            g.value(text, 0);
            CAPTURE(text);
            CHECK(json_document::parse(text).root().materialize() == json::parse(text));
            // member order as ordered_json::parse keeps it
            CHECK(ordered_json_document::parse(text).root().materialize().dump() == ordered_json::parse(text).dump());
        }
        // duplicate keys: the last value, at the position of the first key
        CHECK(json_document::parse(R"({"a":1,"b":2,"a":3})").root().materialize() == json::parse(R"({"a":1,"b":2,"a":3})"));
        CHECK(ordered_json_document::parse(R"({"a":1,"b":2,"a":3})").root().materialize().dump() == R"({"a":3,"b":2})");
        // very deep nesting (iterative, as parse())
        const std::string deep = std::string(100000, '[') + std::string(100000, ']');
        CHECK(json_document::parse(deep).root().materialize() == json::parse(deep));
#if JSON_DIAGNOSTICS
        // the parents are set, so errors name the path
        const json m = json_document::parse(R"({"a":{"b":[1]}})").root().materialize();
        CHECK_THROWS_WITH_AS(m.at("a").at("b").at(0).at("x"), "[json.exception.type_error.304] (/a/b/0) cannot use at() with number", json::type_error&);
#endif
    }

    SECTION("parse errors are those of parse()")
    {
        for (const char* text :
                {
                    "", " ", "[", "]", "{", "[1,]", "{\"a\":1,}", "[1 2]", "{\"a\" 1}", "{1:2}", "tru", "nul", "fals", "truex", "-", "01", "1.", ".5", "1e",
                    "\"", "\"abc", "\"\\x\"", "\"\\u12\"", "\"\\ud800\"", "\"\\udc00\"", "\"\x01\"", "\"\xff\"", "\"\xc3\"", "[1]x", "/", "/*", "[\n  1,\n  x\n]", // NOLINT(modernize-raw-string-literal)
                    "1e400", "-1e400", "[1.7976931348623159e308]", "{\"a\":\n{\"b\": [1, 2,\n 3 x]}}"
                })
        {
            CAPTURE(text);
#if !defined(JSON_NOEXCEPTION)
            const std::string expected = parse_exception(text);
            REQUIRE(!expected.empty());
            CHECK(view_exception(text) == expected);
#endif
            CHECK(!json_document::accept(text));
            const json_document d = json_document::parse(text, false);
            CHECK(d.is_discarded());
            CHECK(d.root().is_discarded());
            CHECK(d.node_count() == 0);
        }
        // the exception types
        json_document _;
        CHECK_THROWS_AS(_ = json_document::parse("[1,"), json::parse_error&);
        CHECK_THROWS_AS(_ = json_document::parse("1e400"), json::out_of_range&);
    }

    SECTION("parse options")
    {
        for (const char* text :
                {"// c\n[1]", "[1, /* c */ 2]", "[1,]", "{\"a\":1,}", "[1,/* c */]", "/", "/* ", "[1,,]"
                })
        {
            CAPTURE(text);
            for (int options = 0; options < 4; ++options)
            {
                const bool comments = (options & 1) != 0;
                const bool trailing_commas = (options & 2) != 0;
                CHECK(json_document::accept(text, comments, trailing_commas) == json::accept(text, comments, trailing_commas));
#if !defined(JSON_NOEXCEPTION)
                CHECK(view_exception(text, comments, trailing_commas) == parse_exception(text, comments, trailing_commas));
#endif
            }
        }
    }

    SECTION("overflow of the floating-point type")
    {
        // the overflow is that of the document's number_float_t: 1e39
        // overflows a float, the largest float 3.4028235e38 does not, but
        // 3.4028236e38 rounds beyond it; a double document is not affected
        using json_float = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;
        using float_document = nlohmann::basic_json_document<json_float>;
        CHECK_FALSE(json_float::accept("1e39"));
        CHECK(json_float::accept("3.4028235e38"));
        CHECK_FALSE(json_float::accept("3.4028236e38"));
        for (const char* text :
                {
                    "1e39", "-1e39", "[3.4028235e38]", "[3.4028236e38]", "{\"a\": [1e38, -3.4028235e38]}", "{\"a\": [1e-50, 1e39]}"
                })
        {
            CAPTURE(text);
            const bool accepted = json_float::accept(text);
            CHECK(float_document::accept(text) == accepted);
            CHECK(float_document::parse(text, false).is_discarded() == !accepted);
            CHECK(json_document::accept(text));
            if (accepted)
            {
                CHECK(float_document::parse(text).root().materialize() == json_float::parse(text));
            }
        }
        float_document f;
        CHECK_THROWS_WITH_AS(f = float_document::parse("1e39"), "[json.exception.out_of_range.406] number overflow parsing '1e39'", json::out_of_range&);
        CHECK_THROWS_WITH_AS(f = float_document::parse("[3.4028236e38]"), "[json.exception.out_of_range.406] number overflow parsing '3.4028236e38'", json::out_of_range&);
    }

    SECTION("NUL and BOM")
    {
        const std::string with_nul("[1]\0garbage", 11);
        CHECK(json_document::accept(with_nul) == json::accept(with_nul));
        const std::string nul_in_comment("[1, // c\0\n2]", 12);
        CHECK(json_document::accept(nul_in_comment, true) == json::accept(nul_in_comment, true));
        CHECK(json_document::parse("\xEF\xBB\xBF[1]").root().materialize() == json::parse("\xEF\xBB\xBF[1]"));
#if !defined(JSON_NOEXCEPTION)
        CHECK(view_exception("\xEF\xBB") == parse_exception("\xEF\xBB"));
#endif
    }

    SECTION("inputs")
    {
        const std::string text = R"([1, "two", {"three": 3.5}])";
        const json expected = json::parse(text);

        // borrowed: the text must outlive the document
        const json_document borrowed = json_document::parse(text);
        CHECK(!borrowed.owns_source());
        CHECK(borrowed.source().data() == text.data());
        CHECK(borrowed.root().materialize() == expected);
        CHECK(json_document::parse(text.c_str()).root().materialize() == expected);
        CHECK(json_document::parse(R"([1, "two", {"three": 3.5}])").root().materialize() == expected);
        CHECK(json_document::parse(text.data(), text.data() + text.size()).root().materialize() == expected);
        const std::vector<char> chars(text.begin(), text.end());
        CHECK(!json_document::parse(chars).owns_source());
        CHECK(json_document::parse(chars).root().materialize() == expected);
        const std::vector<std::uint8_t> bytes(text.begin(), text.end());
        CHECK(json_document::parse(bytes).root().materialize() == expected);
#ifdef JSON_HAS_CPP_17
        const std::string_view sv = text;
        CHECK(!json_document::parse(sv).owns_source());
        CHECK(json_document::parse(sv).root().materialize() == expected);
#endif

        // owned
        std::string moved = text;
        const json_document from_rvalue = json_document::parse(std::move(moved));
        CHECK(from_rvalue.owns_source());
        CHECK(from_rvalue.root().materialize() == expected);
        CHECK(json_document::parse(std::vector<char>(text.begin(), text.end())).owns_source());
        CHECK(json_document::parse_copy(text).owns_source());
        CHECK(json_document::parse_copy(text).root().materialize() == expected);
        std::istringstream stream(text);
        const json_document from_stream = json_document::parse(stream);
        CHECK(from_stream.owns_source());
        CHECK(from_stream.root().materialize() == expected);
        const std::list<char> list(text.begin(), text.end());
        CHECK(json_document::parse(list.begin(), list.end()).owns_source());
        CHECK(json_document::parse(list.begin(), list.end()).root().materialize() == expected);

        // iterator pairs: pointers are borrowed, and so are contiguous library
        // iterators where the input adapter detects them (C++20)
        CHECK(!json_document::parse(text.data(), text.data() + text.size()).owns_source());
        const bool contiguous = nlohmann::detail::iterator_input_adapter<std::vector<char>::const_iterator>::supports_bulk_scan;
        const json_document from_iterators = json_document::parse(chars.cbegin(), chars.cend());
        CHECK(from_iterators.owns_source() != contiguous);
        CHECK((from_iterators.source().data() == chars.data()) == contiguous);
        CHECK(from_iterators.root().materialize() == expected);
        const std::string padded = "x" + text + "x";
        CHECK(json_document::parse(padded.begin() + 1, padded.end() - 1).root().materialize() == expected);
        CHECK(json_document::parse(chars.cbegin(), chars.cbegin(), false).is_discarded());
        const std::wstring wide = L"[\"\u00e4\u20ac\", 1]";
        CHECK(json_document::parse(wide).root().materialize() == json::parse(wide));
        CHECK(json_document::parse(static_cast<const char*>(nullptr), false).is_discarded());
        CHECK(json_document::parse("", false).is_discarded());
    }

    SECTION("document lifetime and reuse")
    {
        json_document d;
        CHECK(d.is_discarded());
        CHECK(d.root().is_discarded());
        CHECK(d.node_count() == 0);
        CHECK(d.memory_usage() == 0);
        CHECK(d.source().empty());

        const std::string a = "[1,2,3]";
        const std::string b = "{\"x\":[true]}";
        d.read(a);
        CHECK(d.node_count() == 4);
        CHECK(d.root().materialize() == json::parse(a));
        d.read(b);
        CHECK(d.node_count() == 4);
        CHECK(d.root().materialize() == json::parse(b));
        d.read("[", false);
        CHECK(d.is_discarded());

        // views stay valid when the document moves
        json_document first = json_document::parse(a);
        const json_view root = first.root();
        const json_document second = std::move(first);
        CHECK(root.materialize() == json::parse(a));
        CHECK(second.root().materialize() == json::parse(a));
    }

    SECTION("memory")
    {
        std::string big = "[";
        for (int i = 0; i < 10000; ++i)
        {
            big += (i != 0 ? ",\"" : "\"") + std::to_string(i) + "\"";
        }
        big += ']';
        json_document d = json_document::parse(big);
        CHECK(d.node_count() == 10001);
        const std::size_t before = d.memory_usage();
        d.shrink_to_fit(); // (invalidates views, like std::vector::shrink_to_fit)
        CHECK(d.memory_usage() <= before);
        CHECK(d.node_count() == 10001);
        CHECK(d.root().materialize() == json::parse(big));
        CHECK(d.root().size() == 10000);
        d.shrink_to_fit(); // nothing left to release

        // after reading a smaller text, both the index and the decoded strings
        // shrink, and the strings are found in their new place
        std::string escaped = "[";
        for (int i = 0; i < 1000; ++i)
        {
            escaped += (i != 0 ? ",\"a\\n" : "\"a\\n") + std::to_string(i) + "\"";
        }
        escaped += ']';
        json_document reused = json_document::parse(escaped);
        const std::string smaller = "[\"x\\ty\", [true, \"\\u00e4\"]]"; // NOLINT(modernize-raw-string-literal)
        reused.read(smaller);
        const std::size_t grown = reused.memory_usage();
        reused.shrink_to_fit();
        CHECK(reused.memory_usage() < grown);
        CHECK(reused.root().materialize() == json::parse(smaller));

        // an empty document has nothing to release
        json_document empty;
        empty.shrink_to_fit();
        CHECK(empty.memory_usage() == 0);

        // a small document stays in the storage block of the header
        json_document small = json_document::parse("[1,[2,3],{\"a\":\"b\\n\"}]"); // NOLINT(modernize-raw-string-literal)
        small.shrink_to_fit();
        CHECK(small.root().materialize() == json::parse("[1,[2,3],{\"a\":\"b\\n\"}]"));
    }

    SECTION("source offsets")
    {
        const std::string text = R"(  {"key": "value", "escaped": "a\nb", "n": 42})";
        const json_document d = json_document::parse(text);
        CHECK(d.root().source_offset() == 2);
        CHECK(d.root()["key"].source_offset() == text.find("value"));
        CHECK(d.root()["escaped"].source_offset() == static_cast<std::size_t>(-1));
        CHECK(d.root()["n"].source_offset() == text.find("42"));
    }
}

namespace
{
// the exception a call throws, or "" if it throws none
template<typename F>
std::string exception_of(F f)
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

// compares a view with the ordered_json value materialize() gives for it:
// types, sizes, elements and members (by index, key, and iteration), in
// document order; duplicate keys are found as their first occurrence
void check_access(const ordered_json_view& v, const ordered_json& j)
{
    REQUIRE(v.type() == j.type());
    CHECK(std::string(v.type_name()) == j.type_name());
    if (v.is_array())
    {
        REQUIRE(v.size() == j.size());
        std::size_t i = 0;
        for (const ordered_json_view e : v)
        {
            CHECK(v[i].materialize() == e.materialize());
            CHECK(v.at(i).materialize() == e.materialize());
            check_access(e, j[i]);
            ++i;
        }
        CHECK(i == v.size());
        CHECK(!v[v.size()]);
        std::size_t index = 0;
        for (const auto& item : v.items())
        {
            CHECK(item.key() == std::to_string(index));
            CHECK(item.value().materialize() == j[index]);
            ++index;
        }
        if (!v.empty())
        {
            CHECK(v.front().materialize() == j.front());
            CHECK(v.back().materialize() == j.back());
        }
    }
    else if (v.is_object())
    {
        std::vector<std::string> keys; // first occurrences, in order
        std::size_t members = 0;
        for (auto it = v.begin(); it != v.end(); ++it)
        {
            ++members;
            const std::string key(it.key().data(), it.key().size());
            CHECK(v.contains(key));
            CHECK(v.count(key) == 1);
            if (std::find(keys.begin(), keys.end(), key) != keys.end())
            {
                continue; // a duplicate: lookups find the first one
            }
            keys.push_back(key);
            CHECK(v.find(key) == it);
            CHECK(v[key].materialize() == it->materialize());
            CHECK(v.at(key).materialize() == it.value().materialize());
            CHECK(v[key.c_str()].materialize() == (*it).materialize());
        }
        CHECK(members == v.size());
        REQUIRE(keys.size() == j.size());
        std::size_t k = 0;
        for (const auto& member : j.items())
        {
            CHECK(keys[k++] == member.key());
        }
        if (keys.size() == members)
        {
            // no duplicates: the values are those of the object
            for (const auto& key : keys)
            {
                check_access(v[key], j[key]);
            }
            if (!v.empty())
            {
                CHECK(v.front().materialize() == j.front());
                CHECK(v.back().materialize() == j.back());
            }
        }
        CHECK(!v["not a key in the generated documents"]);
        CHECK(v.find("not a key in the generated documents") == v.end());
    }
    else
    {
        // a primitive is a range of one element; null is empty
        CHECK(static_cast<std::size_t>(std::distance(v.begin(), v.end())) == (v.is_null() ? 0u : 1u));
        if (!v.is_null())
        {
            CHECK((*v.begin()).materialize() == j);
            CHECK(v.front().materialize() == j);
            CHECK(v.back().materialize() == j);
        }
    }
}
} // namespace

TEST_CASE("json_view element access and iteration")
{
    SECTION("generated documents")
    {
        generator g;
        for (int i = 0; i < 2000; ++i)
        {
            std::string text;
            g.value(text, 0);
            CAPTURE(text);
            const ordered_json_document d = ordered_json_document::parse(text);
            check_access(d.root(), ordered_json::parse(text));
        }
    }

    SECTION("keys")
    {
        // keys of every length around the 2/4/8/16-byte loads, with escapes
        std::string text = "{";
        std::vector<std::string> keys = {"", "x"};
        for (std::size_t n = 1; n <= 40; ++n)
        {
            keys.push_back(std::string(n, 'k'));
            keys.push_back(std::string(n, 'k') + "x");
            keys.push_back("x" + std::string(n, 'k'));
        }
        for (std::size_t i = 0; i < keys.size(); ++i)
        {
            text += (i != 0 ? ",\"" : "\"") + keys[i] + "\":" + std::to_string(i);
        }
        text += ",\"esc\\u0061ped\":\"escaped key\"}";
        const json_document d = json_document::parse(text);
        const json_view root = d.root();
        for (std::size_t i = 0; i < keys.size(); ++i)
        {
            CAPTURE(keys[i]);
            CHECK(root[keys[i]].materialize() == i);
            CHECK(root.at(keys[i]).materialize() == i);
            CHECK(root.find(keys[i]).key() == keys[i]);
            CHECK(!root.contains(keys[i] + "y"));
        }
        CHECK(root["escaped"].materialize() == "escaped key");
        CHECK(!root.contains("esc\\u0061ped"));
#ifdef JSON_HAS_CPP_17
        CHECK(root[std::string_view("kkk")].materialize() == root["kkk"].materialize());
#endif
    }

    SECTION("duplicate keys: lookups find the first member, iteration all")
    {
        const json_document d = json_document::parse(R"({"a":1,"b":2,"a":3})");
        const json_view v = d.root();
        CHECK(v.size() == 3);
        CHECK(v["a"].materialize() == 1);
        CHECK(v.at("a").materialize() == 1);
        CHECK(v.find("a") == v.begin());
        CHECK(v.count("a") == 1);
        std::string order;
        for (auto it = v.begin(); it != v.end(); ++it)
        {
            order += std::string(it.key().data(), it.key().size()) + it->materialize().dump();
        }
        CHECK(order == "a1b2a3");
        CHECK(v.back().materialize() == 3);
        CHECK(v.materialize() == json::parse(R"({"a":1,"b":2,"a":3})")); // the last value, as parse()
    }

    SECTION("errors are those of const basic_json")
    {
        for (const char* text :
                {"null", "true", "42", "-1", "1.5", "\"s\"", "[]", "[1,2]", "{}", "{\"a\":1}"
                })
        {
            CAPTURE(text);
            const json_document d = json_document::parse(text);
            const json_view v = d.root();
            const json j = v.materialize();
            if (!j.is_object())
            {
                CHECK(exception_of([&] { static_cast<void>(v["a"]); }) == exception_of([&] { static_cast<void>(j["a"]); }));
            }
            if (!j.is_array())
            {
                CHECK(exception_of([&] { static_cast<void>(v[0]); }) == exception_of([&] { static_cast<void>(j[0]); }));
            }
            CHECK(exception_of([&] { static_cast<void>(v.at("a")); }) == exception_of([&] { static_cast<void>(j.at("a")); }));
            CHECK(exception_of([&] { static_cast<void>(v.at("missing")); }) == exception_of([&] { static_cast<void>(j.at("missing")); }));
            CHECK(exception_of([&] { static_cast<void>(v.at(0)); }) == exception_of([&] { static_cast<void>(j.at(0)); }));
            CHECK(exception_of([&] { static_cast<void>(v.at(5)); }) == exception_of([&] { static_cast<void>(j.at(5)); }));
            if (!(j.is_object() && j.empty())) // (key() of an end iterator)
            {
                CHECK(exception_of([&] { static_cast<void>(v.begin().key()); }) == exception_of([&] { static_cast<void>(j.begin().key()); }));
            }
            if (!j.empty() || j.is_null())
            {
                CHECK(exception_of([&] { static_cast<void>(v.front()); }) == exception_of([&] { static_cast<void>(j.front()); }));
                CHECK(exception_of([&] { static_cast<void>(v.back()); }) == exception_of([&] { static_cast<void>(j.back()); }));
            }
            CHECK(v.contains("a") == j.contains("a"));
            CHECK(v.count("a") == j.count("a"));
            CHECK((v.find("a") == v.end()) == (j.find("a") == j.end()));
        }

        // where basic_json has undefined behavior, the view answers safely
        const json_document d = json_document::parse(R"({"a":[]})");
        CHECK(!d.root()["b"]);
        CHECK(!d.root()["a"][0]);
        CHECK_THROWS_WITH_AS(d.root()["a"].front(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
        CHECK_THROWS_WITH_AS(d.root()["a"].back(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
        const json_view invalid;
        CHECK(invalid.begin() == invalid.end());
        CHECK(std::string(invalid.type_name()) == "discarded");
        CHECK_THROWS_WITH_AS(invalid["a"], "[json.exception.type_error.305] cannot use operator[] with a string argument with discarded", json::type_error&);
    }

    SECTION("iterators")
    {
        const json_document d = json_document::parse(R"({"x":[1,{"y":2}],"z":null})");
        const json_view v = d.root();
        json_view::iterator it = v.begin();
        CHECK(it.is_object_iterator());
        CHECK(it->is_array());
        CHECK(it->size() == 2);
        const json_view::iterator previous = it++;
        CHECK(previous.key() == "x");
        CHECK(it.key() == "z");
        CHECK(it.value().is_null());
        CHECK(++it == v.end());
        CHECK(v.cbegin() == v.begin());
        CHECK(v.cend() == v.end());
        CHECK(!v["x"].begin().is_object_iterator());
        CHECK(json_view::iterator() == json_view::iterator());
        // standard algorithms
        CHECK(std::count_if(v["x"].begin(), v["x"].end(), [](const json_view & e)
        {
            return e.is_object();
        }) == 1);
    }

    SECTION("items")
    {
        const json_document d = json_document::parse(R"({"a":1,"b":[true,false]})");
        std::string keys;
        for (const auto& item : d.root().items())
        {
            keys += std::string(item.key().data(), item.key().size());
            CHECK(item.value().materialize() == d.root()[item.key()].materialize());
        }
        CHECK(keys == "ab");
        auto items = d.root()["b"].items();
        auto first = items.begin();
        CHECK((*first++).key() == "0");
        CHECK((*first).key() == "1");
        CHECK(++first == items.end());
#ifdef JSON_HAS_CPP_17
        std::string pairs;
        for (const auto [key, value] : d.root().items())
        {
            pairs += std::string(key) + "=" + value.materialize().dump() + ";";
        }
        CHECK(pairs == "a=1;b=[true,false];");
        static_assert(std::tuple_size<json_view::item>::value == 2, "");
        static_assert(std::is_same<std::tuple_element<1, json_view::item>::type, json_view>::value, "");
#endif
    }
}
