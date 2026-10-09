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
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef JSON_HAS_CPP_17
    #include <string_view>
#endif

namespace
{
// the value of a text, through a named document: the views of a temporary
// document would dangle (root() of an rvalue document does not compile)
template<typename Document, typename... Args>
auto materialized(Args&& ... args) -> decltype(std::declval<typename Document::view_type>().materialize())
{
    const Document d = Document::parse(std::forward<Args>(args)...);
    return d.root().materialize();
}

template<typename Document, typename Input>
auto materialized_copy(Input&& input) -> decltype(std::declval<typename Document::view_type>().materialize())
{
    const Document d = Document::parse_copy(std::forward<Input>(input));
    return d.root().materialize();
}

// a "byte container" that claims to hold `size` bytes, to reach the limit on
// the size of the input without allocating gigabytes; nothing past the first
// bytes is ever read, because the size is checked before the parse starts
struct oversized_input
{
    using value_type = char;
    std::size_t claimed;

    const char* data() const
    {
        return "[1]";
    }

    std::size_t size() const
    {
        return claimed;
    }
};

// detection of calls that must not compile
template<typename... Args>
using parse_call_t = decltype(json_document::parse(std::declval<Args>()...));
template<typename... Args>
using parse_copy_call_t = decltype(json_document::parse_copy(std::declval<Args>()...));
template<typename... Args>
using accept_call_t = decltype(json_document::accept(std::declval<Args>()...));
template<typename... Args>
using read_call_t = decltype(std::declval<json_document&>().read(std::declval<Args>()...));
template<typename Document>
using root_call_t = decltype(std::declval<Document>().root());
template<typename View>
using bool_conversion_t = decltype(static_cast<bool>(std::declval<View>()));

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
            CAPTURE(text)
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
            CHECK(v.size() == j.size());
            CHECK(v.empty() == j.empty());
            CHECK(v.materialize() == j);
        }

        const json_view invalid{};
        CHECK(invalid.is_discarded());
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
            CAPTURE(text)
            CHECK(materialized<json_document>(text) == json::parse(text));
            // member order as ordered_json::parse keeps it
            CHECK(materialized<ordered_json_document>(text).dump() == ordered_json::parse(text).dump());
        }
        // duplicate keys: the last value, at the position of the first key
        CHECK(materialized<json_document>(R"({"a":1,"b":2,"a":3})") == json::parse(R"({"a":1,"b":2,"a":3})"));
        CHECK(materialized<ordered_json_document>(R"({"a":1,"b":2,"a":3})").dump() == R"({"a":3,"b":2})");
        // very deep nesting (iterative, as parse())
        const std::string deep = std::string(100000, '[') + std::string(100000, ']');
        CHECK(materialized<json_document>(deep) == json::parse(deep));
#if JSON_DIAGNOSTICS
        // the parents are set, so errors name the path
        const json m = materialized<json_document>(R"({"a":{"b":[1]}})");
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
            CAPTURE(text)
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
            CAPTURE(text)
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
            CAPTURE(text)
            const bool accepted = json_float::accept(text);
            CHECK(float_document::accept(text) == accepted);
            CHECK(float_document::parse(text, false).is_discarded() == !accepted);
            CHECK(json_document::accept(text));
            if (accepted)
            {
                CHECK(materialized<float_document>(text) == json_float::parse(text));
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
        CHECK(materialized<json_document>("\xEF\xBB\xBF[1]") == json::parse("\xEF\xBB\xBF[1]"));
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
        CHECK(materialized<json_document>(text.c_str()) == expected);
        CHECK(materialized<json_document>(R"([1, "two", {"three": 3.5}])") == expected);
        CHECK(materialized<json_document>(text.data(), text.data() + text.size()) == expected);
        const std::vector<char> chars(text.begin(), text.end());
        CHECK(!json_document::parse(chars).owns_source());
        CHECK(materialized<json_document>(chars) == expected);
        const std::vector<std::uint8_t> bytes(text.begin(), text.end());
        CHECK(materialized<json_document>(bytes) == expected);
#ifdef JSON_HAS_CPP_17
        const std::string_view sv = text;
        CHECK(!json_document::parse(sv).owns_source());
        CHECK(materialized<json_document>(sv) == expected);
#endif

        // owned
        std::string moved = text;
        const json_document from_rvalue = json_document::parse(std::move(moved));
        CHECK(from_rvalue.owns_source());
        CHECK(from_rvalue.root().materialize() == expected);
        CHECK(json_document::parse(std::vector<char>(text.begin(), text.end())).owns_source());
        // a const rvalue cannot be moved from, and is not borrowed (it may be a
        // temporary): it is copied, as is a const rvalue of any container
        const std::string const_text = text;
        const json_document from_const_rvalue = json_document::parse(std::move(const_text)); // NOLINT(performance-move-const-arg,hicpp-move-const-arg)
        CHECK(from_const_rvalue.owns_source());
        CHECK(from_const_rvalue.source().data() != const_text.data());
        CHECK(from_const_rvalue.root().materialize() == expected);
        json_document read_const_rvalue;
        read_const_rvalue.read(std::move(const_text)); // NOLINT(performance-move-const-arg,hicpp-move-const-arg)
        CHECK(read_const_rvalue.owns_source());
        CHECK(read_const_rvalue.root().materialize() == expected);
        const std::vector<char> const_chars(text.begin(), text.end());
        CHECK(json_document::parse(std::move(const_chars)).owns_source()); // NOLINT(performance-move-const-arg,hicpp-move-const-arg)
        CHECK(json_document::parse_copy(text).owns_source());
        CHECK(materialized_copy<json_document>(text) == expected);
        std::istringstream stream(text);
        const json_document from_stream = json_document::parse(stream);
        CHECK(from_stream.owns_source());
        CHECK(from_stream.root().materialize() == expected);
        const std::list<char> list(text.begin(), text.end());
        CHECK(json_document::parse(list.begin(), list.end()).owns_source());
        CHECK(materialized<json_document>(list.begin(), list.end()) == expected);

        // iterator pairs: pointers are borrowed, and so are contiguous library
        // iterators where the input adapter detects them (C++20)
        CHECK(!json_document::parse(text.data(), text.data() + text.size()).owns_source());
        const bool contiguous = nlohmann::detail::iterator_input_adapter<std::vector<char>::const_iterator>::supports_bulk_scan;
        const json_document from_iterators = json_document::parse(chars.cbegin(), chars.cend());
        CHECK(from_iterators.owns_source() != contiguous);
        CHECK((from_iterators.source().data() == chars.data()) == contiguous);
        CHECK(from_iterators.root().materialize() == expected);
        const std::string padded = "x" + text + "x";
        CHECK(materialized<json_document>(padded.begin() + 1, padded.end() - 1) == expected);
        CHECK(json_document::parse(chars.cbegin(), chars.cbegin(), false).is_discarded());
        const std::wstring wide = L"[\"\u00e4\u20ac\", 1]";
        CHECK(materialized<json_document>(wide) == json::parse(wide));
        CHECK(json_document::parse(static_cast<const char*>(nullptr), false).is_discarded());
        CHECK(json_document::parse("", false).is_discarded());
    }

    SECTION("integer arguments do not compile")
    {
        using nlohmann::detail::is_detected;

        // a length is not a flag: parse(ptr, len) would convert len to
        // allow_exceptions and read ptr as a C string, which need not end
        static_assert(is_detected<parse_call_t, const char*, bool>::value, "parse(ptr, bool) is valid");
        static_assert(is_detected<parse_call_t, const char*, bool, bool, bool>::value, "parse(ptr, bool, bool, bool) is valid");
        static_assert(is_detected<parse_call_t, const char*, const char*>::value, "parse(first, last) is valid");
        static_assert(is_detected<parse_call_t, const char*, const char*, bool>::value, "parse(first, last, bool) is valid");
        static_assert(!is_detected<parse_call_t, const char*, std::size_t>::value, "parse(ptr, len) must not compile");
        static_assert(!is_detected<parse_call_t, const char*, int>::value, "parse(ptr, int) must not compile");
        static_assert(!is_detected<parse_call_t, const char*, char>::value, "parse(ptr, char) must not compile");
        static_assert(!is_detected<parse_call_t, const char*, std::size_t, bool>::value, "parse(ptr, len, bool) must not compile");
        static_assert(!is_detected<parse_call_t, const std::string&, std::size_t>::value, "parse(string, len) must not compile");
        static_assert(!is_detected<parse_call_t, const std::vector<char>&, std::size_t>::value, "parse(vector, len) must not compile");

        static_assert(is_detected<parse_copy_call_t, const char*, bool>::value, "parse_copy(ptr, bool) is valid");
        static_assert(!is_detected<parse_copy_call_t, const char*, std::size_t>::value, "parse_copy(ptr, len) must not compile");

        static_assert(is_detected<accept_call_t, const char*, bool>::value, "accept(ptr, bool) is valid");
        static_assert(!is_detected<accept_call_t, const char*, std::size_t>::value, "accept(ptr, len) must not compile");

        static_assert(is_detected<read_call_t, const char*, bool>::value, "read(ptr, bool) is valid");
        static_assert(!is_detected<read_call_t, const char*, std::size_t>::value, "read(ptr, len) must not compile");

        // json_view has no conversion to bool: unlike basic_json's, it would
        // mean "exists", not "is not null"; use is_discarded()
        static_assert(!is_detected<bool_conversion_t, json_view>::value, "json_view must not convert to bool");

        // the valid calls still work
        const char* const text = "[1]";
        CHECK(materialized<json_document>(text, true) == json::parse(text));
        CHECK(json_document::accept(text, true, true));
    }

    SECTION("root of a temporary document does not compile")
    {
        using nlohmann::detail::is_detected;

        // the view would dangle: auto v = json_document::parse(text).root();
        static_assert(is_detected<root_call_t, json_document&>::value, "root() of an lvalue is valid");
        static_assert(is_detected<root_call_t, const json_document&>::value, "root() of a const lvalue is valid");
        static_assert(!is_detected<root_call_t, json_document>::value, "root() of an rvalue must not compile");
        static_assert(!is_detected < root_call_t, json_document && >::value, "root() of an rvalue must not compile");
        static_assert(!is_detected < root_call_t, const json_document && >::value, "root() of a const rvalue must not compile");
        static_assert(!is_detected<root_call_t, ordered_json_document>::value, "root() of an rvalue must not compile");

        // a named document is fine, also after a move
        json_document d = json_document::parse("[1]");
        CHECK(d.root().size() == 1);
        const json_document moved = std::move(d);
        CHECK(moved.root().size() == 1);
    }

    SECTION("input size limit")
    {
        // 32-bit offsets: the limit is 4 GiB minus 16 bytes (a margin below 2^32),
        // which is what the exception message and the documentation say
        const std::size_t limit = nlohmann::detail::view::max_input_size;
        CHECK(limit == std::size_t{4294967279u});

        const oversized_input input{limit + 1};
        CHECK(!json_document::accept(input));
        CHECK(json_document::parse(input, false).is_discarded());
#if !defined(JSON_NOEXCEPTION)
        json_document d;
        CHECK_THROWS_WITH_AS(d = json_document::parse(input), "[json.exception.out_of_range.416] input of 4294967280 bytes or more is not supported by json_document", json::out_of_range&);
#endif
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
#if !defined(JSON_NOEXCEPTION)
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
#endif

// compares a view with the ordered_json value materialize() gives for it:
// types, sizes, elements and members (by index, key, and iteration), in
// document order; duplicate keys are found as their last occurrence
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
        CHECK(v[v.size()].is_discarded());
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
            if (std::find(keys.begin(), keys.end(), key) == keys.end())
            {
                keys.push_back(key);
            }
            // lookups find the last member with the key, which is this one if
            // there is no later one
            auto next = it;
            ++next;
            bool is_last = true;
            for (; next != v.end(); ++next)
            {
                is_last = is_last && next.key() != it.key();
            }
            if (!is_last)
            {
                continue;
            }
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
        CHECK(v["not a key in the generated documents"].is_discarded());
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
            CAPTURE(text)
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
            keys.emplace_back(n, 'k');
            keys.push_back(std::string(n, 'k') + "x");
            keys.push_back("x" + std::string(n, 'k'));
        }
        for (std::size_t i = 0; i < keys.size(); ++i)
        {
            text += (i != 0 ? ",\"" : "\"") + keys[i] + "\":" + std::to_string(i);
        }
        text += ",\"esc\\u0061ped\":\"escaped key\"}"; // NOLINT(modernize-raw-string-literal)
        const json_document d = json_document::parse(text);
        const json_view root = d.root();
        for (std::size_t i = 0; i < keys.size(); ++i)
        {
            CAPTURE(keys[i])
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

    SECTION("duplicate keys: lookups find the last member, iteration all")
    {
        const json_document d = json_document::parse(R"({"a":1,"b":2,"a":3})");
        const json_view v = d.root();
        CHECK(v.size() == 3);
        CHECK(v["a"].materialize() == 3);
        CHECK(v.at("a").materialize() == 3);
        CHECK(v.find("a") == std::next(v.begin(), 2));
        CHECK(v.find("a").value().materialize() == 3);
        CHECK(v.find("b") == std::next(v.begin()));
        CHECK(v.count("a") == 1);
        CHECK(v.contains("a"));
        CHECK(v.value("a", 0) == 3);
        CHECK(v["a"].materialize() == v.materialize()["a"]); // as materialize()
        // keys of every length class (the 16-byte short compare and memcmp)
        for (const std::size_t n :
                {
                    0u, 1u, 3u, 7u, 8u, 15u, 16u, 17u, 40u
                })
        {
            const std::string key(n, 'k');
            const json_document dk = json_document::parse("{\"" + key + "\":1,\"" + key + "x\":2,\"" + key + "\":3,\"" + key + "\":4}");
            CAPTURE(n)
            CHECK(dk.root()[key].materialize() == 4);
            CHECK(dk.root().at(key).materialize() == 4);
            CHECK(dk.root().find(key) == std::next(dk.root().begin(), 3));
            CHECK(dk.root().value(key, 0) == 4);
            CHECK(dk.root()[key + "x"].materialize() == 2);
        }
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
            CAPTURE(text)
            const json_document d = json_document::parse(text);
            const json_view v = d.root();
            const json j = v.materialize();
#if !defined(JSON_NOEXCEPTION)
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
#endif
            CHECK(v.contains("a") == j.contains("a"));
            CHECK(v.count("a") == j.count("a"));
            CHECK((v.find("a") == v.end()) == (j.find("a") == j.end())); // NOLINT(readability-container-contains): find() is what is tested
        }

        // where basic_json has undefined behavior, the view answers safely
        const json_document d = json_document::parse(R"({"a":[]})");
        CHECK(d.root()["b"].is_discarded());
        CHECK(d.root()["a"][0].is_discarded());
        CHECK_THROWS_WITH_AS(d.root()["a"].front(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
        CHECK_THROWS_WITH_AS(d.root()["a"].back(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
        const json_view invalid{};
        CHECK(invalid.begin() == invalid.end());
        CHECK(std::string(invalid.type_name()) == "discarded");
    }

    SECTION("chained access is safe: operator[] of a discarded view is discarded")
    {
        const json_document d = json_document::parse(R"({"a":{"b":[10,20]},"s":"str"})");
        const json_view v = d.root();
        // missing keys and indexes
        CHECK(v["x"].is_discarded());
        CHECK(v["x"]["y"].is_discarded());
        CHECK(v["x"]["y"]["z"].is_discarded());
        CHECK(v["x"][0].is_discarded());
        CHECK(v["x"][0u][1L].is_discarded());
        CHECK(v["a"]["b"][2].is_discarded());
        CHECK(v["a"]["b"][2]["c"].is_discarded());
        CHECK(v["a"]["b"][2][json_view::json_pointer("/c")].is_discarded());
        CHECK(v["x"][json_view::json_pointer("/a/b")].is_discarded());
        CHECK(v["x"][json_view::json_pointer("")].is_discarded());
        CHECK(v["x"]["y"].is_discarded());
        CHECK(v["x"][std::string("y")].is_discarded());
        // a resolvable path still resolves
        CHECK(v["a"]["b"][1].materialize() == 20);
        CHECK(v[json_view::json_pointer("/a/b/1")].materialize() == 20);
        // the discarded view of an unresolved pointer is discarded too
        CHECK(v[json_view::json_pointer("/x/y")]["z"].is_discarded());
        CHECK(v[json_view::json_pointer("/a/b/5")][0].is_discarded());
#if !defined(JSON_NOEXCEPTION)
        // type errors on values that are not discarded stay
        CHECK_THROWS_WITH_AS(v[0], "[json.exception.type_error.305] cannot use operator[] with a numeric argument with object", json::type_error&);
        CHECK_THROWS_WITH_AS(v["a"]["b"]["c"], "[json.exception.type_error.305] cannot use operator[] with a string argument with array", json::type_error&);
        CHECK_THROWS_WITH_AS(v["s"]["c"], "[json.exception.type_error.305] cannot use operator[] with a string argument with string", json::type_error&);
        CHECK_THROWS_WITH_AS(v["s"][0], "[json.exception.type_error.305] cannot use operator[] with a numeric argument with string", json::type_error&);
        CHECK_THROWS_AS(v["a"]["b"][0]["c"], json::type_error&);
        CHECK_THROWS_AS(v["s"][json_view::json_pointer("/x")], json::out_of_range&);
        // at() keeps throwing on a discarded view
        const json_view invalid{};
        CHECK(invalid["a"].is_discarded());
        CHECK(invalid[0].is_discarded());
        CHECK(invalid[json_view::json_pointer("/a")].is_discarded());
        CHECK_THROWS_WITH_AS(invalid.at("a"), "[json.exception.type_error.304] cannot use at() with discarded", json::type_error&);
        CHECK_THROWS_WITH_AS(invalid.at(0), "[json.exception.type_error.304] cannot use at() with discarded", json::type_error&);
        CHECK_THROWS_AS(v.at("x").at("y"), json::out_of_range&);
        CHECK_THROWS_AS(v["x"].at("y"), json::type_error&);
        CHECK_THROWS_AS(v.at(json_view::json_pointer("/x/y")), json::out_of_range&);
        CHECK_THROWS_AS(v["x"].at(json_view::json_pointer("/y")), json::out_of_range&);
#endif
    }

    SECTION("integer types as array indexes")
    {
        const json_document d = json_document::parse("[10,20,30]");
        const json_view v = d.root();
        const json j = v.materialize();
        // (compile-time: no overload is ambiguous)
        CHECK(v[0].materialize() == 10);
        CHECK(v[1].materialize() == 20);
        CHECK(v[0u].materialize() == 10);
        CHECK(v[1u].materialize() == 20);
        CHECK(v[1L].materialize() == 20);
        CHECK(v[2UL].materialize() == 30);
        CHECK(v[1LL].materialize() == 20);
        CHECK(v[2ULL].materialize() == 30);
        CHECK(v[static_cast<short>(1)].materialize() == 20);
        CHECK(v[static_cast<unsigned short>(2)].materialize() == 30);
        CHECK(v[static_cast<signed char>(1)].materialize() == 20);
        CHECK(v[static_cast<unsigned char>(2)].materialize() == 30);
        CHECK(v[std::int8_t(1)].materialize() == 20);
        CHECK(v[std::int16_t(2)].materialize() == 30);
        CHECK(v[std::int32_t(1)].materialize() == 20);
        CHECK(v[std::int64_t(2)].materialize() == 30);
        CHECK(v[std::uint32_t(0)].materialize() == 10);
        CHECK(v[std::uint64_t(1)].materialize() == 20);
        CHECK(v[std::size_t(2)].materialize() == 30);
        CHECK(v[std::ptrdiff_t(1)].materialize() == 20);
        CHECK(j[0u] == 10); // as basic_json

        CHECK(v.at(0).materialize() == 10);
        CHECK(v.at(1u).materialize() == 20);
        CHECK(v.at(1L).materialize() == 20);
        CHECK(v.at(2LL).materialize() == 30);
        CHECK(v.at(2ULL).materialize() == 30);
        CHECK(v.at(static_cast<short>(1)).materialize() == 20);
        CHECK(v.at(static_cast<unsigned short>(2)).materialize() == 30);
        CHECK(v.at(std::int32_t(0)).materialize() == 10);
        CHECK(v.at(std::uint32_t(0)).materialize() == 10);
        CHECK(v.at(std::int64_t(0)).materialize() == 10);
        CHECK(v.at(std::uint64_t(1)).materialize() == 20);
        CHECK(v.at(std::size_t(2)).materialize() == 30);
        CHECK(j.at(std::uint32_t(0)) == 10); // as basic_json

        // out of range, including negative values (no wrap-around)
        CHECK(v[3].is_discarded());
        CHECK(v[3u].is_discarded());
        CHECK(v[3L].is_discarded());
        CHECK(v[-1].is_discarded());
        CHECK(v[-1L].is_discarded());
        CHECK(v[-1LL].is_discarded());
        CHECK(v[static_cast<short>(-1)].is_discarded());
        CHECK(v[std::int64_t(-3)].is_discarded());
        CHECK(v[(std::numeric_limits<std::int64_t>::min)()].is_discarded());
        CHECK(v[(std::numeric_limits<std::uint64_t>::max)()].is_discarded());
        CHECK(v[(std::numeric_limits<std::size_t>::max)()].is_discarded());
        CHECK(v[std::numeric_limits<int>::max()].is_discarded());
#if !defined(JSON_NOEXCEPTION)
        CHECK_THROWS_WITH_AS(v.at(3), "[json.exception.out_of_range.401] array index 3 is out of range", json::out_of_range&);
        CHECK_THROWS_WITH_AS(v.at(3u), "[json.exception.out_of_range.401] array index 3 is out of range", json::out_of_range&);
        CHECK_THROWS_WITH_AS(v.at(std::int64_t(3)), "[json.exception.out_of_range.401] array index 3 is out of range", json::out_of_range&);
        CHECK_THROWS_AS(v.at(-1), json::out_of_range&);
        CHECK_THROWS_AS(v.at(-1L), json::out_of_range&);
        CHECK_THROWS_AS(v.at(std::int64_t(-1)), json::out_of_range&);
        CHECK_THROWS_AS(v.at((std::numeric_limits<std::int64_t>::min)()), json::out_of_range&);
        CHECK_THROWS_AS(v.at((std::numeric_limits<std::uint64_t>::max)()), json::out_of_range&);
        // not an array
        const json_document o = json_document::parse("{}");
        CHECK_THROWS_AS(o.root()[0u], json::type_error&);
        CHECK_THROWS_AS(o.root()[1L], json::type_error&);
        CHECK_THROWS_AS(o.root().at(std::uint32_t(0)), json::type_error&);
        CHECK_THROWS_AS(o.root().at(std::int64_t(0)), json::type_error&);
#endif
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

namespace
{
#if !defined(JSON_NOEXCEPTION)
// an exception message without the context that basic_json adds with
// JSON_DIAGNOSTICS ("(/path) ") and JSON_DIAGNOSTIC_POSITIONS ("(bytes 1-2) ");
// the view's exceptions have no such context
std::string without_path(std::string msg)
{
    for (const char* prefix :
            {"] (/", "] (bytes "
            })
    {
        const std::size_t open = msg.find(prefix);
        if (open != std::string::npos)
        {
            msg.erase(open + 2, msg.find(") ", open) + 2 - (open + 2));
        }
    }
    return msg;
}
#endif

// the bits of a float, to compare values bit for bit
std::uint64_t bits(double x)
{
    std::uint64_t r = 0;
    std::memcpy(&r, &x, sizeof(r));
    return r;
}

std::uint32_t bits(float x)
{
    std::uint32_t r = 0;
    std::memcpy(&r, &x, sizeof(r));
    return r;
}

bool has_duplicate_keys(const ordered_json_view& v)
{
    if (v.is_object() && v.size() != v.materialize().size())
    {
        return true;
    }
    return std::any_of(v.begin(), v.end(), [](const ordered_json_view e)
    {
        return e.is_structured() && has_duplicate_keys(e);
    });
}

// compares the conversions of a view with those of ordered_json
void check_values(const ordered_json_view& v, const ordered_json& j, const std::string& text)
{
    CHECK(v.get<ordered_json>() == j);
    switch (j.type())
    {
        case json::value_t::number_integer:
        case json::value_t::number_unsigned:
        case json::value_t::number_float:
        {
            // (converting a float out of range of the target type is undefined)
            if (j.is_number_unsigned())
            {
                CHECK(v.get<std::uint64_t>() == j.get<std::uint64_t>());
            }
            else if (j.is_number_integer())
            {
                CHECK(v.get<std::int64_t>() == j.get<std::int64_t>());
            }
            CHECK(bits(v.get<double>()) == bits(j.get<double>()));
            if (std::abs(j.get<double>()) < 1e9)
            {
                CHECK(v.get<int>() == j.get<int>());
            }
            const auto token = v.number_token();
            CHECK(text.compare(v.source_offset(), token.size(), token.data(), token.size()) == 0);
            break;
        }
        case json::value_t::string:
            CHECK(v.get<std::string>() == j.get<std::string>());
            CHECK(std::string(v.get_string().data(), v.get_string().size()) == j.get<std::string>());
            break;
        case json::value_t::boolean:
            CHECK(v.get<bool>() == j.get<bool>());
            CHECK(v.get<int>() == j.get<int>());
            break;
        case json::value_t::null:
            CHECK(v.get<std::nullptr_t>() == nullptr);
            break;
        case json::value_t::array:
            CHECK(v.get<std::vector<ordered_json>>() == j.get<std::vector<ordered_json>>());
            break;
        case json::value_t::object:
            CHECK((v.get<std::map<std::string, ordered_json>>() == j.get<std::map<std::string, ordered_json>>()));
            break;
        case json::value_t::binary:
        case json::value_t::discarded:
        default:
            break;
    }

#if !defined(JSON_NOEXCEPTION)
    // conversions to the wrong type throw what basic_json throws
    if (!j.is_number())
    {
        CHECK(exception_of([&] { static_cast<void>(v.get<int>()); }) == without_path(exception_of([&] { static_cast<void>(j.get<int>()); })));
    }
    CHECK(exception_of([&] { static_cast<void>(v.get<bool>()); }) == without_path(exception_of([&] { static_cast<void>(j.get<bool>()); })));
    CHECK(exception_of([&] { static_cast<void>(v.get<std::string>()); }) == without_path(exception_of([&] { static_cast<void>(j.get<std::string>()); })));
    CHECK(exception_of([&] { static_cast<void>(v.get<std::nullptr_t>()); }) == without_path(exception_of([&] { static_cast<void>(j.get<std::nullptr_t>()); })));
    if (!j.is_array())
    {
        CHECK(exception_of([&] { static_cast<void>(v.get<std::vector<int>>()); }) == without_path(exception_of([&] { static_cast<void>(j.get<std::vector<int>>()); })));
    }
    if (!j.is_object())
    {
        CHECK(exception_of([&] { static_cast<void>(v.get<std::map<std::string, int>>()); }) == without_path(exception_of([&] { static_cast<void>(j.get<std::map<std::string, int>>()); })));
    }
#endif

    if (v.is_array())
    {
        std::size_t i = 0;
        for (const ordered_json_view e : v)
        {
            check_values(e, j[i++], text);
        }
    }
    else if (v.is_object())
    {
        for (auto it = v.begin(); it != v.end(); ++it)
        {
            const std::string key(it.key().data(), it.key().size());
            if (v.size() == j.size()) // (no duplicate keys)
            {
                check_values(it.value(), j[key], text);
            }
        }
    }
}

struct record
{
    std::string name{}; // NOLINT(readability-redundant-member-init)
    int count = 0;
};

void from_json(const json& j, record& r)
{
    j.at("name").get_to(r.name);
    j.at("count").get_to(r.count);
}
} // namespace

TEST_CASE("json_view values")
{
    SECTION("generated documents")
    {
        generator g;
        for (int i = 0; i < 2000; ++i)
        {
            std::string text;
            g.value(text, 0);
            CAPTURE(text)
            const ordered_json_document d = ordered_json_document::parse(text);
            check_values(d.root(), ordered_json::parse(text), text);
        }
    }

    SECTION("floats are converted as parse() converts them")
    {
        std::mt19937_64 rng(5295); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
        std::vector<std::string> tokens = {"0.1", "-0.0", "1e308", "1.7976931348623157e308", "2.2250738585072011e-308", "4.9e-324", "5e-324",
                                           "0.1000000000000000055511151231257827021181583404541015625", "123456789012345678901234567890",
                                           "9007199254740993", "1.00000000000000011102230246251565404236316680908203125", "7.2057594037927933e16",
                                           // around the limits of the conversion from the digit layout: 19 and 20
                                           // digits, and those of Clinger's fast path (2^53, 10^22)
                                           "1234567890.123456789", "1234567890.1234567891", "0.0000000000000000001", "123456789012345678.9",
                                           "9007199254740992.0", "9007199254740993.0", "9007199254740994.0", "1.5e22", "1.5e23", "15e-22", "15e-23",
                                           "1e-400", "0.0e0", "-0.0e-5", "12E+3", "12e-0",
                                           // and of float: 2^24 + 1 and 2^24 + 3 (ties), the subnormal and normal limits
                                           "16777217", "16777219", "1.4e-45", "7.006492321624085e-46", "7.006492321624086e-46",
                                           "1.17549435e-38", "0.30000001192092896", "3.4028234e37"
                                          };
        for (int i = 0; i < 20000; ++i)
        {
            const std::uint64_t bits = rng();
            double d = 0;
            std::memcpy(&d, &bits, sizeof(d));
            if (!std::isfinite(d))
            {
                continue;
            }
            std::array<char, 400> buf{};
            switch (i % 5) // NOLINT(hicpp-multiway-paths-covered)
            {
                case 0:
                    std::snprintf(buf.data(), buf.size(), "%.17g", d); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
                    break;
                case 1:
                    std::snprintf(buf.data(), buf.size(), "%.15g", d); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
                    break;
                case 2:
                    std::snprintf(buf.data(), buf.size(), "%.3e", d); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
                    break;
                case 3:
                    std::snprintf(buf.data(), buf.size(), "%.25g", d); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
                    break;
                default:
                    std::snprintf(buf.data(), buf.size(), "%.0f", d); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
                    break;
            }
            tokens.emplace_back(buf.data());
        }
        using json_float = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;
        for (const auto& token : tokens)
        {
            CAPTURE(token)
            const std::string text = "[" + token + "]";
            const double b = json::parse(text)[0].get<double>();
            const json_document dd = json_document::parse(text);
            CHECK(bits(dd.root()[0].get<double>()) == bits(b));
            if (std::abs(b) < 1e38)
            {
                const nlohmann::basic_json_document<json_float> df = nlohmann::basic_json_document<json_float>::parse(text);
                CHECK(bits(df.root()[0].get<float>()) == bits(json_float::parse(text)[0].get<float>()));
            }
        }
    }

    SECTION("number tokens")
    {
        const json_document d = json_document::parse(R"([1.50, 1E2, -0, 123456789012345678901234567890, -12, 7, "x"])");
        const json_view v = d.root();
        CHECK(v[0].number_token() == "1.50");
        CHECK(v[1].number_token() == "1E2");
        CHECK(v[2].number_token() == "-0");
        CHECK(v[3].number_token() == "123456789012345678901234567890");
        CHECK(v[4].number_token() == "-12");
        CHECK(v[5].number_token() == "7");
        CHECK_THROWS_WITH_AS(v[6].number_token(), "[json.exception.type_error.302] type must be number, but is string", json::type_error&);
        CHECK_THROWS_WITH_AS(v.get_string(), "[json.exception.type_error.302] type must be string, but is array", json::type_error&);
    }

    SECTION("conversions")
    {
        const std::string text = R"({"name": "widget", "count": 3, "tags": ["a", "b\n"], "sizes": {"s": 1, "m": 2}, "pair": [1, "x"]})";
        const json_document d = json_document::parse(text);
        const json_view v = d.root();
        const json j = json::parse(text);

        // user types with from_json, and other types, through basic_json
        const record r = v.get<record>();
        CHECK(r.name == "widget");
        CHECK(r.count == 3);
        CHECK((v["pair"].get<std::pair<int, std::string>>() == j["pair"].get<std::pair<int, std::string>>()));
        CHECK(v["tags"].get<std::list<std::string>>() == j["tags"].get<std::list<std::string>>());
        CHECK((v["sizes"].get<std::unordered_map<std::string, int>>() == j["sizes"].get<std::unordered_map<std::string, int>>()));
        CHECK(v["tags"].get<std::vector<std::string>>() == std::vector<std::string> {"a", "b\n"});

        // views of the elements
        const auto views = v["tags"].get<std::vector<json_view>>();
        CHECK(views.size() == 2);
        CHECK(views[1].get_string() == "b\n");
        const auto members = v.get<std::map<std::string, json_view>>();
        CHECK(members.at("count").get<int>() == 3);
        CHECK(v.get<json_view>()["name"].get_string() == "widget");

        // strings without a copy point into the source text
        CHECK(v["name"].get_string().data() == text.data() + text.find("widget"));
#ifdef JSON_HAS_CPP_17
        CHECK(v["name"].get<std::string_view>() == "widget");
#endif

        std::string name;
        int count = 0;
        CHECK(&v["name"].get_to(name) == &name);
        v["count"].get_to(count);
        CHECK(name == "widget");
        CHECK(count == 3);

        // a duplicate key: the last value, as parse()
        const json_document dup = json_document::parse(R"({"a":1,"a":2})");
        CHECK((dup.root().get<std::map<std::string, int>>() == std::map<std::string, int> {{"a", 2}}));

        const json_view invalid{};
        CHECK_THROWS_WITH_AS(invalid.get<int>(), "[json.exception.type_error.302] type must be number, but is discarded", json::type_error&);
        CHECK(invalid.get<json>().is_discarded());
    }

    SECTION("value")
    {
        const json_document d = json_document::parse(R"({"n": 1, "s": "text", "o": {"x": [10, 20]}})");
        const json_view v = d.root();
        const json j = v.materialize();
        CHECK(v.value("n", 0) == j.value("n", 0));
        CHECK(v.value("missing", 42) == j.value("missing", 42));
        CHECK(v.value("s", "default") == j.value("s", "default"));
        CHECK(v.value("missing", "default") == j.value("missing", "default"));
        CHECK(v.value(std::string("n"), 2.5) == j.value(std::string("n"), 2.5));
        CHECK(v.value(json::json_pointer("/o/x/1"), 0) == j.value(json::json_pointer("/o/x/1"), 0));
        CHECK(v.value(json::json_pointer("/o/x/5"), 0) == j.value(json::json_pointer("/o/x/5"), 0));
        CHECK(v.value(json::json_pointer("/o/y"), "none") == j.value(json::json_pointer("/o/y"), "none"));
        // with a JSON pointer, arrays can be asked as well
        CHECK(v["o"]["x"].value(json::json_pointer("/1"), 0) == j["o"]["x"].value(json::json_pointer("/1"), 0));
        CHECK(v["o"]["x"].value(json::json_pointer("/7"), 3) == j["o"]["x"].value(json::json_pointer("/7"), 3));
#if !defined(JSON_NOEXCEPTION)
        CHECK(exception_of([&] { static_cast<void>(v["o"]["x"].value("k", 0)); }) == without_path(exception_of([&] { static_cast<void>(j["o"]["x"].value("k", 0)); })));
        CHECK(exception_of([&] { static_cast<void>(v.value("s", 0)); }) == without_path(exception_of([&] { static_cast<void>(j.value("s", 0)); })));
        CHECK(exception_of([&] { static_cast<void>(v["n"].value("x", 0)); }) == without_path(exception_of([&] { static_cast<void>(j["n"].value("x", 0)); })));
        CHECK(exception_of([&] { static_cast<void>(v["n"].value(json::json_pointer("/x"), 0)); }) == without_path(exception_of([&] { static_cast<void>(j["n"].value(json::json_pointer("/x"), 0)); })));
#endif
    }
}

TEST_CASE("json_view JSON pointers")
{
    SECTION("every value of generated documents")
    {
        generator g;
        for (int i = 0; i < 1000; ++i)
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
            const ordered_json flat = j.flatten();
            for (const auto& leaf : flat.items())
            {
                // the leaf and each of its parents
                for (ordered_json::json_pointer p(leaf.key());; p = p.parent_pointer())
                {
                    CAPTURE(p.to_string())
                    CHECK(d.root()[p].materialize() == j[p]);
                    CHECK(d.root().at(p).materialize() == j.at(p));
                    CHECK(d.root().contains(p));
                    if (p.empty())
                    {
                        break;
                    }
                }
            }
        }
    }

#if !defined(JSON_NOEXCEPTION)
    SECTION("errors are those of basic_json")
    {
        const std::string text = R"({"a": [1, {"b": null}], "c": "s", "": {"": 0}, "a~b": 1, "c/d": 2})";
        const json_document d = json_document::parse(text);
        const json_view v = d.root();
        const json j = v.materialize();
        for (const char* pointer :
                {"", "/", "//", "/a", "/a/0", "/a/1/b", "/a/-", "/a/01", "/a/00", "/a/1a", "/a/a", "/a/", "/a/2", "/a/99", "/a/99999999999999999999",
                 "/a/18446744073709551615", "/a/-1", "/a/+1", "/a/ 1", "/x", "/c/x", "/a/0/x", "/a/1/b/c", "/a~0b", "/c~1d", "/c~1d/x", "/a/1/-"
                })
        {
            CAPTURE(pointer)
            const json::json_pointer p(pointer);
            const std::string at_error = without_path(exception_of([&] { static_cast<void>(j.at(p)); }));
            CHECK(exception_of([&] { static_cast<void>(v.at(p)); }) == at_error);
            if (at_error.empty())
            {
                CHECK(v.at(p).materialize() == j.at(p));
                CHECK(v[p].materialize() == j[p]);
            }
            else if (at_error.find("out_of_range.401") != std::string::npos || at_error.find("out_of_range.403") != std::string::npos) // NOLINT(abseil-string-find-str-contains)
            {
                // undefined behavior for const basic_json::operator[]
                CHECK(v[p].is_discarded());
            }
            else
            {
                CHECK(exception_of([&] { static_cast<void>(v[p]); }) == without_path(exception_of([&] { static_cast<void>(j[p]); })));
            }
            // (basic_json::contains() throws out_of_range.404 for an empty
            // array index token, although it is not meant to throw; the view
            // answers false)
            const std::string contains_error = exception_of([&]
            {
                const bool found = j.contains(p);
                static_cast<void>(found);
            });
            CHECK(v.contains(p) == (contains_error.empty() && j.contains(p)));
            CHECK(exception_of([&] { static_cast<void>(v.value(p, 5)); }) == without_path(exception_of([&] { static_cast<void>(j.value(p, 5)); })));
        }
    }
#endif
}

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
            CHECK(json_document::parse(many_tokens).root().dump() == json::parse(many_tokens).dump());
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
        const json_document d = json_document::parse("{\"a\":\"" + chars + R"(","k\n":1})");
        const json expected = json::parse("\"" + chars + "\"");
        CHECK(d.root()["a"].dump(-1, ' ', true) == expected.dump(-1, ' ', true));
        CHECK(d.root()["a"].dump(-1, ' ', true).size() == 2 + 5000 * 6);
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
        const ordered_json_document ab = ordered_json_document::parse(R"({"a": 1, "b": 2})");
        const ordered_json_document ba = ordered_json_document::parse(R"({"b": 2, "a": 1})");
        CHECK(ab.root() != ba.root());

        // discarded values compare as basic_json's do
        const json discarded(json::value_t::discarded);
        CHECK((json_view() == json_view()) == (discarded == discarded)); // NOLINT(readability-container-size-empty): operator== is tested
        CHECK((json_view() == discarded) == (discarded == discarded));
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
            CHECK(v.contains(key));
            CHECK(v.find(key).key() == key);
            CHECK(!v.contains(key + "x"));
            if (key == "k1")
            {
                continue; // repeated below: the last member wins
            }
            CHECK(v[key].get<std::size_t>() == i);
            CHECK(v.at(key).get<std::size_t>() == i);
        }
        CHECK(v[""].get_string() == "empty key");
        CHECK(v["k1"].get_string() == "a duplicate of an earlier key"); // the last of duplicate keys, as for small objects
        CHECK(v.at("k1").get_string() == "a duplicate of an earlier key");
        CHECK(!v.contains("missing"));
        CHECK_THROWS_WITH_AS(v.at("missing"), "[json.exception.out_of_range.403] key 'missing' not found", json::out_of_range&);
        CHECK(v == j);
        CHECK(v.materialize() == j);
    }

    SECTION("duplicate keys: the last member wins, with and without a table")
    {
        // an object of `total` members: the keys "k0".."k<n-1>" in order, then
        // three keys repeated twice more (one copy in the middle, one at the
        // end), and two keys repeated once; the value of a member is its
        // position, so that the last member of a key can be told apart
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
            std::map<std::string, std::size_t> last;
            for (const member& m : members)
            {
                text += (text.size() > 1 ? ",\"" : "\"") + m.key + "\":" + std::to_string(m.position);
                last[m.key] = m.position;
            }
            text += '}';
            REQUIRE(last.size() < members.size());

            const json_document d = json_document::parse(text);
            const json_view v = d.root();
            const json j = json::parse(text);
            CHECK(v.size() == members.size()); // every occurrence is visited
            for (const auto& entry : last)
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
                CHECK(j[entry.first].get<std::size_t>() == expected); // as materialize() and parse() keep it
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
            for (std::uint64_t x = counter, i = 0; i < 8; ++i, x /= 26)
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
                for (int i = 0; i < members + object; ++i)
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
            for (int i = 0; i < 150 + object; ++i)
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
