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

#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <type_traits>
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

    const char* data() const // NOLINT(readability-convert-member-functions-to-static): container interface
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
        // (one check per step, so that a failure shows which step it is)
        const json_document deep_document = json_document::parse(deep);
        CHECK(deep_document.root().is_array());
        const json deep_value = deep_document.root().materialize();
        CHECK(deep_value.is_array());
        const json deep_parsed = json::parse(deep);
        CHECK(deep_parsed.is_array());
        CHECK(deep_value == deep_parsed);
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
        const std::string const_text = text; // NOLINT(performance-unnecessary-copy-initialization)
        const json_document from_const_rvalue = json_document::parse(std::move(const_text)); // NOLINT(performance-move-const-arg,hicpp-move-const-arg)
        CHECK(from_const_rvalue.owns_source());
        CHECK(from_const_rvalue.source().data() != const_text.data()); // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved): const, not moved from
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
        const std::size_t limit = nlohmann::detail::view::max_input_size();
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
        // (element access comes with a later change; the offsets of the
        // string nodes are checked through materialize() above)
    }
}
