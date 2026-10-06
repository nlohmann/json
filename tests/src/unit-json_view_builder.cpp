//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
#if JSON_TEST_USING_MULTIPLE_HEADERS
    #include <nlohmann/detail/view/builder.hpp>
    #include <nlohmann/detail/view/string_ref.hpp>
#else
    #include <nlohmann/json_view.hpp> // the single header contains the internal headers
#endif
using nlohmann::json;

#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <test_data.hpp>

namespace
{
using nlohmann::detail::view::document_data;
using nlohmann::detail::view::node;

// the node index of a text; a vector input has no terminating NUL, so that
// AddressSanitizer catches any read past the last byte
struct built
{
    std::unique_ptr<document_data, document_data::deleter> data{}; // NOLINT(readability-redundant-member-init)
    std::vector<char> copy{}; // NOLINT(readability-redundant-member-init)
    bool ok = false;
    nlohmann::detail::view::parse_failure failure{};
};

template<typename FloatType = double>
built build(const std::string& text, bool comments, bool trailing_commas, bool sentinel)
{
    built r;
    r.data.reset(document_data::create(nlohmann::detail::view::estimate_nodes(text.data(), text.size())));
    const char* src = text.c_str();
    if (!sentinel)
    {
        r.copy.assign(text.begin(), text.end());
        src = r.copy.data();
    }
    r.ok = nlohmann::detail::view::build < FloatType, !nlohmann::detail::abi_config::strict_nul_handling > (*r.data, src, text.size(), comments, trailing_commas, sentinel, r.failure);
    r.data->src = src;
    r.data->base[0] = src;
    r.data->base[1] = r.data->arena.data();
    return r;
}

// the value of a subtree, as json::parse would build it
json value_of(const document_data& d, const node*& n)
{
    const node& x = *n;
    ++n;
    switch (static_cast<json::value_t>(x.kind))
    {
        case json::value_t::object:
        {
            json o = json::object();
            const node* const end = &x + x.next;
            while (n != end)
            {
                const std::string key(d.str(*n), n->len);
                ++n;
                o[key] = value_of(d, n);
            }
            return o;
        }
        case json::value_t::array:
        {
            json a = json::array();
            const node* const end = &x + x.next;
            while (n != end)
            {
                a.push_back(value_of(d, n));
            }
            return a;
        }
        case json::value_t::string:
            return std::string(d.str(x), x.len);
        case json::value_t::boolean:
            return (x.flags & nlohmann::detail::view::node_flags::is_true) != 0;
        case json::value_t::number_integer:
            return static_cast<std::int64_t>(nlohmann::detail::view::integer_bits(x));
        case json::value_t::number_unsigned:
            return nlohmann::detail::view::integer_bits(x);
        case json::value_t::number_float:
            return json::parse(std::string(d.src + x.off, x.len)).get<double>();
        case json::value_t::null:
        case json::value_t::binary:
        case json::value_t::discarded:
        default:
            return nullptr;
    }
}

json value_of(const built& b)
{
    const node* n = b.data->tape;
    json v = value_of(*b.data, n);
    CHECK(n == b.data->tape + b.data->tape_size);
    return v;
}

// accept/reject and the value must match json::parse, for all options and
// with and without a NUL after the text
void check_same(const std::string& text)
{
    CAPTURE(text)
    for (int options = 0; options < 4; ++options)
    {
        const bool comments = (options & 1) != 0;
        const bool trailing_commas = (options & 2) != 0;
        const bool accepted = json::accept(text, comments, trailing_commas);
        for (const bool sentinel :
                {
                    true, false
                })
        {
            const built b = build(text, comments, trailing_commas, sentinel);
            CHECK(b.ok == accepted);
            if (b.ok && accepted)
            {
                CHECK(value_of(b) == json::parse(text, nullptr, true, comments, trailing_commas));
            }
        }
    }
}

// a small deterministic generator of documents
struct generator
{
    std::mt19937 rng{5295}; // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)

    int r(int n)
    {
        return static_cast<int>(rng() % static_cast<unsigned>(n));
    }

    void ws(std::string& o)
    {
        for (int n = r(4) == 0 ? r(12) : r(2); n > 0; --n)
        {
            o += " \n\t\r  "[r(6)];
        }
    }

    void str(std::string& o)
    {
        static const char* const pieces[] = {"a", "Z", " ", "~", "\\n", "\\\"", "\\\\", "\\/", "\\u00e9", "\\ud83d\\ude00", "\xc3\xa9", "\xe3\x81\x82", "\xf0\x9f\x98\x80", "\x7f", "\\u001f", "long enough text to leave the first 16 bytes"}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        o += '"';
        for (int n = r(3) == 0 ? r(20) : r(6); n > 0; --n)
        {
            o += pieces[r(16)];
        }
        o += '"';
    }

    void num(std::string& o)
    {
        static const char* const numbers[] = {"0", "-0", "1", "-1", "12", "123456789", "1234567890123456789", "9223372036854775807", "-9223372036854775808", // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
                                              "9223372036854775808", "18446744073709551615", "18446744073709551616", "-9223372036854775809",
                                              "1.5", "-2.25e-3", "1e10", "1E+2", "0.000001", "3.141592653589793238462643", "1e308", "-1e-400", "123.456e7"
                                             };
        o += numbers[r(22)];
    }

    void value(std::string& o, int depth)
    {
        ws(o);
        const int k = depth > 5 ? 2 + r(6) : r(8);
        if (k == 0 || k == 1)
        {
            const bool object = k == 0;
            o += object ? '{' : '[';
            for (int i = r(5); i > 0; --i)
            {
                ws(o);
                if (object)
                {
                    str(o);
                    ws(o);
                    o += ':';
                }
                value(o, depth + 1);
                o += i > 1 ? "," : "";
            }
            ws(o);
            o += object ? '}' : ']';
        }
        else if (k < 4)
        {
            str(o);
        }
        else if (k < 6)
        {
            num(o);
        }
        else
        {
            static const char* const literals[] = {"true", "false", "null"}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            o += literals[r(3)];
        }
        ws(o);
    }
};
} // namespace

TEST_CASE("json_view string_ref")
{
    // std::string_view in C++17, a stand-in with the same members before
    using nlohmann::detail::view::string_ref;
    const std::string text = "abc";
    const string_ref r(text);
    CHECK(r.length() == 3);
    CHECK(std::string(r.begin(), r.end()) == "abc");
    CHECK(r[1] == 'b');
    CHECK(r != string_ref("abd"));
    CHECK_FALSE(r != string_ref("abcd", 3));
    std::ostringstream o;
    o << r;
    CHECK(o.str() == "abc");
}

TEST_CASE("json_view builder")
{
    SECTION("scalars and containers")
    {
        for (const char* text :
                {
                    "null", "true", "false", "0", "-0", "42", "-42", "1.5", "\"\"", "\"abc\"", "[]", "{}", "[1,2,3]", "{\"a\":1,\"b\":[true,null]}", // NOLINT(modernize-raw-string-literal)
                    " [ 1 , 2 ] ", "{\"a\" : {\"b\" : {}}}", "[[[]]]", "\"\\u00e4\\n\\ud83d\\ude00\"", "{\"a\":1,\"a\":2}", "18446744073709551616", // NOLINT(modernize-raw-string-literal)
                    "-9223372036854775809", "123456789012345678901234567890", "1e400", "-1e400", "1.7976931348623157e308"
                })
        {
            check_same(text);
        }

        // the midpoint between the largest double and 2^1024 rounds to
        // infinity (an overflow), one less to the largest double: with more
        // than 19 digits, Eisel-Lemire cannot decide these, and the overflow
        // check needs the exact comparison with the midpoint
        const std::string midpoint = "179769313486231580793728971405303415079934132710037826936173778980444968292764750946649017977587207096330286416692887910946555547851940402630657488671505820681908902000708383676273854845817711531764475730270069855571366959622842914819860834936475292719074168444365510704342711559699508093042880177904174497792";
        const std::string below = "179769313486231580793728971405303415079934132710037826936173778980444968292764750946649017977587207096330286416692887910946555547851940402630657488671505820681908902000708383676273854845817711531764475730270069855571366959622842914819860834936475292719074168444365510704342711559699508093042880177904174497791";
        check_same(midpoint);
        check_same("-" + midpoint);
        check_same(below);
        check_same("[" + below + "," + midpoint + "]");

        // the check uses the floating-point type of the document: with float,
        // the view rejects what parse() rejects (out_of_range.406), and a
        // double document is not affected
        using float_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;
        CHECK_FALSE(float_json::accept("1e39"));
        CHECK(float_json::accept("3.4028235e38"));
        CHECK_FALSE(float_json::accept("3.4028236e38"));
        for (const char* text :
                {
                    "1e39", "-1e39", "3.4028235e38", "-3.4028235e38", "3.4028236e38", "-3.4028236e38", "3.4028234663852886e38", "1e38",
                    "340282356779733661637539395458142568448", "340282356779733661637539395458142568447.99", "0.00034028236e42",
                    "[1.5e38, 3.5e38]", "{\"a\": 1e-50, \"b\": 1e39}"
                })
        {
            CAPTURE(text)
            const bool float_accepted = float_json::accept(text);
            for (const bool sentinel :
                    {
                        true, false
                    })
            {
                const built f = build<float>(text, false, false, sentinel);
                CHECK(f.ok == float_accepted);
                if (!f.ok)
                {
                    CHECK(f.failure.code == nlohmann::detail::view::error_code::number_overflow);
                }
                CHECK(build<double>(text, false, false, sentinel).ok == json::accept(text));
            }
        }
    }

    SECTION("malformed input")
    {
        for (const char* text :
                {
                    "", " ", "[", "]", "{", "}", "[1,]", "{\"a\":1,}", "[1 2]", "{\"a\" 1}", "{1:2}", "tru", "nul", "fals", "truex", "-", "01", "1.", ".5", "1e", "1e+",
                    "\"", "\"abc", "\"\\x\"", "\"\\u12\"", "\"\\u12G4\"", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800\\u0041\"", "\"\x01\"", "\"\xff\"", "\"\xc3\"", // NOLINT(modernize-raw-string-literal)
                    "\"\xe0\x80\x80\"", "\"\xed\xa0\x80\"", "[1]x", "[1] [2]", "/", "/*", "/* */ 1", "// c\n1", "1 // c", "[1,/*c*/2]", "[1,2,]"
                })
        {
            check_same(text);
        }
    }

    SECTION("NUL, BOM, and whitespace")
    {
        // a NUL inside a string is a control character, as for json::parse
        // (where a NUL ends the input, it does so only between values)
        for (const bool sentinel :
                {
                    true, false
                })
        {
            const built b = build(std::string("[\"ab\0cd\"]", 9), false, false, sentinel);
            CHECK(!b.ok);
            CHECK(b.failure.code == nlohmann::detail::view::error_code::string_control_character);
            CHECK(b.failure.offset == 4);
        }
        check_same(std::string("[1]\0garbage", 11));
        check_same(std::string("[1\0]", 4));
        check_same(std::string("[1, // c\0\n2]", 12));
        check_same(std::string("[1, /* c\0 */ 2]", 15));
        check_same("\xEF\xBB\xBF[1]");
        check_same("\xEF\xBB[1]");
        check_same(" \t\r\n 7 \n");
        for (const char* text :
                {"[1]\r", "[1]\n", "[1]\r\n", "[1,\r2]", "[1,\r\n2]", "7\r", "\"x\"\r", "{\"a\":\r\n1}\r", "[\n  1,\n  2\n]", "{\n    \"a\": [\n        1\n    ]\n}"
                })
        {
            check_same(text);
        }
    }

    SECTION("deep nesting")
    {
        // the open containers beyond 64 levels live on the heap
        for (const std::size_t depth :
                {
                    63u, 64u, 65u, 1000u, 100000u
                })
        {
            const std::string arrays = std::string(depth, '[') + std::string(depth, ']');
            const built b = build(arrays, false, false, false);
            REQUIRE(b.ok);
            CHECK(b.data->tape_size == depth);
            CHECK(b.data->tape[0].next == depth);
            std::string objects;
            for (std::size_t i = 0; i < depth; ++i)
            {
                objects += "{\"a\":";
            }
            objects += '1' + std::string(depth, '}');
            const built o = build(objects, false, false, false);
            REQUIRE(o.ok);
            CHECK(o.data->tape_size == (2 * depth) + 1);
            CHECK(!build(std::string(depth, '[') + std::string(depth - 1, ']'), false, false, false).ok);
        }
    }

    SECTION("generated documents and damaged copies")
    {
        generator g;
        for (int i = 0; i < 3000; ++i)
        {
            std::string text;
            g.value(text, 0);
            check_same(text);
            // damage: flip one byte, or cut the text
            std::string damaged = text;
            const auto at = static_cast<std::size_t>(g.r(static_cast<int>(damaged.size())));
            static const char replacements[] = {'x', '"', '\\', ',', ':', ']', '}', '[', '{', '1', '-', '.', 'e', '\0', '\n', '/'}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            damaged[at] = replacements[g.r(16)];
            check_same(damaged);
            check_same(text.substr(0, at));
        }
    }

    SECTION("test files")
    {
        for (const char* name :
                {
                    "/json.org/1.json", "/json.org/2.json", "/json.org/3.json", "/json.org/4.json", "/json.org/5.json",
                    "/json_testsuite/sample.json", "/nativejson-benchmark/canada.json", "/nativejson-benchmark/citm_catalog.json",
                    "/nativejson-benchmark/twitter.json", "/json_tests/pass1.json", "/json_tests/pass2.json", "/json_tests/pass3.json"
                })
        {
            CAPTURE(name)
            std::ifstream f(std::string(TEST_DATA_DIRECTORY) + name, std::ios::binary);
            std::stringstream ss;
            ss << f.rdbuf();
            const std::string text = ss.str();
            REQUIRE(!text.empty());
            const built b = build(text, false, false, true);
            REQUIRE(b.ok);
            CHECK(value_of(b) == json::parse(text));
        }
    }
}
