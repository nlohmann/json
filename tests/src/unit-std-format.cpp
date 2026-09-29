//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake selects the C++ standard versions with which to build a
// unit test based on the presence of JSON_HAS_CPP_<VERSION> macros.
// When using macros that are only defined for particular versions of the standard
// (e.g., JSON_HAS_FILESYSTEM for C++17 and up), please mention the corresponding
// version macro in a comment close by, like this:
// JSON_HAS_CPP_<VERSION> (do not remove; see note at top of file)

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

// JSON_HAS_CPP_20 (do not remove; see note at top of file)
#if JSON_HAS_STD_FORMAT

#include <cmath>
#include <iterator>
#include <random>
#include <string>

TEST_CASE("std::formatter<nlohmann::json>")
{
    SECTION("compact formatting matches dump()")
    {
        CHECK(std::format("{}", json(nullptr)) == json(nullptr).dump());
        CHECK(std::format("{}", json(true)) == json(true).dump());
        CHECK(std::format("{}", json(42)) == json(42).dump());
        CHECK(std::format("{}", json(42.23)) == json(42.23).dump());
        CHECK(std::format("{}", json("foo")) == json("foo").dump());
        CHECK(std::format("{}", json::array({1, 2, 3})) == json::array({1, 2, 3}).dump());

        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        CHECK(std::format("{}", j) == j.dump());
    }

    SECTION("'#' triggers pretty-printing with an indent of 4, like dump(4)")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        CHECK(std::format("{:#}", j) == j.dump(4));
        CHECK(std::format("{:#}", json::array()) == json::array().dump(4));
    }

    SECTION("a width sets the indent, like dump(width), with or without '#'")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        CHECK(std::format("{:2}", j) == j.dump(2));
        CHECK(std::format("{:#2}", j) == j.dump(2));
        CHECK(std::format("{:8}", j) == j.dump(8));
        // multi-digit widths must accumulate every digit, not just the first
        CHECK(std::format("{:12}", j) == j.dump(12));
        CHECK(std::format("{:#12}", j) == j.dump(12));
        CHECK(std::format("{:10}", j) == j.dump(10));
    }

    SECTION("bare alignment with no fill character defaults to a space indent character")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        // without a preceding fill character, the alignment character itself must not
        // be mistaken for the indent character -- the default space is kept
        CHECK(std::format("{:<}", j) == j.dump());
        CHECK(std::format("{:>}", j) == j.dump());
        CHECK(std::format("{:^}", j) == j.dump());
        CHECK(std::format("{:<3}", j) == j.dump(3, ' '));
        CHECK(std::format("{:>3}", j) == j.dump(3, ' '));
        CHECK(std::format("{:^3}", j) == j.dump(3, ' '));
    }

    SECTION("fill-and-align sets the indent character, like dump(indent, indent_char)")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        CHECK(std::format("{:.>#}", j) == j.dump(4, '.'));
        CHECK(std::format("{:.>#3}", j) == j.dump(3, '.'));
        CHECK(std::format("{:.>3}", j) == j.dump(3, '.'));
        // the alignment direction itself ('<', '>', '^') has no separate meaning for
        // JSON values -- only the fill character before it is used as the indent character
        CHECK(std::format("{:.<3}", j) == j.dump(3, '.'));
        CHECK(std::format("{:.^3}", j) == j.dump(3, '.'));
    }

    SECTION("format args with no meaning for JSON values are rejected")
    {
        // std::vformat parses the format string at runtime (unlike std::format, whose
        // format_string type is checked at compile time), so it lets us verify that an
        // invalid spec throws std::format_error without needing a compile-time-illegal
        // format string.
        const json j = 42;
        CHECK_THROWS_AS(std::vformat("{:x}", std::make_format_args(j)), std::format_error);
        CHECK_THROWS_AS(std::vformat("{:+}", std::make_format_args(j)), std::format_error);   // sign
        CHECK_THROWS_AS(std::vformat("{:-}", std::make_format_args(j)), std::format_error);   // sign
        CHECK_THROWS_AS(std::vformat("{: }", std::make_format_args(j)), std::format_error);   // sign
        CHECK_THROWS_AS(std::vformat("{:04}", std::make_format_args(j)), std::format_error);  // '0' flag
        CHECK_THROWS_AS(std::vformat("{:L}", std::make_format_args(j)), std::format_error);   // locale
        const int dynamic_width = 4;
        CHECK_THROWS_AS(std::vformat("{:{}}", std::make_format_args(j, dynamic_width)), std::format_error); // dynamic width
        CHECK_THROWS_AS(std::vformat("{:.{}}", std::make_format_args(j, dynamic_width)), std::format_error); // dynamic precision
        CHECK_THROWS_AS(std::vformat("{:.}", std::make_format_args(j)), std::format_error);   // '.' without digits
        CHECK_THROWS_AS(std::vformat("{:.3x}", std::make_format_args(j)), std::format_error); // type after precision
        CHECK_THROWS_AS(std::vformat("{:.3#}", std::make_format_args(j)), std::format_error); // '#' after precision
    }

    SECTION("a precision sets the significant digits of floating-point numbers")
    {
        // rounded, not truncated, with the digits of std::format on the number
        CHECK(std::format("{:.3}", json(3.141592653589793)) == "3.14");
        CHECK(std::format("{:.3}", json(1.9999)) == "2.0");
        CHECK(std::format("{:.3}", json(0.000123456)) == "0.000123");
        CHECK(std::format("{:.3}", json(12345.678)) == "1.23e+04");
        CHECK(std::format("{:.1}", json(0.15)) == "0.1");
        CHECK(std::format("{:.3}", json(2.675)) == "2.67");
        CHECK(std::format("{:.3}", json(5405000.0)) == "5.4e+06");
        CHECK(std::format("{:.0}", json(3.141592653589793)) == "3.0");
        CHECK(std::format("{:.17}", json(0.1)) == "0.10000000000000001");
        CHECK(std::format("{:.99999999999}", json(0.1)) == "0.1000000000000000055511151231257827021181583404541015625");

        // integers, strings, and NaN are unaffected
        const json j = {{"pi", 3.141592653589793}, {"n", 123456789}, {"s", "3.14159"}, {"nan", NAN}};
        CHECK(std::format("{:.3}", j) == R"({"n":123456789,"nan":null,"pi":3.14,"s":"3.14159"})");
    }

    SECTION("a precision gives the digits of std::format on the number")
    {
        std::mt19937_64 gen(42); // NOLINT(cert-msc32-c,cert-msc51-cpp)
        std::uniform_real_distribution<double> mantissa(1.0, 10.0);
        std::uniform_int_distribution<int> exponent(-30, 30);
        std::uniform_int_distribution<int> digits(0, 20);
        for (int i = 0; i < 100000; ++i)
        {
            // half of the values are short decimals, whose ties are the tricky case
            double v = mantissa(gen) * std::pow(10.0, exponent(gen));
            if (i % 2 == 0)
            {
                v = std::stod(std::format("{:.4}", v));
            }
            const int p = digits(gen);
            std::string expected = std::vformat("{:." + std::to_string(p) + "}", std::make_format_args(v));
            if (expected.find_first_of(".e") == std::string::npos)
            {
                expected += ".0";
            }
            CAPTURE(v);
            CAPTURE(p);
            const json j = v;
            CHECK(std::vformat("{:." + std::to_string(p) + "}", std::make_format_args(j)) == expected);
        }
    }

    SECTION("a precision combines with the other specs")
    {
        const json j = {{"a", {1.9999, 2}}, {"pi", 3.141592653589793}};
        CHECK(std::format("{:#.3}", j) ==
              "{\n"
              "    \"a\": [\n"
              "        2.0,\n"
              "        2\n"
              "    ],\n"
              "    \"pi\": 3.14\n"
              "}");
        CHECK(std::format("{:2.3}", j) ==
              "{\n"
              "  \"a\": [\n"
              "    2.0,\n"
              "    2\n"
              "  ],\n"
              "  \"pi\": 3.14\n"
              "}");
        CHECK(std::format("{:.>#1.2}", j) ==
              "{\n"
              ".\"a\": [\n"
              "..2.0,\n"
              "..2\n"
              ".],\n"
              ".\"pi\": 3.1\n"
              "}");
    }

    SECTION("without a precision, the output is unchanged")
    {
        const json j = {{"pi", 3.141592653589793}, {"x", 0.1}};
        CHECK(std::format("{}", j) == j.dump());
        CHECK(std::format("{:#}", j) == j.dump(4));
    }

    SECTION("a format spec may run to the end of the parse context")
    {
        // std::format always hands parse() a range that still holds the closing
        // '}', but a parse context may also end right after the spec
        const auto parse = [](const char* spec)
        {
            std::format_parse_context ctx(spec);
            std::formatter<json> f;
            CHECK(f.parse(ctx) == ctx.end());
            return f;
        };

        CHECK(parse("").indent == -1);
        CHECK(parse(">").indent == -1);
        CHECK(parse("#").indent == 4);
        CHECK(parse("3").indent == 3);
        CHECK(parse("#12").indent == 12);
        CHECK(parse("").precision == -1);
        CHECK(parse(".3").precision == 3);
        CHECK(parse("#2.10").precision == 10);

        const auto f = parse(".>");
        CHECK(f.indent == -1);
        CHECK(f.indent_char == '.');
    }

    SECTION("std::format_to writes through an arbitrary output iterator")
    {
        const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
        std::string out;
        std::format_to(std::back_inserter(out), "{}", j);
        CHECK(out == j.dump());
    }
}

TEST_CASE("std::formatter<nlohmann::ordered_json>")
{
    // spot-check a non-default basic_json instantiation, since the formatter
    // is written against the generic NLOHMANN_BASIC_JSON_TPL_DECLARATION
    // template and must actually instantiate (and behave correctly) for
    // template arguments other than nlohmann::json
    const ordered_json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
    CHECK(std::format("{}", j) == j.dump());
    CHECK(std::format("{:#}", j) == j.dump(4));
    CHECK(std::format("{:2}", j) == j.dump(2));
    CHECK(std::format("{:.3}", ordered_json(3.141592653589793)) == "3.14");
}

#endif
