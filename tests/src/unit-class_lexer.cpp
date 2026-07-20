//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <sstream> // stringstream
#include <string> // string
#include <vector> // vector

namespace
{
// shortcut to scan a string literal
json::lexer::token_type scan_string(const char* s, bool ignore_comments = false);
json::lexer::token_type scan_string(const char* s, const bool ignore_comments)
{
    auto ia = nlohmann::detail::input_adapter(s);
    return nlohmann::detail::lexer<json, decltype(ia)>(std::move(ia), ignore_comments).scan(); // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
}
} // namespace

std::string get_error_message(const char* s, bool ignore_comments = false); // NOLINT(misc-use-internal-linkage)
std::string get_error_message(const char* s, const bool ignore_comments)
{
    auto ia = nlohmann::detail::input_adapter(s);
    auto lexer = nlohmann::detail::lexer<json, decltype(ia)>(std::move(ia), ignore_comments); // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
    lexer.scan();
    return lexer.get_error_message();
}

TEST_CASE("lexer class")
{
    SECTION("scan")
    {
        SECTION("structural characters")
        {
            CHECK((scan_string("[") == json::lexer::token_type::begin_array));
            CHECK((scan_string("]") == json::lexer::token_type::end_array));
            CHECK((scan_string("{") == json::lexer::token_type::begin_object));
            CHECK((scan_string("}") == json::lexer::token_type::end_object));
            CHECK((scan_string(",") == json::lexer::token_type::value_separator));
            CHECK((scan_string(":") == json::lexer::token_type::name_separator));
        }

        SECTION("literal names")
        {
            CHECK((scan_string("null") == json::lexer::token_type::literal_null));
            CHECK((scan_string("true") == json::lexer::token_type::literal_true));
            CHECK((scan_string("false") == json::lexer::token_type::literal_false));
        }

        SECTION("numbers")
        {
            CHECK((scan_string("0") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("1") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("2") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("3") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("4") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("5") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("6") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("7") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("8") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("9") == json::lexer::token_type::value_unsigned));

            CHECK((scan_string("-0") == json::lexer::token_type::value_integer));
            CHECK((scan_string("-1") == json::lexer::token_type::value_integer));

            CHECK((scan_string("1.1") == json::lexer::token_type::value_float));
            CHECK((scan_string("-1.1") == json::lexer::token_type::value_float));
            CHECK((scan_string("1E10") == json::lexer::token_type::value_float));
        }

        SECTION("whitespace")
        {
            // result is end_of_input, because not token is following
            CHECK((scan_string(" ") == json::lexer::token_type::end_of_input));
            CHECK((scan_string("\t") == json::lexer::token_type::end_of_input));
            CHECK((scan_string("\n") == json::lexer::token_type::end_of_input));
            CHECK((scan_string("\r") == json::lexer::token_type::end_of_input));
            CHECK((scan_string(" \t\n\r\n\t ") == json::lexer::token_type::end_of_input));
        }
    }

    SECTION("token_type_name")
    {
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::uninitialized)) == "<uninitialized>"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::literal_true)) == "true literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::literal_false)) == "false literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::literal_null)) == "null literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_string)) == "string literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_unsigned)) == "number literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_integer)) == "number literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_float)) == "number literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::begin_array)) == "'['"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::begin_object)) == "'{'"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::end_array)) == "']'"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::end_object)) == "'}'"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::name_separator)) == "':'"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_separator)) == "','"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::parse_error)) == "<parse error>"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::end_of_input)) == "end of input"));
    }

    SECTION("parse errors on first character")
    {
        for (int c = 1; c < 128; ++c)
        {
            // create string from the ASCII code
            const auto s = std::string(1, static_cast<char>(c));
            // store scan() result
            const auto res = scan_string(s.c_str());

            CAPTURE(s)

            switch (c)
            {
                // single characters that are valid tokens
                case ('['):
                case (']'):
                case ('{'):
                case ('}'):
                case (','):
                case (':'):
                case ('0'):
                case ('1'):
                case ('2'):
                case ('3'):
                case ('4'):
                case ('5'):
                case ('6'):
                case ('7'):
                case ('8'):
                case ('9'):
                {
                    CHECK((res != json::lexer::token_type::parse_error));
                    break;
                }

                // whitespace
                case (' '):
                case ('\t'):
                case ('\n'):
                case ('\r'):
                {
                    CHECK((res == json::lexer::token_type::end_of_input));
                    break;
                }

                // anything else is not expected
                default:
                {
                    CHECK((res == json::lexer::token_type::parse_error));
                    break;
                }
            }
        }
    }

    SECTION("very large string")
    {
        // strings larger than 1024 bytes yield a resize of the lexer's yytext buffer
        std::string s("\"");
        s += std::string(2048, 'x');
        s += "\"";
        CHECK((scan_string(s.c_str()) == json::lexer::token_type::value_string));
    }

    SECTION("fail on comments")
    {
        CHECK((scan_string("/", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/", false) == "invalid literal");

        CHECK((scan_string("/!", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/!", false) == "invalid literal");
        CHECK((scan_string("/*", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/*", false) == "invalid literal");
        CHECK((scan_string("/**", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/**", false) == "invalid literal");

        CHECK((scan_string("//", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("//", false) == "invalid literal");
        CHECK((scan_string("/**/", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/**/", false) == "invalid literal");
        CHECK((scan_string("/** /", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/** /", false) == "invalid literal");

        CHECK((scan_string("/***/", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/***/", false) == "invalid literal");
        CHECK((scan_string("/* true */", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/* true */", false) == "invalid literal");
        CHECK((scan_string("/*/**/", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/*/**/", false) == "invalid literal");
        CHECK((scan_string("/*/* */", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/*/* */", false) == "invalid literal");
    }

    SECTION("ignore comments")
    {
        CHECK((scan_string("/", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/", true) == "invalid comment; expecting '/' or '*' after '/'");

        CHECK((scan_string("/!", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/!", true) == "invalid comment; expecting '/' or '*' after '/'");
        CHECK((scan_string("/*", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/*", true) == "invalid comment; missing closing '*/'");
        CHECK((scan_string("/**", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/**", true) == "invalid comment; missing closing '*/'");

        CHECK((scan_string("//", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/**/", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/** /", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/** /", true) == "invalid comment; missing closing '*/'");

        CHECK((scan_string("/***/", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/* true */", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/*/**/", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/*/* */", true) == json::lexer::token_type::end_of_input));

        CHECK((scan_string("//\n//\n", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/**//**//**/", true) == json::lexer::token_type::end_of_input));
    }
}

TEST_CASE("lexer number fast path")
{
    // The contiguous fast path (used for pointer/string input) must agree with
    // the streaming byte path (used for std::istream) on token type, numeric
    // value, and round-trip text for every well-formed number, and reject the
    // same malformed numbers with the same message.
    SECTION("contiguous vs streaming parity")
    {
        const std::vector<std::string> numbers =
        {
            "0", "-0", "1", "-1", "42", "-42", "10", "100", "1234567890",
            "0.0", "-0.0", "3.14", "-3.14", "0.5", "-0.001", "123.456789",
            "1e0", "1E0", "1e10", "1e-10", "1e+10", "1.5e3", "-2.5E-4",
            "9223372036854775807",             // INT64_MAX -> unsigned
            "9223372036854775808",             // INT64_MAX + 1 -> unsigned
            "18446744073709551615",            // UINT64_MAX -> unsigned
            "18446744073709551616",            // UINT64_MAX + 1 -> float
            "-9223372036854775808",            // INT64_MIN -> integer
            "-9223372036854775809",            // INT64_MIN - 1 -> float
            "123456789012345678901234567890",  // huge -> float
            "0.30000000000000004", "2.2250738585072014e-308", "1e308"
        };

        for (const auto& n : numbers)
        {
            const std::string doc = "[" + n + "]";

            // contiguous fast path
            const json a = json::parse(doc);
            // streaming byte path
            std::stringstream ss(doc);
            const json b = json::parse(ss);

            CAPTURE(n);
            CHECK(a == b);
            CHECK(a.dump() == b.dump());
            CHECK(a[0].type() == b[0].type());
        }
    }

    SECTION("token type classification")
    {
        CHECK((scan_string("0") == json::lexer::token_type::value_unsigned));
        CHECK((scan_string("-1") == json::lexer::token_type::value_integer));
        CHECK((scan_string("1.5") == json::lexer::token_type::value_float));
        CHECK((scan_string("1e5") == json::lexer::token_type::value_float));
        CHECK((scan_string("18446744073709551615") == json::lexer::token_type::value_unsigned));
        CHECK((scan_string("18446744073709551616") == json::lexer::token_type::value_float));
        CHECK((scan_string("-9223372036854775808") == json::lexer::token_type::value_integer));
        CHECK((scan_string("-9223372036854775809") == json::lexer::token_type::value_float));
    }

    SECTION("malformed numbers are rejected identically")
    {
        for (const char* bad :
                {"-", "1.", "1e", "1e+", "1.2e", "01", "-01", "1..2", "1.2.3"
                })
        {
            CAPTURE(bad);
            // the contiguous fast path must decline and let the byte path report
            const std::string doc = std::string("[") + bad + "]";
            CHECK_FALSE(json::accept(doc));
            std::stringstream ss(doc);
            CHECK_FALSE(json::accept(ss));
        }
    }
}
