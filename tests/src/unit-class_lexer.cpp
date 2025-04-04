//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

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
