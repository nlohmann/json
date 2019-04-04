/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.6.1
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "doctest_compatibility.h"

#define private public
#include <nlohmann/json.hpp>
using nlohmann::json;
#undef private

namespace
{
// shortcut to scan a string literal
json::lexer::token_type scan_string(const char* s);
json::lexer::token_type scan_string(const char* s)
{
    return json::lexer(nlohmann::detail::input_adapter(s)).scan();
}
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
}
