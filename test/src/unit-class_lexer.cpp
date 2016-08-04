/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.2
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2016 Niels Lohmann <http://nlohmann.me>.

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

#include "catch.hpp"

#define private public
#include "json.hpp"
using nlohmann::json;

TEST_CASE("lexer class")
{
    SECTION("scan")
    {
        SECTION("structural characters")
        {
            CHECK(json::lexer("[").scan() == json::lexer::token_type::begin_array);
            CHECK(json::lexer("]").scan() == json::lexer::token_type::end_array);
            CHECK(json::lexer("{").scan() == json::lexer::token_type::begin_object);
            CHECK(json::lexer("}").scan() == json::lexer::token_type::end_object);
            CHECK(json::lexer(",").scan() == json::lexer::token_type::value_separator);
            CHECK(json::lexer(":").scan() == json::lexer::token_type::name_separator);
        }

        SECTION("literal names")
        {
            CHECK(json::lexer("null").scan() == json::lexer::token_type::literal_null);
            CHECK(json::lexer("true").scan() == json::lexer::token_type::literal_true);
            CHECK(json::lexer("false").scan() == json::lexer::token_type::literal_false);
        }

        SECTION("numbers")
        {
            CHECK(json::lexer("0").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("1").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("2").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("3").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("4").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("5").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("6").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("7").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("8").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("9").scan() == json::lexer::token_type::value_number);
        }

        SECTION("whitespace")
        {
            // result is end_of_input, because not token is following
            CHECK(json::lexer(" ").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\t").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\n").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\r").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer(" \t\n\r\n\t ").scan() == json::lexer::token_type::end_of_input);
        }
    }

    SECTION("token_type_name")
    {
        CHECK(json::lexer::token_type_name(json::lexer::token_type::uninitialized) == "<uninitialized>");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_true) == "true literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_false) == "false literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_null) == "null literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_string) == "string literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_number) == "number literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::begin_array) == "'['");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::begin_object) == "'{'");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_array) == "']'");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_object) == "'}'");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::name_separator) == "':'");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_separator) == "','");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::parse_error) == "<parse error>");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_of_input) == "end of input");
    }

    SECTION("parse errors on first character")
    {
        for (int c = 1; c < 128; ++c)
        {
            auto s = std::string(1, c);

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
                    CHECK(json::lexer(s.c_str()).scan() != json::lexer::token_type::parse_error);
                    break;
                }

                // whitespace
                case (' '):
                case ('\t'):
                case ('\n'):
                case ('\r'):
                {
                    CHECK(json::lexer(s.c_str()).scan() == json::lexer::token_type::end_of_input);
                    break;
                }

                // anything else is not expected
                default:
                {
                    CHECK(json::lexer(s.c_str()).scan() == json::lexer::token_type::parse_error);
                    break;
                }
            }
        }
    }

    SECTION("to_unicode")
    {
        CHECK(json::lexer::to_unicode(0x1F4A9) == "💩");
        CHECK_THROWS_AS(json::lexer::to_unicode(0x200000), std::out_of_range);
        CHECK_THROWS_WITH(json::lexer::to_unicode(0x200000), "code points above 0x10FFFF are invalid");
    }
}
