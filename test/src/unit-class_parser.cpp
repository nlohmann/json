/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.1.1
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2017 Niels Lohmann <http://nlohmann.me>.

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

#include <valarray>

// shortcut to parse a string literal
json::parser parse_string(const char* s);
json::parser parse_string(const char* s)
{
    return json::parser(json::input_adapter::create(s));
}

TEST_CASE("parser class")
{
    SECTION("parse")
    {
        SECTION("null")
        {
            CHECK(parse_string("null").parse() == json(nullptr));
        }

        SECTION("true")
        {
            CHECK(parse_string("true").parse() == json(true));
        }

        SECTION("false")
        {
            CHECK(parse_string("false").parse() == json(false));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                CHECK(parse_string("[]").parse() == json(json::value_t::array));
                CHECK(parse_string("[ ]").parse() == json(json::value_t::array));
            }

            SECTION("nonempty array")
            {
                CHECK(parse_string("[true, false, null]").parse() == json({true, false, nullptr}));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                CHECK(parse_string("{}").parse() == json(json::value_t::object));
                CHECK(parse_string("{ }").parse() == json(json::value_t::object));
            }

            SECTION("nonempty object")
            {
                CHECK(parse_string("{\"\": true, \"one\": 1, \"two\": null}").parse() == json({{"", true}, {"one", 1}, {"two", nullptr}}));
            }
        }

        SECTION("string")
        {
            // empty string
            CHECK(parse_string("\"\"").parse() == json(json::value_t::string));

            SECTION("errors")
            {
                // error: tab in string
                CHECK_THROWS_AS(parse_string("\"\t\"").parse(), json::parse_error);
                CHECK_THROWS_WITH(parse_string("\"\t\"").parse(),
                                  "[json.exception.parse_error.101] parse error at 2: syntax error - invalid string: control character U+0009 must be escaped; last read '\"<U+0009>'");
                // error: newline in string
                CHECK_THROWS_AS(parse_string("\"\n\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\r\"").parse(), json::parse_error);
                CHECK_THROWS_WITH(parse_string("\"\n\"").parse(),
                                  "[json.exception.parse_error.101] parse error at 2: syntax error - invalid string: control character U+000A must be escaped; last read '\"<U+000A>'");
                CHECK_THROWS_WITH(parse_string("\"\r\"").parse(),
                                  "[json.exception.parse_error.101] parse error at 2: syntax error - invalid string: control character U+000D must be escaped; last read '\"<U+000D>'");
                // error: backspace in string
                CHECK_THROWS_AS(parse_string("\"\b\"").parse(), json::parse_error);
                CHECK_THROWS_WITH(parse_string("\"\b\"").parse(),
                                  "[json.exception.parse_error.101] parse error at 2: syntax error - invalid string: control character U+0008 must be escaped; last read '\"<U+0008>'");
                // improve code coverage
                CHECK_THROWS_AS(parse_string("\uFF01").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("[-4:1,]").parse(), json::parse_error);
                // unescaped control characters
                CHECK_THROWS_AS(parse_string("\"\x00\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x01\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x02\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x03\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x04\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x05\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x06\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x07\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x08\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x09\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x0a\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x0b\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x0c\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x0d\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x0e\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x0f\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x10\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x11\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x12\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x13\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x14\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x15\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x16\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x17\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x18\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x19\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x1a\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x1b\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x1c\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x1d\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x1e\"").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("\"\x1f\"").parse(), json::parse_error);
            }

            SECTION("escaped")
            {
                // quotation mark "\""
                auto r1 = R"("\"")"_json;
                CHECK(parse_string("\"\\\"\"").parse() == r1);
                // reverse solidus "\\"
                auto r2 = R"("\\")"_json;
                CHECK(parse_string("\"\\\\\"").parse() == r2);
                // solidus
                CHECK(parse_string("\"\\/\"").parse() == R"("/")"_json);
                // backspace
                CHECK(parse_string("\"\\b\"").parse() == json("\b"));
                // formfeed
                CHECK(parse_string("\"\\f\"").parse() == json("\f"));
                // newline
                CHECK(parse_string("\"\\n\"").parse() == json("\n"));
                // carriage return
                CHECK(parse_string("\"\\r\"").parse() == json("\r"));
                // horizontal tab
                CHECK(parse_string("\"\\t\"").parse() == json("\t"));

                CHECK(parse_string("\"\\u0001\"").parse().get<json::string_t>() == "\x01");
                CHECK(parse_string("\"\\u000a\"").parse().get<json::string_t>() == "\n");
                CHECK(parse_string("\"\\u00b0\"").parse().get<json::string_t>() == "°");
                CHECK(parse_string("\"\\u0c00\"").parse().get<json::string_t>() == "ఀ");
                CHECK(parse_string("\"\\ud000\"").parse().get<json::string_t>() == "퀀");
                CHECK(parse_string("\"\\u000E\"").parse().get<json::string_t>() == "\x0E");
                CHECK(parse_string("\"\\u00F0\"").parse().get<json::string_t>() == "ð");
                CHECK(parse_string("\"\\u0100\"").parse().get<json::string_t>() == "Ā");
                CHECK(parse_string("\"\\u2000\"").parse().get<json::string_t>() == " ");
                CHECK(parse_string("\"\\uFFFF\"").parse().get<json::string_t>() == "￿");
                CHECK(parse_string("\"\\u20AC\"").parse().get<json::string_t>() == "€");
                CHECK(parse_string("\"€\"").parse().get<json::string_t>() == "€");
                CHECK(parse_string("\"🎈\"").parse().get<json::string_t>() == "🎈");

                CHECK(parse_string("\"\\ud80c\\udc60\"").parse().get<json::string_t>() == u8"\U00013060");
                CHECK(parse_string("\"\\ud83c\\udf1e\"").parse().get<json::string_t>() == "🌞");
            }
        }

        SECTION("number")
        {
            SECTION("integers")
            {
                SECTION("without exponent")
                {
                    CHECK(parse_string("-128").parse() == json(-128));
                    CHECK(parse_string("-0").parse() == json(-0));
                    CHECK(parse_string("0").parse() == json(0));
                    CHECK(parse_string("128").parse() == json(128));
                }

                SECTION("with exponent")
                {
                    CHECK(parse_string("0e1").parse() == json(0e1));
                    CHECK(parse_string("0E1").parse() == json(0e1));

                    CHECK(parse_string("10000E-4").parse() == json(10000e-4));
                    CHECK(parse_string("10000E-3").parse() == json(10000e-3));
                    CHECK(parse_string("10000E-2").parse() == json(10000e-2));
                    CHECK(parse_string("10000E-1").parse() == json(10000e-1));
                    CHECK(parse_string("10000E0").parse() == json(10000e0));
                    CHECK(parse_string("10000E1").parse() == json(10000e1));
                    CHECK(parse_string("10000E2").parse() == json(10000e2));
                    CHECK(parse_string("10000E3").parse() == json(10000e3));
                    CHECK(parse_string("10000E4").parse() == json(10000e4));

                    CHECK(parse_string("10000e-4").parse() == json(10000e-4));
                    CHECK(parse_string("10000e-3").parse() == json(10000e-3));
                    CHECK(parse_string("10000e-2").parse() == json(10000e-2));
                    CHECK(parse_string("10000e-1").parse() == json(10000e-1));
                    CHECK(parse_string("10000e0").parse() == json(10000e0));
                    CHECK(parse_string("10000e1").parse() == json(10000e1));
                    CHECK(parse_string("10000e2").parse() == json(10000e2));
                    CHECK(parse_string("10000e3").parse() == json(10000e3));
                    CHECK(parse_string("10000e4").parse() == json(10000e4));

                    CHECK(parse_string("-0e1").parse() == json(-0e1));
                    CHECK(parse_string("-0E1").parse() == json(-0e1));
                    CHECK(parse_string("-0E123").parse() == json(-0e123));
                }

                SECTION("edge cases")
                {
                    // From RFC7159, Section 6:
                    // Note that when such software is used, numbers that are
                    // integers and are in the range [-(2**53)+1, (2**53)-1]
                    // are interoperable in the sense that implementations will
                    // agree exactly on their numeric values.

                    // -(2**53)+1
                    CHECK(parse_string("-9007199254740991").parse().get<int64_t>() == -9007199254740991);
                    // (2**53)-1
                    CHECK(parse_string("9007199254740991").parse().get<int64_t>() == 9007199254740991);
                }

                SECTION("over the edge cases")  // issue #178 - Integer conversion to unsigned (incorrect handling of 64 bit integers)
                {
                    // While RFC7159, Section 6 specifies a preference for support
                    // for ranges in range of IEEE 754-2008 binary64 (double precision)
                    // this does not accommodate 64 bit integers without loss of accuracy.
                    // As 64 bit integers are now widely used in software, it is desirable
                    // to expand support to to the full 64 bit (signed and unsigned) range
                    // i.e. -(2**63) -> (2**64)-1.

                    // -(2**63)    ** Note: compilers see negative literals as negated positive numbers (hence the -1))
                    CHECK(parse_string("-9223372036854775808").parse().get<int64_t>() == -9223372036854775807 - 1);
                    // (2**63)-1
                    CHECK(parse_string("9223372036854775807").parse().get<int64_t>() == 9223372036854775807);
                    // (2**64)-1
                    CHECK(parse_string("18446744073709551615").parse().get<uint64_t>() == 18446744073709551615u);
                }
            }

            SECTION("floating-point")
            {
                SECTION("without exponent")
                {
                    CHECK(parse_string("-128.5").parse() == json(-128.5));
                    CHECK(parse_string("0.999").parse() == json(0.999));
                    CHECK(parse_string("128.5").parse() == json(128.5));
                    CHECK(parse_string("-0.0").parse() == json(-0.0));
                }

                SECTION("with exponent")
                {
                    CHECK(parse_string("-128.5E3").parse() == json(-128.5E3));
                    CHECK(parse_string("-128.5E-3").parse() == json(-128.5E-3));
                    CHECK(parse_string("-0.0e1").parse() == json(-0.0e1));
                    CHECK(parse_string("-0.0E1").parse() == json(-0.0e1));
                }
            }

            SECTION("overflow")
            {
                // overflows during parsing yield an exception
                CHECK_THROWS_AS(parse_string("1.18973e+4932").parse() == json(), json::out_of_range);
                CHECK_THROWS_WITH(parse_string("1.18973e+4932").parse() == json(),
                                  "[json.exception.out_of_range.406] number overflow parsing '1.18973e+4932'");
            }

            SECTION("invalid numbers")
            {
                CHECK_THROWS_AS(parse_string("01").parse(),      json::parse_error);
                CHECK_THROWS_AS(parse_string("--1").parse(),     json::parse_error);
                CHECK_THROWS_AS(parse_string("1.").parse(),      json::parse_error);
                CHECK_THROWS_AS(parse_string("1E").parse(),      json::parse_error);
                CHECK_THROWS_AS(parse_string("1E-").parse(),     json::parse_error);
                CHECK_THROWS_AS(parse_string("1.E1").parse(),    json::parse_error);
                CHECK_THROWS_AS(parse_string("-1E").parse(),     json::parse_error);
                CHECK_THROWS_AS(parse_string("-0E#").parse(),    json::parse_error);
                CHECK_THROWS_AS(parse_string("-0E-#").parse(),   json::parse_error);
                CHECK_THROWS_AS(parse_string("-0#").parse(),     json::parse_error);
                CHECK_THROWS_AS(parse_string("-0.0:").parse(),   json::parse_error);
                CHECK_THROWS_AS(parse_string("-0.0Z").parse(),   json::parse_error);
                CHECK_THROWS_AS(parse_string("-0E123:").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("-0e0-:").parse(),  json::parse_error);
                CHECK_THROWS_AS(parse_string("-0e-:").parse(),   json::parse_error);
                CHECK_THROWS_AS(parse_string("-0f").parse(),     json::parse_error);

                // numbers must not begin with "+"
                CHECK_THROWS_AS(parse_string("+1").parse(), json::parse_error);
                CHECK_THROWS_AS(parse_string("+0").parse(), json::parse_error);

                CHECK_THROWS_WITH(parse_string("01").parse(),
                                  "[json.exception.parse_error.101] parse error at 2: syntax error - unexpected number literal; expected end of input");
                CHECK_THROWS_WITH(parse_string("-01").parse(),
                                  "[json.exception.parse_error.101] parse error at 3: syntax error - unexpected number literal; expected end of input");
                CHECK_THROWS_WITH(parse_string("--1").parse(),
                                  "[json.exception.parse_error.101] parse error at 2: syntax error - invalid number; expected digit after '-'; last read '--'");
                CHECK_THROWS_WITH(parse_string("1.").parse(),
                                  "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected digit after '.'; last read '1.'");
                CHECK_THROWS_WITH(parse_string("1E").parse(),
                                  "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '1E'");
                CHECK_THROWS_WITH(parse_string("1E-").parse(),
                                  "[json.exception.parse_error.101] parse error at 4: syntax error - invalid number; expected digit after exponent sign; last read '1E-'");
                CHECK_THROWS_WITH(parse_string("1.E1").parse(),
                                  "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected digit after '.'; last read '1.E'");
                CHECK_THROWS_WITH(parse_string("-1E").parse(),
                                  "[json.exception.parse_error.101] parse error at 4: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '-1E'");
                CHECK_THROWS_WITH(parse_string("-0E#").parse(),
                                  "[json.exception.parse_error.101] parse error at 4: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '-0E#'");
                CHECK_THROWS_WITH(parse_string("-0E-#").parse(),
                                  "[json.exception.parse_error.101] parse error at 5: syntax error - invalid number; expected digit after exponent sign; last read '-0E-#'");
                CHECK_THROWS_WITH(parse_string("-0#").parse(),
                                  "[json.exception.parse_error.101] parse error at 3: syntax error - invalid literal; last read: '-0#'; expected end of input");
                CHECK_THROWS_WITH(parse_string("-0.0:").parse(),
                                  "[json.exception.parse_error.101] parse error at 5: syntax error - unexpected ':'; expected end of input");
                CHECK_THROWS_WITH(parse_string("-0.0Z").parse(),
                                  "[json.exception.parse_error.101] parse error at 5: syntax error - invalid literal; last read: '-0.0Z'; expected end of input");
                CHECK_THROWS_WITH(parse_string("-0E123:").parse(),
                                  "[json.exception.parse_error.101] parse error at 7: syntax error - unexpected ':'; expected end of input");
                CHECK_THROWS_WITH(parse_string("-0e0-:").parse(),
                                  "[json.exception.parse_error.101] parse error at 6: syntax error - invalid number; expected digit after '-'; last read: '-:'; expected end of input");
                CHECK_THROWS_WITH(parse_string("-0e-:").parse(),
                                  "[json.exception.parse_error.101] parse error at 5: syntax error - invalid number; expected digit after exponent sign; last read '-0e-:'");
                CHECK_THROWS_WITH(parse_string("-0f").parse(),
                                  "[json.exception.parse_error.101] parse error at 4: syntax error - invalid literal; expected 'false'; last read: '-0f'; expected end of input");
            }
        }
    }

    SECTION("accept")
    {
        SECTION("null")
        {
            CHECK(parse_string("null").accept());
        }

        SECTION("true")
        {
            CHECK(parse_string("true").accept());
        }

        SECTION("false")
        {
            CHECK(parse_string("false").accept());
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                CHECK(parse_string("[]").accept());
                CHECK(parse_string("[ ]").accept());
            }

            SECTION("nonempty array")
            {
                CHECK(parse_string("[true, false, null]").accept());
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                CHECK(parse_string("{}").accept());
                CHECK(parse_string("{ }").accept());
            }

            SECTION("nonempty object")
            {
                CHECK(parse_string("{\"\": true, \"one\": 1, \"two\": null}").accept());
            }
        }

        SECTION("string")
        {
            // empty string
            CHECK(parse_string("\"\"").accept());

            SECTION("errors")
            {
                // error: tab in string
                CHECK(parse_string("\"\t\"").accept() == false);
                // error: newline in string
                CHECK(parse_string("\"\n\"").accept() == false);
                CHECK(parse_string("\"\r\"").accept() == false);
                // error: backspace in string
                CHECK(parse_string("\"\b\"").accept() == false);
                // improve code coverage
                CHECK(parse_string("\uFF01").accept() == false);
                CHECK(parse_string("[-4:1,]").accept() == false);
                // unescaped control characters
                CHECK(parse_string("\"\x00\"").accept() == false);
                CHECK(parse_string("\"\x01\"").accept() == false);
                CHECK(parse_string("\"\x02\"").accept() == false);
                CHECK(parse_string("\"\x03\"").accept() == false);
                CHECK(parse_string("\"\x04\"").accept() == false);
                CHECK(parse_string("\"\x05\"").accept() == false);
                CHECK(parse_string("\"\x06\"").accept() == false);
                CHECK(parse_string("\"\x07\"").accept() == false);
                CHECK(parse_string("\"\x08\"").accept() == false);
                CHECK(parse_string("\"\x09\"").accept() == false);
                CHECK(parse_string("\"\x0a\"").accept() == false);
                CHECK(parse_string("\"\x0b\"").accept() == false);
                CHECK(parse_string("\"\x0c\"").accept() == false);
                CHECK(parse_string("\"\x0d\"").accept() == false);
                CHECK(parse_string("\"\x0e\"").accept() == false);
                CHECK(parse_string("\"\x0f\"").accept() == false);
                CHECK(parse_string("\"\x10\"").accept() == false);
                CHECK(parse_string("\"\x11\"").accept() == false);
                CHECK(parse_string("\"\x12\"").accept() == false);
                CHECK(parse_string("\"\x13\"").accept() == false);
                CHECK(parse_string("\"\x14\"").accept() == false);
                CHECK(parse_string("\"\x15\"").accept() == false);
                CHECK(parse_string("\"\x16\"").accept() == false);
                CHECK(parse_string("\"\x17\"").accept() == false);
                CHECK(parse_string("\"\x18\"").accept() == false);
                CHECK(parse_string("\"\x19\"").accept() == false);
                CHECK(parse_string("\"\x1a\"").accept() == false);
                CHECK(parse_string("\"\x1b\"").accept() == false);
                CHECK(parse_string("\"\x1c\"").accept() == false);
                CHECK(parse_string("\"\x1d\"").accept() == false);
                CHECK(parse_string("\"\x1e\"").accept() == false);
                CHECK(parse_string("\"\x1f\"").accept() == false);
            }

            SECTION("escaped")
            {
                // quotation mark "\""
                auto r1 = R"("\"")"_json;
                CHECK(parse_string("\"\\\"\"").accept());
                // reverse solidus "\\"
                auto r2 = R"("\\")"_json;
                CHECK(parse_string("\"\\\\\"").accept());
                // solidus
                CHECK(parse_string("\"\\/\"").accept());
                // backspace
                CHECK(parse_string("\"\\b\"").accept());
                // formfeed
                CHECK(parse_string("\"\\f\"").accept());
                // newline
                CHECK(parse_string("\"\\n\"").accept());
                // carriage return
                CHECK(parse_string("\"\\r\"").accept());
                // horizontal tab
                CHECK(parse_string("\"\\t\"").accept());

                CHECK(parse_string("\"\\u0001\"").accept());
                CHECK(parse_string("\"\\u000a\"").accept());
                CHECK(parse_string("\"\\u00b0\"").accept());
                CHECK(parse_string("\"\\u0c00\"").accept());
                CHECK(parse_string("\"\\ud000\"").accept());
                CHECK(parse_string("\"\\u000E\"").accept());
                CHECK(parse_string("\"\\u00F0\"").accept());
                CHECK(parse_string("\"\\u0100\"").accept());
                CHECK(parse_string("\"\\u2000\"").accept());
                CHECK(parse_string("\"\\uFFFF\"").accept());
                CHECK(parse_string("\"\\u20AC\"").accept());
                CHECK(parse_string("\"€\"").accept());
                CHECK(parse_string("\"🎈\"").accept());

                CHECK(parse_string("\"\\ud80c\\udc60\"").accept());
                CHECK(parse_string("\"\\ud83c\\udf1e\"").accept());
            }
        }

        SECTION("number")
        {
            SECTION("integers")
            {
                SECTION("without exponent")
                {
                    CHECK(parse_string("-128").accept());
                    CHECK(parse_string("-0").accept());
                    CHECK(parse_string("0").accept());
                    CHECK(parse_string("128").accept());
                }

                SECTION("with exponent")
                {
                    CHECK(parse_string("0e1").accept());
                    CHECK(parse_string("0E1").accept());

                    CHECK(parse_string("10000E-4").accept());
                    CHECK(parse_string("10000E-3").accept());
                    CHECK(parse_string("10000E-2").accept());
                    CHECK(parse_string("10000E-1").accept());
                    CHECK(parse_string("10000E0").accept());
                    CHECK(parse_string("10000E1").accept());
                    CHECK(parse_string("10000E2").accept());
                    CHECK(parse_string("10000E3").accept());
                    CHECK(parse_string("10000E4").accept());

                    CHECK(parse_string("10000e-4").accept());
                    CHECK(parse_string("10000e-3").accept());
                    CHECK(parse_string("10000e-2").accept());
                    CHECK(parse_string("10000e-1").accept());
                    CHECK(parse_string("10000e0").accept());
                    CHECK(parse_string("10000e1").accept());
                    CHECK(parse_string("10000e2").accept());
                    CHECK(parse_string("10000e3").accept());
                    CHECK(parse_string("10000e4").accept());

                    CHECK(parse_string("-0e1").accept());
                    CHECK(parse_string("-0E1").accept());
                    CHECK(parse_string("-0E123").accept());
                }

                SECTION("edge cases")
                {
                    // From RFC7159, Section 6:
                    // Note that when such software is used, numbers that are
                    // integers and are in the range [-(2**53)+1, (2**53)-1]
                    // are interoperable in the sense that implementations will
                    // agree exactly on their numeric values.

                    // -(2**53)+1
                    CHECK(parse_string("-9007199254740991").accept());
                    // (2**53)-1
                    CHECK(parse_string("9007199254740991").accept());
                }

                SECTION("over the edge cases")  // issue #178 - Integer conversion to unsigned (incorrect handling of 64 bit integers)
                {
                    // While RFC7159, Section 6 specifies a preference for support
                    // for ranges in range of IEEE 754-2008 binary64 (double precision)
                    // this does not accommodate 64 bit integers without loss of accuracy.
                    // As 64 bit integers are now widely used in software, it is desirable
                    // to expand support to to the full 64 bit (signed and unsigned) range
                    // i.e. -(2**63) -> (2**64)-1.

                    // -(2**63)    ** Note: compilers see negative literals as negated positive numbers (hence the -1))
                    CHECK(parse_string("-9223372036854775808").accept());
                    // (2**63)-1
                    CHECK(parse_string("9223372036854775807").accept());
                    // (2**64)-1
                    CHECK(parse_string("18446744073709551615").accept());
                }
            }

            SECTION("floating-point")
            {
                SECTION("without exponent")
                {
                    CHECK(parse_string("-128.5").accept());
                    CHECK(parse_string("0.999").accept());
                    CHECK(parse_string("128.5").accept());
                    CHECK(parse_string("-0.0").accept());
                }

                SECTION("with exponent")
                {
                    CHECK(parse_string("-128.5E3").accept());
                    CHECK(parse_string("-128.5E-3").accept());
                    CHECK(parse_string("-0.0e1").accept());
                    CHECK(parse_string("-0.0E1").accept());
                }
            }

            SECTION("overflow")
            {
                // overflows during parsing yield an exception, but is accepted anyway
                CHECK(parse_string("1.18973e+4932").accept());
            }

            SECTION("invalid numbers")
            {
                CHECK(parse_string("01").accept() == false);
                CHECK(parse_string("--1").accept() == false);
                CHECK(parse_string("1.").accept() == false);
                CHECK(parse_string("1E").accept() == false);
                CHECK(parse_string("1E-").accept() == false);
                CHECK(parse_string("1.E1").accept() == false);
                CHECK(parse_string("-1E").accept() == false);
                CHECK(parse_string("-0E#").accept() == false);
                CHECK(parse_string("-0E-#").accept() == false);
                CHECK(parse_string("-0#").accept() == false);
                CHECK(parse_string("-0.0:").accept() == false);
                CHECK(parse_string("-0.0Z").accept() == false);
                CHECK(parse_string("-0E123:").accept() == false);
                CHECK(parse_string("-0e0-:").accept() == false);
                CHECK(parse_string("-0e-:").accept() == false);
                CHECK(parse_string("-0f").accept() == false);

                // numbers must not begin with "+"
                CHECK(parse_string("+1").accept() == false);
                CHECK(parse_string("+0").accept() == false);
            }
        }
    }

    SECTION("parse errors")
    {
        // unexpected end of number
        CHECK_THROWS_AS(parse_string("0.").parse(),  json::parse_error);
        CHECK_THROWS_AS(parse_string("-").parse(),   json::parse_error);
        CHECK_THROWS_AS(parse_string("--").parse(),  json::parse_error);
        CHECK_THROWS_AS(parse_string("-0.").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("-.").parse(),  json::parse_error);
        CHECK_THROWS_AS(parse_string("-:").parse(),  json::parse_error);
        CHECK_THROWS_AS(parse_string("0.:").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("e.").parse(),  json::parse_error);
        CHECK_THROWS_AS(parse_string("1e.").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("1e/").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("1e:").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("1E.").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("1E/").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("1E:").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("0.").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected digit after '.'; last read '0.'");
        CHECK_THROWS_WITH(parse_string("-").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - invalid number; expected digit after '-'; last read '-'");
        CHECK_THROWS_WITH(parse_string("--").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - invalid number; expected digit after '-'; last read '--'");
        CHECK_THROWS_WITH(parse_string("-0.").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - invalid number; expected digit after '.'; last read '-0.'");
        CHECK_THROWS_WITH(parse_string("-.").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - invalid number; expected digit after '-'; last read '-.'");
        CHECK_THROWS_WITH(parse_string("-:").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - invalid number; expected digit after '-'; last read '-:'");
        CHECK_THROWS_WITH(parse_string("0.:").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected digit after '.'; last read '0.:'");
        CHECK_THROWS_WITH(parse_string("e.").parse(),
                          "[json.exception.parse_error.101] parse error at 1: syntax error - invalid literal; last read 'e'");
        CHECK_THROWS_WITH(parse_string("1e.").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '1e.'");
        CHECK_THROWS_WITH(parse_string("1e/").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '1e/'");
        CHECK_THROWS_WITH(parse_string("1e:").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '1e:'");
        CHECK_THROWS_WITH(parse_string("1E.").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '1E.'");
        CHECK_THROWS_WITH(parse_string("1E/").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '1E/'");
        CHECK_THROWS_WITH(parse_string("1E:").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid number; expected '+', '-', or digit after exponent; last read '1E:'");

        // unexpected end of null
        CHECK_THROWS_AS(parse_string("n").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("nu").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("nul").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("n").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - invalid literal; expected 'null'; last read 'n'");
        CHECK_THROWS_WITH(parse_string("nu").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid literal; expected 'null'; last read 'nu'");
        CHECK_THROWS_WITH(parse_string("nul").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - invalid literal; expected 'null'; last read 'nul'");

        // unexpected end of true
        CHECK_THROWS_AS(parse_string("t").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("tr").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("tru").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("t").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - invalid literal; expected 'true'; last read 't'");
        CHECK_THROWS_WITH(parse_string("tr").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid literal; expected 'true'; last read 'tr'");
        CHECK_THROWS_WITH(parse_string("tru").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - invalid literal; expected 'true'; last read 'tru'");

        // unexpected end of false
        CHECK_THROWS_AS(parse_string("f").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("fa").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("fal").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("fals").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("f").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - invalid literal; expected 'false'; last read 'f'");
        CHECK_THROWS_WITH(parse_string("fa").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid literal; expected 'false'; last read 'fa'");
        CHECK_THROWS_WITH(parse_string("fal").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - invalid literal; expected 'false'; last read 'fal'");
        CHECK_THROWS_WITH(parse_string("fals").parse(),
                          "[json.exception.parse_error.101] parse error at 5: syntax error - invalid literal; expected 'false'; last read 'fals'");

        // missing/unexpected end of array
        CHECK_THROWS_AS(parse_string("[").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("[1").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("[1,").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("[1,]").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("]").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("[").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - unexpected end of input");
        CHECK_THROWS_WITH(parse_string("[1").parse(),
                          "[json.exception.parse_error.101] parse error at 3: syntax error - unexpected end of input; expected ']'");
        CHECK_THROWS_WITH(parse_string("[1,").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - unexpected end of input");
        CHECK_THROWS_WITH(parse_string("[1,]").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - unexpected ']'");
        CHECK_THROWS_WITH(parse_string("]").parse(),
                          "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected ']'");

        // missing/unexpected end of object
        CHECK_THROWS_AS(parse_string("{").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("{\"foo\"").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("{\"foo\":").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("{\"foo\":}").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("{\"foo\":1,}").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("}").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("{").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - unexpected end of input; expected string literal");
        CHECK_THROWS_WITH(parse_string("{\"foo\"").parse(),
                          "[json.exception.parse_error.101] parse error at 7: syntax error - unexpected end of input; expected ':'");
        CHECK_THROWS_WITH(parse_string("{\"foo\":").parse(),
                          "[json.exception.parse_error.101] parse error at 8: syntax error - unexpected end of input");
        CHECK_THROWS_WITH(parse_string("{\"foo\":}").parse(),
                          "[json.exception.parse_error.101] parse error at 8: syntax error - unexpected '}'");
        CHECK_THROWS_WITH(parse_string("{\"foo\":1,}").parse(),
                          "[json.exception.parse_error.101] parse error at 10: syntax error - unexpected '}'; expected string literal");
        CHECK_THROWS_WITH(parse_string("}").parse(),
                          "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected '}'");

        // missing/unexpected end of string
        CHECK_THROWS_AS(parse_string("\"").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\\"").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\u\"").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\u0\"").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\u01\"").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\u012\"").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\u").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\u0").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\u01").parse(), json::parse_error);
        CHECK_THROWS_AS(parse_string("\"\\u012").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("\"").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - invalid string: missing closing quote; last read '\"'");
        CHECK_THROWS_WITH(parse_string("\"\\\"").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - invalid string: missing closing quote; last read '\"\\\"'");
        CHECK_THROWS_WITH(parse_string("\"\\u\"").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '\"\\u\"'");
        CHECK_THROWS_WITH(parse_string("\"\\u0\"").parse(),
                          "[json.exception.parse_error.101] parse error at 5: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '\"\\u0\"'");
        CHECK_THROWS_WITH(parse_string("\"\\u01\"").parse(),
                          "[json.exception.parse_error.101] parse error at 6: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '\"\\u01\"'");
        CHECK_THROWS_WITH(parse_string("\"\\u012\"").parse(),
                          "[json.exception.parse_error.101] parse error at 7: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '\"\\u012\"'");
        CHECK_THROWS_WITH(parse_string("\"\\u").parse(),
                          "[json.exception.parse_error.101] parse error at 4: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '\"\\u'");
        CHECK_THROWS_WITH(parse_string("\"\\u0").parse(),
                          "[json.exception.parse_error.101] parse error at 5: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '\"\\u0'");
        CHECK_THROWS_WITH(parse_string("\"\\u01").parse(),
                          "[json.exception.parse_error.101] parse error at 6: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '\"\\u01'");
        CHECK_THROWS_WITH(parse_string("\"\\u012").parse(),
                          "[json.exception.parse_error.101] parse error at 7: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '\"\\u012'");

        // invalid escapes
        for (int c = 1; c < 128; ++c)
        {
            auto s = std::string("\"\\") + std::string(1, static_cast<char>(c)) + "\"";

            switch (c)
            {
                // valid escapes
                case ('"'):
                case ('\\'):
                case ('/'):
                case ('b'):
                case ('f'):
                case ('n'):
                case ('r'):
                case ('t'):
                {
                    CHECK_NOTHROW(parse_string(s.c_str()).parse());
                    break;
                }

                // \u must be followed with four numbers, so we skip it here
                case ('u'):
                {
                    break;
                }

                // any other combination of backslash and character is invalid
                default:
                {
                    CHECK_THROWS_AS(parse_string(s.c_str()).parse(), json::parse_error);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parse_string(s.c_str()).parse(),
                                          "[json.exception.parse_error.101] parse error at 3: syntax error - invalid string: forbidden character after backspace; last read '\"\\" + std::string(1, static_cast<char>(c)) + "'");
                    }
                    break;
                }
            }
        }

        // invalid \uxxxx escapes
        {
            // check whether character is a valid hex character
            const auto valid = [](int c)
            {
                switch (c)
                {
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
                    case ('a'):
                    case ('b'):
                    case ('c'):
                    case ('d'):
                    case ('e'):
                    case ('f'):
                    case ('A'):
                    case ('B'):
                    case ('C'):
                    case ('D'):
                    case ('E'):
                    case ('F'):
                    {
                        return true;
                    }

                    default:
                    {
                        return false;
                    }
                }
            };

            for (int c = 1; c < 128; ++c)
            {
                std::string s = "\"\\u";

                // create a string with the iterated character at each position
                auto s1 = s + "000" + std::string(1, static_cast<char>(c)) + "\"";
                auto s2 = s + "00" + std::string(1, static_cast<char>(c)) + "0\"";
                auto s3 = s + "0" + std::string(1, static_cast<char>(c)) + "00\"";
                auto s4 = s + std::string(1, static_cast<char>(c)) + "000\"";

                if (valid(c))
                {
                    CAPTURE(s1);
                    CHECK_NOTHROW(parse_string(s1.c_str()).parse());
                    CAPTURE(s2);
                    CHECK_NOTHROW(parse_string(s2.c_str()).parse());
                    CAPTURE(s3);
                    CHECK_NOTHROW(parse_string(s3.c_str()).parse());
                    CAPTURE(s4);
                    CHECK_NOTHROW(parse_string(s4.c_str()).parse());
                }
                else
                {
                    CAPTURE(s1);
                    CHECK_THROWS_AS(parse_string(s1.c_str()).parse(), json::parse_error);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parse_string(s1.c_str()).parse(),
                                          "[json.exception.parse_error.101] parse error at 7: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '" + s1.substr(0, 7) + "'");
                    }

                    CAPTURE(s2);
                    CHECK_THROWS_AS(parse_string(s2.c_str()).parse(), json::parse_error);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parse_string(s2.c_str()).parse(),
                                          "[json.exception.parse_error.101] parse error at 6: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '" + s2.substr(0, 6) + "'");
                    }

                    CAPTURE(s3);
                    CHECK_THROWS_AS(parse_string(s3.c_str()).parse(), json::parse_error);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parse_string(s3.c_str()).parse(),
                                          "[json.exception.parse_error.101] parse error at 5: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '" + s3.substr(0, 5) + "'");
                    }

                    CAPTURE(s4);
                    CHECK_THROWS_AS(parse_string(s4.c_str()).parse(), json::parse_error);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parse_string(s4.c_str()).parse(),
                                          "[json.exception.parse_error.101] parse error at 4: syntax error - invalid string: '\\u' must be followed by 4 hex digits; last read '" + s4.substr(0, 4) + "'");
                    }
                }
            }
        }

        // missing part of a surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\""), json::parse_error);
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\""),
                          "[json.exception.parse_error.101] parse error at 8: syntax error - invalid string: surrogate U+D80C must be followed by U+DC00..U+DFFF; last read '\"\\uD80C\"'");
        // invalid surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uD80C\""), json::parse_error);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\u0000\""), json::parse_error);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uFFFF\""), json::parse_error);
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\uD80C\""),
                          "[json.exception.parse_error.101] parse error at 13: syntax error - invalid string: surrogate U+D80C must be followed by U+DC00..U+DFFF instead of U+D80C; last read '\"\\uD80C\\uD80C'");
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\u0000\""),
                          "[json.exception.parse_error.101] parse error at 13: syntax error - invalid string: surrogate U+D80C must be followed by U+DC00..U+DFFF instead of U+0000; last read '\"\\uD80C\\u0000'");
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\uFFFF\""),
                          "[json.exception.parse_error.101] parse error at 13: syntax error - invalid string: surrogate U+D80C must be followed by U+DC00..U+DFFF instead of U+FFFF; last read '\"\\uD80C\\uFFFF'");
    }

    SECTION("parse errors (accept)")
    {
        // unexpected end of number
        CHECK(parse_string("0.").accept() == false);
        CHECK(parse_string("-").accept() == false);
        CHECK(parse_string("--").accept() == false);
        CHECK(parse_string("-0.").accept() == false);
        CHECK(parse_string("-.").accept() == false);
        CHECK(parse_string("-:").accept() == false);
        CHECK(parse_string("0.:").accept() == false);
        CHECK(parse_string("e.").accept() == false);
        CHECK(parse_string("1e.").accept() == false);
        CHECK(parse_string("1e/").accept() == false);
        CHECK(parse_string("1e:").accept() == false);
        CHECK(parse_string("1E.").accept() == false);
        CHECK(parse_string("1E/").accept() == false);
        CHECK(parse_string("1E:").accept() == false);

        // unexpected end of null
        CHECK(parse_string("n").accept() == false);
        CHECK(parse_string("nu").accept() == false);
        CHECK(parse_string("nul").accept() == false);

        // unexpected end of true
        CHECK(parse_string("t").accept() == false);
        CHECK(parse_string("tr").accept() == false);
        CHECK(parse_string("tru").accept() == false);

        // unexpected end of false
        CHECK(parse_string("f").accept() == false);
        CHECK(parse_string("fa").accept() == false);
        CHECK(parse_string("fal").accept() == false);
        CHECK(parse_string("fals").accept() == false);

        // missing/unexpected end of array
        CHECK(parse_string("[").accept() == false);
        CHECK(parse_string("[1").accept() == false);
        CHECK(parse_string("[1,").accept() == false);
        CHECK(parse_string("[1,]").accept() == false);
        CHECK(parse_string("]").accept() == false);

        // missing/unexpected end of object
        CHECK(parse_string("{").accept() == false);
        CHECK(parse_string("{\"foo\"").accept() == false);
        CHECK(parse_string("{\"foo\":").accept() == false);
        CHECK(parse_string("{\"foo\":}").accept() == false);
        CHECK(parse_string("{\"foo\":1,}").accept() == false);
        CHECK(parse_string("}").accept() == false);

        // missing/unexpected end of string
        CHECK(parse_string("\"").accept() == false);
        CHECK(parse_string("\"\\\"").accept() == false);
        CHECK(parse_string("\"\\u\"").accept() == false);
        CHECK(parse_string("\"\\u0\"").accept() == false);
        CHECK(parse_string("\"\\u01\"").accept() == false);
        CHECK(parse_string("\"\\u012\"").accept() == false);
        CHECK(parse_string("\"\\u").accept() == false);
        CHECK(parse_string("\"\\u0").accept() == false);
        CHECK(parse_string("\"\\u01").accept() == false);
        CHECK(parse_string("\"\\u012").accept() == false);

        // invalid escapes
        for (int c = 1; c < 128; ++c)
        {
            auto s = std::string("\"\\") + std::string(1, static_cast<char>(c)) + "\"";

            switch (c)
            {
                // valid escapes
                case ('"'):
                case ('\\'):
                case ('/'):
                case ('b'):
                case ('f'):
                case ('n'):
                case ('r'):
                case ('t'):
                {
                    CHECK(parse_string(s.c_str()).accept());
                    break;
                }

                // \u must be followed with four numbers, so we skip it here
                case ('u'):
                {
                    break;
                }

                // any other combination of backslash and character is invalid
                default:
                {
                    CHECK(parse_string(s.c_str()).accept() == false);
                    break;
                }
            }
        }

        // invalid \uxxxx escapes
        {
            // check whether character is a valid hex character
            const auto valid = [](int c)
            {
                switch (c)
                {
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
                    case ('a'):
                    case ('b'):
                    case ('c'):
                    case ('d'):
                    case ('e'):
                    case ('f'):
                    case ('A'):
                    case ('B'):
                    case ('C'):
                    case ('D'):
                    case ('E'):
                    case ('F'):
                    {
                        return true;
                    }

                    default:
                    {
                        return false;
                    }
                }
            };

            for (int c = 1; c < 128; ++c)
            {
                std::string s = "\"\\u";

                // create a string with the iterated character at each position
                auto s1 = s + "000" + std::string(1, static_cast<char>(c)) + "\"";
                auto s2 = s + "00" + std::string(1, static_cast<char>(c)) + "0\"";
                auto s3 = s + "0" + std::string(1, static_cast<char>(c)) + "00\"";
                auto s4 = s + std::string(1, static_cast<char>(c)) + "000\"";

                if (valid(c))
                {
                    CAPTURE(s1);
                    CHECK(parse_string(s1.c_str()).accept());
                    CAPTURE(s2);
                    CHECK(parse_string(s2.c_str()).accept());
                    CAPTURE(s3);
                    CHECK(parse_string(s3.c_str()).accept());
                    CAPTURE(s4);
                    CHECK(parse_string(s4.c_str()).accept());
                }
                else
                {
                    CAPTURE(s1);
                    CHECK(parse_string(s1.c_str()).accept() == false);

                    CAPTURE(s2);
                    CHECK(parse_string(s2.c_str()).accept() == false);

                    CAPTURE(s3);
                    CHECK(parse_string(s3.c_str()).accept() == false);

                    CAPTURE(s4);
                    CHECK(parse_string(s4.c_str()).accept() == false);
                }
            }
        }

        // missing part of a surrogate pair
        CHECK(parse_string("\"\\uD80C\"").accept() == false);
        // invalid surrogate pair
        CHECK(parse_string("\"\\uD80C\\uD80C\"").accept() == false);
        CHECK(parse_string("\"\\uD80C\\u0000\"").accept() == false);
        CHECK(parse_string("\"\\uD80C\\uFFFF\"").accept() == false);
    }

    SECTION("tests found by mutate++")
    {
        // test case to make sure no comma preceeds the first key
        CHECK_THROWS_AS(parse_string("{,\"key\": false}").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("{,\"key\": false}").parse(),
                          "[json.exception.parse_error.101] parse error at 2: syntax error - unexpected ','; expected string literal");
        // test case to make sure an object is properly closed
        CHECK_THROWS_AS(parse_string("[{\"key\": false true]").parse(), json::parse_error);
        CHECK_THROWS_WITH(parse_string("[{\"key\": false true]").parse(),
                          "[json.exception.parse_error.101] parse error at 19: syntax error - unexpected true literal; expected '}'");

        // test case to make sure the callback is properly evaluated after reading a key
        {
            json::parser_callback_t cb = [](int, json::parse_event_t event, json&)
            {
                if (event == json::parse_event_t::key)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            };

            json x = json::parse("{\"key\": false}", cb);
            CHECK(x == json::object());
        }
    }

    SECTION("callback function")
    {
        auto s_object = R"(
            {
                "foo": 2,
                "bar": {
                    "baz": 1
                }
            }
        )";

        auto s_array = R"(
            [1,2,[3,4,5],4,5]
        )";

        SECTION("filter nothing")
        {
            json j_object = json::parse(s_object, [](int, json::parse_event_t, const json&)
            {
                return true;
            });

            CHECK (j_object == json({{"foo", 2}, {"bar", {{"baz", 1}}}}));

            json j_array = json::parse(s_array, [](int, json::parse_event_t, const json&)
            {
                return true;
            });

            CHECK (j_array == json({1, 2, {3, 4, 5}, 4, 5}));
        }

        SECTION("filter everything")
        {
            json j_object = json::parse(s_object, [](int, json::parse_event_t, const json&)
            {
                return false;
            });

            // the top-level object will be discarded, leaving a null
            CHECK (j_object.is_null());

            json j_array = json::parse(s_array, [](int, json::parse_event_t, const json&)
            {
                return false;
            });

            // the top-level array will be discarded, leaving a null
            CHECK (j_array.is_null());
        }

        SECTION("filter specific element")
        {
            json j_object = json::parse(s_object, [](int, json::parse_event_t, const json & j)
            {
                // filter all number(2) elements
                if (j == json(2))
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });

            CHECK (j_object == json({{"bar", {{"baz", 1}}}}));

            json j_array = json::parse(s_array, [](int, json::parse_event_t, const json & j)
            {
                if (j == json(2))
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });

            CHECK (j_array == json({1, {3, 4, 5}, 4, 5}));
        }

        SECTION("filter specific events")
        {
            SECTION("first closing event")
            {
                {
                    json j_object = json::parse(s_object, [](int, json::parse_event_t e, const json&)
                    {
                        static bool first = true;
                        if (e == json::parse_event_t::object_end and first)
                        {
                            first = false;
                            return false;
                        }
                        else
                        {
                            return true;
                        }
                    });

                    // the first completed object will be discarded
                    CHECK (j_object == json({{"foo", 2}}));
                }

                {
                    json j_array = json::parse(s_array, [](int, json::parse_event_t e, const json&)
                    {
                        static bool first = true;
                        if (e == json::parse_event_t::array_end and first)
                        {
                            first = false;
                            return false;
                        }
                        else
                        {
                            return true;
                        }
                    });

                    // the first completed array will be discarded
                    CHECK (j_array == json({1, 2, 4, 5}));
                }
            }
        }

        SECTION("special cases")
        {
            // the following test cases cover the situation in which an empty
            // object and array is discarded only after the closing character
            // has been read

            json j_empty_object = json::parse("{}", [](int, json::parse_event_t e, const json&)
            {
                if (e == json::parse_event_t::object_end)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });
            CHECK(j_empty_object == json());

            json j_empty_array = json::parse("[]", [](int, json::parse_event_t e, const json&)
            {
                if (e == json::parse_event_t::array_end)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            });
            CHECK(j_empty_array == json());
        }
    }

    SECTION("constructing from contiguous containers")
    {
        SECTION("from std::vector")
        {
            std::vector<uint8_t> v = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(json::input_adapter::create(std::begin(v), std::end(v))).parse() == json(true));
        }

        SECTION("from std::array")
        {
            std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
            CHECK(json::parser(json::input_adapter::create(std::begin(v), std::end(v))).parse() == json(true));
        }

        SECTION("from array")
        {
            uint8_t v[] = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(json::input_adapter::create(std::begin(v), std::end(v))).parse() == json(true));
        }

        SECTION("from char literal")
        {
            CHECK(parse_string("true").parse() == json(true));
        }

        SECTION("from std::string")
        {
            std::string v = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(json::input_adapter::create(std::begin(v), std::end(v))).parse() == json(true));
        }

        SECTION("from std::initializer_list")
        {
            std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(json::input_adapter::create(std::begin(v), std::end(v))).parse() == json(true));
        }

        SECTION("from std::valarray")
        {
            std::valarray<uint8_t> v = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(json::input_adapter::create(std::begin(v), std::end(v))).parse() == json(true));
        }
    }
}
