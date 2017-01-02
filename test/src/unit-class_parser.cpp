/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.10
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

TEST_CASE("parser class")
{
    SECTION("parse")
    {
        SECTION("null")
        {
            CHECK(json::parser("null").parse() == json(nullptr));
        }

        SECTION("true")
        {
            CHECK(json::parser("true").parse() == json(true));
        }

        SECTION("false")
        {
            CHECK(json::parser("false").parse() == json(false));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                CHECK(json::parser("[]").parse() == json(json::value_t::array));
                CHECK(json::parser("[ ]").parse() == json(json::value_t::array));
            }

            SECTION("nonempty array")
            {
                CHECK(json::parser("[true, false, null]").parse() == json({true, false, nullptr}));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                CHECK(json::parser("{}").parse() == json(json::value_t::object));
                CHECK(json::parser("{ }").parse() == json(json::value_t::object));
            }

            SECTION("nonempty object")
            {
                CHECK(json::parser("{\"\": true, \"one\": 1, \"two\": null}").parse() == json({{"", true}, {"one", 1}, {"two", nullptr}}));
            }
        }

        SECTION("string")
        {
            // empty string
            CHECK(json::parser("\"\"").parse() == json(json::value_t::string));

            SECTION("errors")
            {
                // error: tab in string
                CHECK_THROWS_AS(json::parser("\"\t\"").parse(), std::invalid_argument);
                CHECK_THROWS_WITH(json::parser("\"\t\"").parse(), "parse error - unexpected '\"'");
                // error: newline in string
                CHECK_THROWS_AS(json::parser("\"\n\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\r\"").parse(), std::invalid_argument);
                CHECK_THROWS_WITH(json::parser("\"\n\"").parse(), "parse error - unexpected '\"'");
                CHECK_THROWS_WITH(json::parser("\"\r\"").parse(), "parse error - unexpected '\"'");
                // error: backspace in string
                CHECK_THROWS_AS(json::parser("\"\b\"").parse(), std::invalid_argument);
                CHECK_THROWS_WITH(json::parser("\"\b\"").parse(), "parse error - unexpected '\"'");
                // improve code coverage
                CHECK_THROWS_AS(json::parser("\uFF01").parse(), std::invalid_argument);
                // unescaped control characters
                CHECK_THROWS_AS(json::parser("\"\x00\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x01\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x02\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x03\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x04\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x05\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x06\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x07\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x08\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x09\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x0a\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x0b\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x0c\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x0d\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x0e\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x0f\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x10\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x11\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x12\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x13\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x14\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x15\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x16\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x17\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x18\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x19\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x1a\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x1b\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x1c\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x1d\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x1e\"").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("\"\x1f\"").parse(), std::invalid_argument);
            }

            SECTION("escaped")
            {
                // quotation mark "\""
                auto r1 = R"("\"")"_json;
                CHECK(json::parser("\"\\\"\"").parse() == r1);
                // reverse solidus "\\"
                auto r2 = R"("\\")"_json;
                CHECK(json::parser("\"\\\\\"").parse() == r2);
                // solidus
                CHECK(json::parser("\"\\/\"").parse() == R"("/")"_json);
                // backspace
                CHECK(json::parser("\"\\b\"").parse() == json("\b"));
                // formfeed
                CHECK(json::parser("\"\\f\"").parse() == json("\f"));
                // newline
                CHECK(json::parser("\"\\n\"").parse() == json("\n"));
                // carriage return
                CHECK(json::parser("\"\\r\"").parse() == json("\r"));
                // horizontal tab
                CHECK(json::parser("\"\\t\"").parse() == json("\t"));

                CHECK(json::parser("\"\\u0001\"").parse().get<json::string_t>() == "\x01");
                CHECK(json::parser("\"\\u000a\"").parse().get<json::string_t>() == "\n");
                CHECK(json::parser("\"\\u00b0\"").parse().get<json::string_t>() == "°");
                CHECK(json::parser("\"\\u0c00\"").parse().get<json::string_t>() == "ఀ");
                CHECK(json::parser("\"\\ud000\"").parse().get<json::string_t>() == "퀀");
                CHECK(json::parser("\"\\u000E\"").parse().get<json::string_t>() == "\x0E");
                CHECK(json::parser("\"\\u00F0\"").parse().get<json::string_t>() == "ð");
                CHECK(json::parser("\"\\u0100\"").parse().get<json::string_t>() == "Ā");
                CHECK(json::parser("\"\\u2000\"").parse().get<json::string_t>() == " ");
                CHECK(json::parser("\"\\uFFFF\"").parse().get<json::string_t>() == "￿");
                CHECK(json::parser("\"\\u20AC\"").parse().get<json::string_t>() == "€");
                CHECK(json::parser("\"€\"").parse().get<json::string_t>() == "€");
                CHECK(json::parser("\"🎈\"").parse().get<json::string_t>() == "🎈");

                CHECK(json::parse("\"\\ud80c\\udc60\"").get<json::string_t>() == u8"\U00013060");
                CHECK(json::parse("\"\\ud83c\\udf1e\"").get<json::string_t>() == "🌞");
            }
        }

        SECTION("number")
        {
            SECTION("integers")
            {
                SECTION("without exponent")
                {
                    CHECK(json::parser("-128").parse() == json(-128));
                    CHECK(json::parser("-0").parse() == json(-0));
                    CHECK(json::parser("0").parse() == json(0));
                    CHECK(json::parser("128").parse() == json(128));
                }

                SECTION("with exponent")
                {
                    CHECK(json::parser("0e1").parse() == json(0e1));
                    CHECK(json::parser("0E1").parse() == json(0e1));

                    CHECK(json::parser("10000E-4").parse() == json(10000e-4));
                    CHECK(json::parser("10000E-3").parse() == json(10000e-3));
                    CHECK(json::parser("10000E-2").parse() == json(10000e-2));
                    CHECK(json::parser("10000E-1").parse() == json(10000e-1));
                    CHECK(json::parser("10000E0").parse() == json(10000e0));
                    CHECK(json::parser("10000E1").parse() == json(10000e1));
                    CHECK(json::parser("10000E2").parse() == json(10000e2));
                    CHECK(json::parser("10000E3").parse() == json(10000e3));
                    CHECK(json::parser("10000E4").parse() == json(10000e4));

                    CHECK(json::parser("10000e-4").parse() == json(10000e-4));
                    CHECK(json::parser("10000e-3").parse() == json(10000e-3));
                    CHECK(json::parser("10000e-2").parse() == json(10000e-2));
                    CHECK(json::parser("10000e-1").parse() == json(10000e-1));
                    CHECK(json::parser("10000e0").parse() == json(10000e0));
                    CHECK(json::parser("10000e1").parse() == json(10000e1));
                    CHECK(json::parser("10000e2").parse() == json(10000e2));
                    CHECK(json::parser("10000e3").parse() == json(10000e3));
                    CHECK(json::parser("10000e4").parse() == json(10000e4));

                    CHECK(json::parser("-0e1").parse() == json(-0e1));
                    CHECK(json::parser("-0E1").parse() == json(-0e1));
                    CHECK(json::parser("-0E123").parse() == json(-0e123));
                }

                SECTION("edge cases")
                {
                    // From RFC7159, Section 6:
                    // Note that when such software is used, numbers that are
                    // integers and are in the range [-(2**53)+1, (2**53)-1]
                    // are interoperable in the sense that implementations will
                    // agree exactly on their numeric values.

                    // -(2**53)+1
                    CHECK(json::parser("-9007199254740991").parse().get<int64_t>() == -9007199254740991);
                    // (2**53)-1
                    CHECK(json::parser("9007199254740991").parse().get<int64_t>() == 9007199254740991);
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
                    CHECK(json::parser("-9223372036854775808").parse().get<int64_t>() == -9223372036854775807 - 1);
                    // (2**63)-1
                    CHECK(json::parser("9223372036854775807").parse().get<int64_t>() == 9223372036854775807);
                    // (2**64)-1
                    CHECK(json::parser("18446744073709551615").parse().get<uint64_t>() == 18446744073709551615u);
                }
            }

            SECTION("floating-point")
            {
                SECTION("without exponent")
                {
                    CHECK(json::parser("-128.5").parse() == json(-128.5));
                    CHECK(json::parser("0.999").parse() == json(0.999));
                    CHECK(json::parser("128.5").parse() == json(128.5));
                    CHECK(json::parser("-0.0").parse() == json(-0.0));
                }

                SECTION("with exponent")
                {
                    CHECK(json::parser("-128.5E3").parse() == json(-128.5E3));
                    CHECK(json::parser("-128.5E-3").parse() == json(-128.5E-3));
                    CHECK(json::parser("-0.0e1").parse() == json(-0.0e1));
                    CHECK(json::parser("-0.0E1").parse() == json(-0.0e1));
                }
            }

            SECTION("invalid numbers")
            {
                CHECK_THROWS_AS(json::parser("01").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("--1").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("1.").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("1E").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("1E-").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("1.E1").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-1E").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0E#").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0E-#").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0#").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0.0:").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0.0Z").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0E123:").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0e0-:").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0e-:").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("-0f").parse(), std::invalid_argument);

                // numbers must not begin with "+"
                CHECK_THROWS_AS(json::parser("+1").parse(), std::invalid_argument);
                CHECK_THROWS_AS(json::parser("+0").parse(), std::invalid_argument);

                CHECK_THROWS_WITH(json::parser("01").parse(),
                                  "parse error - unexpected number literal; expected end of input");
                CHECK_THROWS_WITH(json::parser("--1").parse(), "parse error - unexpected '-'");
                CHECK_THROWS_WITH(json::parser("1.").parse(),
                                  "parse error - unexpected '.'; expected end of input");
                CHECK_THROWS_WITH(json::parser("1E").parse(),
                                  "parse error - unexpected 'E'; expected end of input");
                CHECK_THROWS_WITH(json::parser("1E-").parse(),
                                  "parse error - unexpected 'E'; expected end of input");
                CHECK_THROWS_WITH(json::parser("1.E1").parse(),
                                  "parse error - unexpected '.'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-1E").parse(),
                                  "parse error - unexpected 'E'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0E#").parse(),
                                  "parse error - unexpected 'E'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0E-#").parse(),
                                  "parse error - unexpected 'E'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0#").parse(),
                                  "parse error - unexpected '#'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0.0:").parse(),
                                  "parse error - unexpected ':'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0.0Z").parse(),
                                  "parse error - unexpected 'Z'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0E123:").parse(),
                                  "parse error - unexpected ':'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0e0-:").parse(),
                                  "parse error - unexpected '-'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0e-:").parse(),
                                  "parse error - unexpected 'e'; expected end of input");
                CHECK_THROWS_WITH(json::parser("-0f").parse(),
                                  "parse error - unexpected 'f'; expected end of input");
            }
        }
    }

    SECTION("parse errors")
    {
        // unexpected end of number
        CHECK_THROWS_AS(json::parser("0.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("-").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("--").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("-0.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("-.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("-:").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("0.:").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("e.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1e.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1e/").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1e:").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1E.").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1E/").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("1E:").parse(), std::invalid_argument);
        CHECK_THROWS_WITH(json::parser("0.").parse(),
                          "parse error - unexpected '.'; expected end of input");
        CHECK_THROWS_WITH(json::parser("-").parse(), "parse error - unexpected '-'");
        CHECK_THROWS_WITH(json::parser("--").parse(),
                          "parse error - unexpected '-'");
        CHECK_THROWS_WITH(json::parser("-0.").parse(),
                          "parse error - unexpected '.'; expected end of input");
        CHECK_THROWS_WITH(json::parser("-.").parse(),
                          "parse error - unexpected '-'");
        CHECK_THROWS_WITH(json::parser("-:").parse(),
                          "parse error - unexpected '-'");
        CHECK_THROWS_WITH(json::parser("0.:").parse(),
                          "parse error - unexpected '.'; expected end of input");
        CHECK_THROWS_WITH(json::parser("e.").parse(),
                          "parse error - unexpected 'e'");
        CHECK_THROWS_WITH(json::parser("1e.").parse(),
                          "parse error - unexpected 'e'; expected end of input");
        CHECK_THROWS_WITH(json::parser("1e/").parse(),
                          "parse error - unexpected 'e'; expected end of input");
        CHECK_THROWS_WITH(json::parser("1e:").parse(),
                          "parse error - unexpected 'e'; expected end of input");
        CHECK_THROWS_WITH(json::parser("1E.").parse(),
                          "parse error - unexpected 'E'; expected end of input");
        CHECK_THROWS_WITH(json::parser("1E/").parse(),
                          "parse error - unexpected 'E'; expected end of input");
        CHECK_THROWS_WITH(json::parser("1E:").parse(),
                          "parse error - unexpected 'E'; expected end of input");

        // unexpected end of null
        CHECK_THROWS_AS(json::parser("n").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("nu").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("nul").parse(), std::invalid_argument);
        CHECK_THROWS_WITH(json::parser("n").parse(), "parse error - unexpected 'n'");
        CHECK_THROWS_WITH(json::parser("nu").parse(),
                          "parse error - unexpected 'n'");
        CHECK_THROWS_WITH(json::parser("nul").parse(),
                          "parse error - unexpected 'n'");

        // unexpected end of true
        CHECK_THROWS_AS(json::parser("t").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("tr").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("tru").parse(), std::invalid_argument);
        CHECK_THROWS_WITH(json::parser("t").parse(), "parse error - unexpected 't'");
        CHECK_THROWS_WITH(json::parser("tr").parse(),
                          "parse error - unexpected 't'");
        CHECK_THROWS_WITH(json::parser("tru").parse(),
                          "parse error - unexpected 't'");

        // unexpected end of false
        CHECK_THROWS_AS(json::parser("f").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("fa").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("fal").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("fals").parse(), std::invalid_argument);
        CHECK_THROWS_WITH(json::parser("f").parse(), "parse error - unexpected 'f'");
        CHECK_THROWS_WITH(json::parser("fa").parse(),
                          "parse error - unexpected 'f'");
        CHECK_THROWS_WITH(json::parser("fal").parse(),
                          "parse error - unexpected 'f'");
        CHECK_THROWS_WITH(json::parser("fals").parse(),
                          "parse error - unexpected 'f'");

        // missing/unexpected end of array
        CHECK_THROWS_AS(json::parser("[").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("[1").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("[1,").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("[1,]").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("]").parse(), std::invalid_argument);
        CHECK_THROWS_WITH(json::parser("[").parse(),
                          "parse error - unexpected end of input");
        CHECK_THROWS_WITH(json::parser("[1").parse(),
                          "parse error - unexpected end of input; expected ']'");
        CHECK_THROWS_WITH(json::parser("[1,").parse(),
                          "parse error - unexpected end of input");
        CHECK_THROWS_WITH(json::parser("[1,]").parse(),
                          "parse error - unexpected ']'");
        CHECK_THROWS_WITH(json::parser("]").parse(), "parse error - unexpected ']'");

        // missing/unexpected end of object
        CHECK_THROWS_AS(json::parser("{").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("{\"foo\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("{\"foo\":").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("{\"foo\":}").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("{\"foo\":1,}").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("}").parse(), std::invalid_argument);
        CHECK_THROWS_WITH(json::parser("{").parse(),
                          "parse error - unexpected end of input; expected string literal");
        CHECK_THROWS_WITH(json::parser("{\"foo\"").parse(),
                          "parse error - unexpected end of input; expected ':'");
        CHECK_THROWS_WITH(json::parser("{\"foo\":").parse(),
                          "parse error - unexpected end of input");
        CHECK_THROWS_WITH(json::parser("{\"foo\":}").parse(),
                          "parse error - unexpected '}'");
        CHECK_THROWS_WITH(json::parser("{\"foo\":1,}").parse(),
                          "parse error - unexpected '}'; expected string literal");
        CHECK_THROWS_WITH(json::parser("}").parse(), "parse error - unexpected '}'");

        // missing/unexpected end of string
        CHECK_THROWS_AS(json::parser("\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u0\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u01\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u012\"").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u0").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u01").parse(), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("\"\\u012").parse(), std::invalid_argument);
        CHECK_THROWS_WITH(json::parser("\"").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\\"").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\u\"").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\u0\"").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\u01\"").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\u012\"").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\u").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\u0").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\u01").parse(),
                          "parse error - unexpected '\"'");
        CHECK_THROWS_WITH(json::parser("\"\\u012").parse(),
                          "parse error - unexpected '\"'");

        // invalid escapes
        for (int c = 1; c < 128; ++c)
        {
            auto s = std::string("\"\\") + std::string(1, c) + "\"";

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
                    CHECK_NOTHROW(json::parser(s.c_str()).parse());
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
                    CHECK_THROWS_AS(json::parser(s.c_str()).parse(), std::invalid_argument);
                    CHECK_THROWS_WITH(json::parser(s.c_str()).parse(), "parse error - unexpected '\"'");
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
                auto s1 = s + "000" + std::string(1, c) + "\"";
                auto s2 = s + "00" + std::string(1, c) + "0\"";
                auto s3 = s + "0" + std::string(1, c) + "00\"";
                auto s4 = s + std::string(1, c) + "000\"";

                if (valid(c))
                {
                    CHECK_NOTHROW(json::parser(s1.c_str()).parse());
                    CHECK_NOTHROW(json::parser(s2.c_str()).parse());
                    CHECK_NOTHROW(json::parser(s3.c_str()).parse());
                    CHECK_NOTHROW(json::parser(s4.c_str()).parse());
                }
                else
                {
                    CHECK_THROWS_AS(json::parser(s1.c_str()).parse(), std::invalid_argument);
                    CHECK_THROWS_AS(json::parser(s2.c_str()).parse(), std::invalid_argument);
                    CHECK_THROWS_AS(json::parser(s3.c_str()).parse(), std::invalid_argument);
                    CHECK_THROWS_AS(json::parser(s4.c_str()).parse(), std::invalid_argument);

                    CHECK_THROWS_WITH(json::parser(s1.c_str()).parse(), "parse error - unexpected '\"'");
                    CHECK_THROWS_WITH(json::parser(s2.c_str()).parse(), "parse error - unexpected '\"'");
                    CHECK_THROWS_WITH(json::parser(s3.c_str()).parse(), "parse error - unexpected '\"'");
                    CHECK_THROWS_WITH(json::parser(s4.c_str()).parse(), "parse error - unexpected '\"'");
                }
            }
        }

        // missing part of a surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\""), std::invalid_argument);
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\""), "missing low surrogate");
        // invalid surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uD80C\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\u0000\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uFFFF\""), std::invalid_argument);
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\uD80C\""),
                          "missing or wrong low surrogate");
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\u0000\""),
                          "missing or wrong low surrogate");
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\uFFFF\""),
                          "missing or wrong low surrogate");
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
            CHECK(json::parser(std::begin(v), std::end(v)).parse() == json(true));
        }

        SECTION("from std::array")
        {
            std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
            CHECK(json::parser(std::begin(v), std::end(v)).parse() == json(true));
        }

        SECTION("from array")
        {
            uint8_t v[] = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(std::begin(v), std::end(v)).parse() == json(true));
        }

        SECTION("from char literal")
        {
            CHECK(json::parser("true").parse() == json(true));
        }

        SECTION("from std::string")
        {
            std::string v = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(std::begin(v), std::end(v)).parse() == json(true));
        }

        SECTION("from std::initializer_list")
        {
            std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(std::begin(v), std::end(v)).parse() == json(true));
        }

        SECTION("from std::valarray")
        {
            std::valarray<uint8_t> v = {'t', 'r', 'u', 'e'};
            CHECK(json::parser(std::begin(v), std::end(v)).parse() == json(true));
        }
    }
}
