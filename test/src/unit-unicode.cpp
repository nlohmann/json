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

#include <fstream>

TEST_CASE("Unicode", "[hide]")
{
    SECTION("full enumeration of Unicode code points")
    {
        // create an escaped string from a code point
        const auto codepoint_to_unicode = [](std::size_t cp)
        {
            // copd points are represented as a six-character sequence: a
            // reverse solidus, followed by the lowercase letter u, followed
            // by four hexadecimal digits that encode the character's code
            // point
            std::stringstream ss;
            ss << "\\u" << std::setw(4) << std::setfill('0') << std::hex << cp;
            return ss.str();
        };

        // generate all UTF-8 code points; in total, 1112064 code points are
        // generated: 0x1FFFFF code points - 2048 invalid values between
        // 0xD800 and 0xDFFF.
        for (std::size_t cp = 0; cp <= 0x10FFFFu; ++cp)
        {
            // The Unicode standard permanently reserves these code point
            // values for UTF-16 encoding of the high and low surrogates, and
            // they will never be assigned a character, so there should be no
            // reason to encode them. The official Unicode standard says that
            // no UTF forms, including UTF-16, can encode these code points.
            if (cp >= 0xD800u and cp <= 0xDFFFu)
            {
                // if we would not skip these code points, we would get a
                // "missing low surrogate" exception
                continue;
            }

            // string to store the code point as in \uxxxx format
            std::string escaped_string;
            // string to store the code point as unescaped character sequence
            std::string unescaped_string;

            if (cp < 0x10000u)
            {
                // code points in the Basic Multilingual Plane can be
                // represented with one \\uxxxx sequence
                escaped_string = codepoint_to_unicode(cp);

                // All Unicode characters may be placed within the quotation
                // marks, except for the characters that must be escaped:
                // quotation mark, reverse solidus, and the control characters
                // (U+0000 through U+001F); we ignore these code points as
                // they are checked with codepoint_to_unicode.
                if (cp > 0x1f and cp != 0x22 and cp != 0x5c)
                {
                    unescaped_string = json::lexer::to_unicode(cp);
                }
            }
            else
            {
                // To escape an extended character that is not in the Basic
                // Multilingual Plane, the character is represented as a
                // 12-character sequence, encoding the UTF-16 surrogate pair
                const auto codepoint1 = 0xd800u + (((cp - 0x10000u) >> 10) & 0x3ffu);
                const auto codepoint2 = 0xdc00u + ((cp - 0x10000u) & 0x3ffu);
                escaped_string = codepoint_to_unicode(codepoint1);
                escaped_string += codepoint_to_unicode(codepoint2);
                unescaped_string += json::lexer::to_unicode(codepoint1, codepoint2);
            }

            // all other code points are valid and must not yield parse errors
            CAPTURE(cp);
            CAPTURE(escaped_string);
            CAPTURE(unescaped_string);

            json j1, j2, j3, j4;
            CHECK_NOTHROW(j1 = json::parse("\"" + escaped_string + "\""));
            CHECK_NOTHROW(j2 = json::parse(j1.dump()));
            CHECK(j1 == j2);

            CHECK_NOTHROW(j3 = json::parse("\"" + unescaped_string + "\""));
            CHECK_NOTHROW(j4 = json::parse(j3.dump()));
            CHECK(j3 == j4);
        }
    }

    SECTION("read all unicode characters")
    {
        // read a file with all unicode characters stored as single-character
        // strings in a JSON array
        std::ifstream f("test/data/json_nlohmann_tests/all_unicode.json");
        json j;
        CHECK_NOTHROW(j << f);

        // the array has 1112064 + 1 elemnts (a terminating "null" value)
        // Note: 1112064 = 0x1FFFFF code points - 2048 invalid values between
        // 0xD800 and 0xDFFF.
        CHECK(j.size() == 1112065);

        SECTION("check JSON Pointers")
        {
            for (auto s : j)
            {
                // skip non-string JSON values
                if (not s.is_string())
                {
                    continue;
                }

                std::string ptr = s;

                // tilde must be followed by 0 or 1
                if (ptr == "~")
                {
                    ptr += "0";
                }

                // JSON Pointers must begin with "/"
                ptr = "/" + ptr;

                CHECK_NOTHROW(json::json_pointer("/" + ptr));

                // check escape/unescape roundtrip
                auto escaped = json::json_pointer::escape(ptr);
                json::json_pointer::unescape(escaped);
                CHECK(escaped == ptr);
            }
        }
    }

    SECTION("ignore byte-order-mark")
    {
        // read a file with a UTF-8 BOM
        std::ifstream f("test/data/json_nlohmann_tests/bom.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("error for incomplete/wrong BOM")
    {
        CHECK_THROWS_AS(json::parse("\xef\xbb"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\xef\xbb\xbb"), std::invalid_argument);
    }
}
