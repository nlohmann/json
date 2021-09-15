/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.2
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

// for some reason including this after the json header leads to linker errors with VS 2017...
#include <locale>
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <fstream>
#include <sstream>
#include <iomanip>
#include <test_data.hpp>

TEST_CASE("Unicode (1/5)" * doctest::skip())
{
    SECTION("\\uxxxx sequences")
    {
        // create an escaped string from a code point
        const auto codepoint_to_unicode = [](std::size_t cp)
        {
            // code points are represented as a six-character sequence: a
            // reverse solidus, followed by the lowercase letter u, followed
            // by four hexadecimal digits that encode the character's code
            // point
            std::stringstream ss;
            ss << "\\u" << std::setw(4) << std::setfill('0') << std::hex << cp;
            return ss.str();
        };

        SECTION("correct sequences")
        {
            // generate all UTF-8 code points; in total, 1112064 code points are
            // generated: 0x1FFFFF code points - 2048 invalid values between
            // 0xD800 and 0xDFFF.
            for (std::size_t cp = 0; cp <= 0x10FFFFu; ++cp)
            {
                // string to store the code point as in \uxxxx format
                std::string json_text = "\"";

                // decide whether to use one or two \uxxxx sequences
                if (cp < 0x10000u)
                {
                    // The Unicode standard permanently reserves these code point
                    // values for UTF-16 encoding of the high and low surrogates, and
                    // they will never be assigned a character, so there should be no
                    // reason to encode them. The official Unicode standard says that
                    // no UTF forms, including UTF-16, can encode these code points.
                    if (cp >= 0xD800u && cp <= 0xDFFFu)
                    {
                        // if we would not skip these code points, we would get a
                        // "missing low surrogate" exception
                        continue;
                    }

                    // code points in the Basic Multilingual Plane can be
                    // represented with one \uxxxx sequence
                    json_text += codepoint_to_unicode(cp);
                }
                else
                {
                    // To escape an extended character that is not in the Basic
                    // Multilingual Plane, the character is represented as a
                    // 12-character sequence, encoding the UTF-16 surrogate pair
                    const auto codepoint1 = 0xd800u + (((cp - 0x10000u) >> 10) & 0x3ffu);
                    const auto codepoint2 = 0xdc00u + ((cp - 0x10000u) & 0x3ffu);
                    json_text += codepoint_to_unicode(codepoint1) + codepoint_to_unicode(codepoint2);
                }

                json_text += "\"";
                CAPTURE(json_text)
                json _;
                CHECK_NOTHROW(_ = json::parse(json_text));
            }
        }

        SECTION("incorrect sequences")
        {
            SECTION("incorrect surrogate values")
            {
                json _;

                CHECK_THROWS_AS(_ = json::parse("\"\\uDC00\\uDC00\""), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::parse("\"\\uDC00\\uDC00\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - invalid string: surrogate U+DC00..U+DFFF must follow U+D800..U+DBFF; last read: '\"\\uDC00'");

                CHECK_THROWS_AS(_ = json::parse("\"\\uD7FF\\uDC00\""), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::parse("\"\\uD7FF\\uDC00\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+DC00..U+DFFF must follow U+D800..U+DBFF; last read: '\"\\uD7FF\\uDC00'");

                CHECK_THROWS_AS(_ = json::parse("\"\\uD800]\""), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::parse("\"\\uD800]\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD800]'");

                CHECK_THROWS_AS(_ = json::parse("\"\\uD800\\v\""), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::parse("\"\\uD800\\v\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 9: syntax error while parsing value - invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD800\\v'");

                CHECK_THROWS_AS(_ = json::parse("\"\\uD800\\u123\""), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::parse("\"\\uD800\\u123\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\uD800\\u123\"'");

                CHECK_THROWS_AS(_ = json::parse("\"\\uD800\\uDBFF\""), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::parse("\"\\uD800\\uDBFF\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD800\\uDBFF'");

                CHECK_THROWS_AS(_ = json::parse("\"\\uD800\\uE000\""), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::parse("\"\\uD800\\uE000\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD800\\uE000'");
            }
        }

#if 0
        SECTION("incorrect sequences")
        {
            SECTION("high surrogate without low surrogate")
            {
                // D800..DBFF are high surrogates and must be followed by low
                // surrogates DC00..DFFF; here, nothing follows
                for (std::size_t cp = 0xD800u; cp <= 0xDBFFu; ++cp)
                {
                    std::string json_text = "\"" + codepoint_to_unicode(cp) + "\"";
                    CAPTURE(json_text)
                    CHECK_THROWS_AS(json::parse(json_text), json::parse_error&);
                }
            }

            SECTION("high surrogate with wrong low surrogate")
            {
                // D800..DBFF are high surrogates and must be followed by low
                // surrogates DC00..DFFF; here a different sequence follows
                for (std::size_t cp1 = 0xD800u; cp1 <= 0xDBFFu; ++cp1)
                {
                    for (std::size_t cp2 = 0x0000u; cp2 <= 0xFFFFu; ++cp2)
                    {
                        if (0xDC00u <= cp2 && cp2 <= 0xDFFFu)
                        {
                            continue;
                        }

                        std::string json_text = "\"" + codepoint_to_unicode(cp1) + codepoint_to_unicode(cp2) + "\"";
                        CAPTURE(json_text)
                        CHECK_THROWS_AS(json::parse(json_text), json::parse_error&);
                    }
                }
            }

            SECTION("low surrogate without high surrogate")
            {
                // low surrogates DC00..DFFF must follow high surrogates; here,
                // they occur alone
                for (std::size_t cp = 0xDC00u; cp <= 0xDFFFu; ++cp)
                {
                    std::string json_text = "\"" + codepoint_to_unicode(cp) + "\"";
                    CAPTURE(json_text)
                    CHECK_THROWS_AS(json::parse(json_text), json::parse_error&);
                }
            }

        }
#endif
    }

    SECTION("read all unicode characters")
    {
        // read a file with all unicode characters stored as single-character
        // strings in a JSON array
        std::ifstream f(TEST_DATA_DIRECTORY "/json_nlohmann_tests/all_unicode.json");
        json j;
        CHECK_NOTHROW(f >> j);

        // the array has 1112064 + 1 elements (a terminating "null" value)
        // Note: 1112064 = 0x1FFFFF code points - 2048 invalid values between
        // 0xD800 and 0xDFFF.
        CHECK(j.size() == 1112065);

        SECTION("check JSON Pointers")
        {
            for (const auto& s : j)
            {
                // skip non-string JSON values
                if (!s.is_string())
                {
                    continue;
                }

                auto ptr = s.get<std::string>();

                // tilde must be followed by 0 or 1
                if (ptr == "~")
                {
                    ptr += "0";
                }

                // JSON Pointers must begin with "/"
                ptr.insert(0, "/");

                CHECK_NOTHROW(json::json_pointer("/" + ptr));

                // check escape/unescape roundtrip
                auto escaped = nlohmann::detail::escape(ptr);
                nlohmann::detail::unescape(escaped);
                CHECK(escaped == ptr);
            }
        }
    }

    SECTION("ignore byte-order-mark")
    {
        SECTION("in a stream")
        {
            // read a file with a UTF-8 BOM
            std::ifstream f(TEST_DATA_DIRECTORY "/json_nlohmann_tests/bom.json");
            json j;
            CHECK_NOTHROW(f >> j);
        }

        SECTION("with an iterator")
        {
            std::string i = "\xef\xbb\xbf{\n   \"foo\": true\n}";
            json _;
            CHECK_NOTHROW(_ = json::parse(i.begin(), i.end()));
        }
    }

    SECTION("error for incomplete/wrong BOM")
    {
        json _;
        CHECK_THROWS_AS(_ = json::parse("\xef\xbb"), json::parse_error&);
        CHECK_THROWS_AS(_ = json::parse("\xef\xbb\xbb"), json::parse_error&);
    }
}

namespace
{
void roundtrip(bool success_expected, const std::string& s);

void roundtrip(bool success_expected, const std::string& s)
{
    CAPTURE(s)
    json _;

    // create JSON string value
    json j = s;
    // create JSON text
    std::string ps = std::string("\"") + s + "\"";

    if (success_expected)
    {
        // serialization succeeds
        CHECK_NOTHROW(j.dump());

        // exclude parse test for U+0000
        if (s[0] != '\0')
        {
            // parsing JSON text succeeds
            CHECK_NOTHROW(_ = json::parse(ps));
        }

        // roundtrip succeeds
        CHECK_NOTHROW(_ = json::parse(j.dump()));

        // after roundtrip, the same string is stored
        json jr = json::parse(j.dump());
        CHECK(jr.get<std::string>() == s);
    }
    else
    {
        // serialization fails
        CHECK_THROWS_AS(j.dump(), json::type_error&);

        // parsing JSON text fails
        CHECK_THROWS_AS(_ = json::parse(ps), json::parse_error&);
    }
}
} // namespace

TEST_CASE("Markus Kuhn's UTF-8 decoder capability and stress test")
{
    // Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/> - 2015-08-28 - CC BY 4.0
    // http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt

    SECTION("1  Some correct UTF-8 text")
    {
        roundtrip(true, "κόσμε");
    }

    SECTION("2  Boundary condition test cases")
    {
        SECTION("2.1  First possible sequence of a certain length")
        {
            // 2.1.1  1 byte  (U-00000000)
            roundtrip(true, std::string("\0", 1));
            // 2.1.2  2 bytes (U-00000080)
            roundtrip(true, "\xc2\x80");
            // 2.1.3  3 bytes (U-00000800)
            roundtrip(true, "\xe0\xa0\x80");
            // 2.1.4  4 bytes (U-00010000)
            roundtrip(true, "\xf0\x90\x80\x80");

            // 2.1.5  5 bytes (U-00200000)
            roundtrip(false, "\xF8\x88\x80\x80\x80");
            // 2.1.6  6 bytes (U-04000000)
            roundtrip(false, "\xFC\x84\x80\x80\x80\x80");
        }

        SECTION("2.2  Last possible sequence of a certain length")
        {
            // 2.2.1  1 byte  (U-0000007F)
            roundtrip(true, "\x7f");
            // 2.2.2  2 bytes (U-000007FF)
            roundtrip(true, "\xdf\xbf");
            // 2.2.3  3 bytes (U-0000FFFF)
            roundtrip(true, "\xef\xbf\xbf");

            // 2.2.4  4 bytes (U-001FFFFF)
            roundtrip(false, "\xF7\xBF\xBF\xBF");
            // 2.2.5  5 bytes (U-03FFFFFF)
            roundtrip(false, "\xFB\xBF\xBF\xBF\xBF");
            // 2.2.6  6 bytes (U-7FFFFFFF)
            roundtrip(false, "\xFD\xBF\xBF\xBF\xBF\xBF");
        }

        SECTION("2.3  Other boundary conditions")
        {
            // 2.3.1  U-0000D7FF = ed 9f bf
            roundtrip(true, "\xed\x9f\xbf");
            // 2.3.2  U-0000E000 = ee 80 80
            roundtrip(true, "\xee\x80\x80");
            // 2.3.3  U-0000FFFD = ef bf bd
            roundtrip(true, "\xef\xbf\xbd");
            // 2.3.4  U-0010FFFF = f4 8f bf bf
            roundtrip(true, "\xf4\x8f\xbf\xbf");

            // 2.3.5  U-00110000 = f4 90 80 80
            roundtrip(false, "\xf4\x90\x80\x80");
        }
    }

    SECTION("3  Malformed sequences")
    {
        SECTION("3.1  Unexpected continuation bytes")
        {
            // Each unexpected continuation byte should be separately signalled as a
            // malformed sequence of its own.

            // 3.1.1  First continuation byte 0x80
            roundtrip(false, "\x80");
            // 3.1.2  Last  continuation byte 0xbf
            roundtrip(false, "\xbf");

            // 3.1.3  2 continuation bytes
            roundtrip(false, "\x80\xbf");
            // 3.1.4  3 continuation bytes
            roundtrip(false, "\x80\xbf\x80");
            // 3.1.5  4 continuation bytes
            roundtrip(false, "\x80\xbf\x80\xbf");
            // 3.1.6  5 continuation bytes
            roundtrip(false, "\x80\xbf\x80\xbf\x80");
            // 3.1.7  6 continuation bytes
            roundtrip(false, "\x80\xbf\x80\xbf\x80\xbf");
            // 3.1.8  7 continuation bytes
            roundtrip(false, "\x80\xbf\x80\xbf\x80\xbf\x80");

            // 3.1.9  Sequence of all 64 possible continuation bytes (0x80-0xbf)
            roundtrip(false, "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf");
        }

        SECTION("3.2  Lonely start characters")
        {
            // 3.2.1  All 32 first bytes of 2-byte sequences (0xc0-0xdf)
            roundtrip(false, "\xc0 \xc1 \xc2 \xc3 \xc4 \xc5 \xc6 \xc7 \xc8 \xc9 \xca \xcb \xcc \xcd \xce \xcf \xd0 \xd1 \xd2 \xd3 \xd4 \xd5 \xd6 \xd7 \xd8 \xd9 \xda \xdb \xdc \xdd \xde \xdf");
            // 3.2.2  All 16 first bytes of 3-byte sequences (0xe0-0xef)
            roundtrip(false, "\xe0 \xe1 \xe2 \xe3 \xe4 \xe5 \xe6 \xe7 \xe8 \xe9 \xea \xeb \xec \xed \xee \xef");
            // 3.2.3  All 8 first bytes of 4-byte sequences (0xf0-0xf7)
            roundtrip(false, "\xf0 \xf1 \xf2 \xf3 \xf4 \xf5 \xf6 \xf7");
            // 3.2.4  All 4 first bytes of 5-byte sequences (0xf8-0xfb)
            roundtrip(false, "\xf8 \xf9 \xfa \xfb");
            // 3.2.5  All 2 first bytes of 6-byte sequences (0xfc-0xfd)
            roundtrip(false, "\xfc \xfd");
        }

        SECTION("3.3  Sequences with last continuation byte missing")
        {
            // All bytes of an incomplete sequence should be signalled as a single
            // malformed sequence, i.e., you should see only a single replacement
            // character in each of the next 10 tests. (Characters as in section 2)

            // 3.3.1  2-byte sequence with last byte missing (U+0000)
            roundtrip(false, "\xc0");
            // 3.3.2  3-byte sequence with last byte missing (U+0000)
            roundtrip(false, "\xe0\x80");
            // 3.3.3  4-byte sequence with last byte missing (U+0000)
            roundtrip(false, "\xf0\x80\x80");
            // 3.3.4  5-byte sequence with last byte missing (U+0000)
            roundtrip(false, "\xf8\x80\x80\x80");
            // 3.3.5  6-byte sequence with last byte missing (U+0000)
            roundtrip(false, "\xfc\x80\x80\x80\x80");
            // 3.3.6  2-byte sequence with last byte missing (U-000007FF)
            roundtrip(false, "\xdf");
            // 3.3.7  3-byte sequence with last byte missing (U-0000FFFF)
            roundtrip(false, "\xef\xbf");
            // 3.3.8  4-byte sequence with last byte missing (U-001FFFFF)
            roundtrip(false, "\xf7\xbf\xbf");
            // 3.3.9  5-byte sequence with last byte missing (U-03FFFFFF)
            roundtrip(false, "\xfb\xbf\xbf\xbf");
            // 3.3.10 6-byte sequence with last byte missing (U-7FFFFFFF)
            roundtrip(false, "\xfd\xbf\xbf\xbf\xbf");
        }

        SECTION("3.4  Concatenation of incomplete sequences")
        {
            // All the 10 sequences of 3.3 concatenated, you should see 10 malformed
            // sequences being signalled:
            roundtrip(false, "\xc0\xe0\x80\xf0\x80\x80\xf8\x80\x80\x80\xfc\x80\x80\x80\x80\xdf\xef\xbf\xf7\xbf\xbf\xfb\xbf\xbf\xbf\xfd\xbf\xbf\xbf\xbf");
        }

        SECTION("3.5  Impossible bytes")
        {
            // The following two bytes cannot appear in a correct UTF-8 string

            // 3.5.1  fe
            roundtrip(false, "\xfe");
            // 3.5.2  ff
            roundtrip(false, "\xff");
            // 3.5.3  fe fe ff ff
            roundtrip(false, "\xfe\xfe\xff\xff");
        }
    }

    SECTION("4  Overlong sequences")
    {
        // The following sequences are not malformed according to the letter of
        // the Unicode 2.0 standard. However, they are longer then necessary and
        // a correct UTF-8 encoder is not allowed to produce them. A "safe UTF-8
        // decoder" should reject them just like malformed sequences for two
        // reasons: (1) It helps to debug applications if overlong sequences are
        // not treated as valid representations of characters, because this helps
        // to spot problems more quickly. (2) Overlong sequences provide
        // alternative representations of characters, that could maliciously be
        // used to bypass filters that check only for ASCII characters. For
        // instance, a 2-byte encoded line feed (LF) would not be caught by a
        // line counter that counts only 0x0a bytes, but it would still be
        // processed as a line feed by an unsafe UTF-8 decoder later in the
        // pipeline. From a security point of view, ASCII compatibility of UTF-8
        // sequences means also, that ASCII characters are *only* allowed to be
        // represented by ASCII bytes in the range 0x00-0x7f. To ensure this
        // aspect of ASCII compatibility, use only "safe UTF-8 decoders" that
        // reject overlong UTF-8 sequences for which a shorter encoding exists.

        SECTION("4.1  Examples of an overlong ASCII character")
        {
            // With a safe UTF-8 decoder, all of the following five overlong
            // representations of the ASCII character slash ("/") should be rejected
            // like a malformed UTF-8 sequence, for instance by substituting it with
            // a replacement character. If you see a slash below, you do not have a
            // safe UTF-8 decoder!

            // 4.1.1 U+002F = c0 af
            roundtrip(false, "\xc0\xaf");
            // 4.1.2 U+002F = e0 80 af
            roundtrip(false, "\xe0\x80\xaf");
            // 4.1.3 U+002F = f0 80 80 af
            roundtrip(false, "\xf0\x80\x80\xaf");
            // 4.1.4 U+002F = f8 80 80 80 af
            roundtrip(false, "\xf8\x80\x80\x80\xaf");
            // 4.1.5 U+002F = fc 80 80 80 80 af
            roundtrip(false, "\xfc\x80\x80\x80\x80\xaf");
        }

        SECTION("4.2  Maximum overlong sequences")
        {
            // Below you see the highest Unicode value that is still resulting in an
            // overlong sequence if represented with the given number of bytes. This
            // is a boundary test for safe UTF-8 decoders. All five characters should
            // be rejected like malformed UTF-8 sequences.

            // 4.2.1  U-0000007F = c1 bf
            roundtrip(false, "\xc1\xbf");
            // 4.2.2  U-000007FF = e0 9f bf
            roundtrip(false, "\xe0\x9f\xbf");
            // 4.2.3  U-0000FFFF = f0 8f bf bf
            roundtrip(false, "\xf0\x8f\xbf\xbf");
            // 4.2.4  U-001FFFFF = f8 87 bf bf bf
            roundtrip(false, "\xf8\x87\xbf\xbf\xbf");
            // 4.2.5  U-03FFFFFF = fc 83 bf bf bf bf
            roundtrip(false, "\xfc\x83\xbf\xbf\xbf\xbf");
        }

        SECTION("4.3  Overlong representation of the NUL character")
        {
            // The following five sequences should also be rejected like malformed
            // UTF-8 sequences and should not be treated like the ASCII NUL
            // character.

            // 4.3.1  U+0000 = c0 80
            roundtrip(false, "\xc0\x80");
            // 4.3.2  U+0000 = e0 80 80
            roundtrip(false, "\xe0\x80\x80");
            // 4.3.3  U+0000 = f0 80 80 80
            roundtrip(false, "\xf0\x80\x80\x80");
            // 4.3.4  U+0000 = f8 80 80 80 80
            roundtrip(false, "\xf8\x80\x80\x80\x80");
            // 4.3.5  U+0000 = fc 80 80 80 80 80
            roundtrip(false, "\xfc\x80\x80\x80\x80\x80");
        }
    }

    SECTION("5  Illegal code positions")
    {
        // The following UTF-8 sequences should be rejected like malformed
        // sequences, because they never represent valid ISO 10646 characters and
        // a UTF-8 decoder that accepts them might introduce security problems
        // comparable to overlong UTF-8 sequences.

        SECTION("5.1 Single UTF-16 surrogates")
        {
            // 5.1.1  U+D800 = ed a0 80
            roundtrip(false, "\xed\xa0\x80");
            // 5.1.2  U+DB7F = ed ad bf
            roundtrip(false, "\xed\xad\xbf");
            // 5.1.3  U+DB80 = ed ae 80
            roundtrip(false, "\xed\xae\x80");
            // 5.1.4  U+DBFF = ed af bf
            roundtrip(false, "\xed\xaf\xbf");
            // 5.1.5  U+DC00 = ed b0 80
            roundtrip(false, "\xed\xb0\x80");
            // 5.1.6  U+DF80 = ed be 80
            roundtrip(false, "\xed\xbe\x80");
            // 5.1.7  U+DFFF = ed bf bf
            roundtrip(false, "\xed\xbf\xbf");
        }

        SECTION("5.2 Paired UTF-16 surrogates")
        {
            // 5.2.1  U+D800 U+DC00 = ed a0 80 ed b0 80
            roundtrip(false, "\xed\xa0\x80\xed\xb0\x80");
            // 5.2.2  U+D800 U+DFFF = ed a0 80 ed bf bf
            roundtrip(false, "\xed\xa0\x80\xed\xbf\xbf");
            // 5.2.3  U+DB7F U+DC00 = ed ad bf ed b0 80
            roundtrip(false, "\xed\xad\xbf\xed\xb0\x80");
            // 5.2.4  U+DB7F U+DFFF = ed ad bf ed bf bf
            roundtrip(false, "\xed\xad\xbf\xed\xbf\xbf");
            // 5.2.5  U+DB80 U+DC00 = ed ae 80 ed b0 80
            roundtrip(false, "\xed\xae\x80\xed\xb0\x80");
            // 5.2.6  U+DB80 U+DFFF = ed ae 80 ed bf bf
            roundtrip(false, "\xed\xae\x80\xed\xbf\xbf");
            // 5.2.7  U+DBFF U+DC00 = ed af bf ed b0 80
            roundtrip(false, "\xed\xaf\xbf\xed\xb0\x80");
            // 5.2.8  U+DBFF U+DFFF = ed af bf ed bf bf
            roundtrip(false, "\xed\xaf\xbf\xed\xbf\xbf");
        }

        SECTION("5.3 Noncharacter code positions")
        {
            // The following "noncharacters" are "reserved for internal use" by
            // applications, and according to older versions of the Unicode Standard
            // "should never be interchanged". Unicode Corrigendum #9 dropped the
            // latter restriction. Nevertheless, their presence in incoming UTF-8 data
            // can remain a potential security risk, depending on what use is made of
            // these codes subsequently. Examples of such internal use:
            //
            //  - Some file APIs with 16-bit characters may use the integer value -1
            //    = U+FFFF to signal an end-of-file (EOF) or error condition.
            //
            //  - In some UTF-16 receivers, code point U+FFFE might trigger a
            //    byte-swap operation (to convert between UTF-16LE and UTF-16BE).
            //
            // With such internal use of noncharacters, it may be desirable and safer
            // to block those code points in UTF-8 decoders, as they should never
            // occur legitimately in incoming UTF-8 data, and could trigger unsafe
            // behaviour in subsequent processing.

            // Particularly problematic noncharacters in 16-bit applications:

            // 5.3.1  U+FFFE = ef bf be
            roundtrip(true, "\xef\xbf\xbe");
            // 5.3.2  U+FFFF = ef bf bf
            roundtrip(true, "\xef\xbf\xbf");

            // 5.3.3  U+FDD0 .. U+FDEF
            roundtrip(true, "\xEF\xB7\x90");
            roundtrip(true, "\xEF\xB7\x91");
            roundtrip(true, "\xEF\xB7\x92");
            roundtrip(true, "\xEF\xB7\x93");
            roundtrip(true, "\xEF\xB7\x94");
            roundtrip(true, "\xEF\xB7\x95");
            roundtrip(true, "\xEF\xB7\x96");
            roundtrip(true, "\xEF\xB7\x97");
            roundtrip(true, "\xEF\xB7\x98");
            roundtrip(true, "\xEF\xB7\x99");
            roundtrip(true, "\xEF\xB7\x9A");
            roundtrip(true, "\xEF\xB7\x9B");
            roundtrip(true, "\xEF\xB7\x9C");
            roundtrip(true, "\xEF\xB7\x9D");
            roundtrip(true, "\xEF\xB7\x9E");
            roundtrip(true, "\xEF\xB7\x9F");
            roundtrip(true, "\xEF\xB7\xA0");
            roundtrip(true, "\xEF\xB7\xA1");
            roundtrip(true, "\xEF\xB7\xA2");
            roundtrip(true, "\xEF\xB7\xA3");
            roundtrip(true, "\xEF\xB7\xA4");
            roundtrip(true, "\xEF\xB7\xA5");
            roundtrip(true, "\xEF\xB7\xA6");
            roundtrip(true, "\xEF\xB7\xA7");
            roundtrip(true, "\xEF\xB7\xA8");
            roundtrip(true, "\xEF\xB7\xA9");
            roundtrip(true, "\xEF\xB7\xAA");
            roundtrip(true, "\xEF\xB7\xAB");
            roundtrip(true, "\xEF\xB7\xAC");
            roundtrip(true, "\xEF\xB7\xAD");
            roundtrip(true, "\xEF\xB7\xAE");
            roundtrip(true, "\xEF\xB7\xAF");

            // 5.3.4  U+nFFFE U+nFFFF (for n = 1..10)
            roundtrip(true, "\xF0\x9F\xBF\xBF");
            roundtrip(true, "\xF0\xAF\xBF\xBF");
            roundtrip(true, "\xF0\xBF\xBF\xBF");
            roundtrip(true, "\xF1\x8F\xBF\xBF");
            roundtrip(true, "\xF1\x9F\xBF\xBF");
            roundtrip(true, "\xF1\xAF\xBF\xBF");
            roundtrip(true, "\xF1\xBF\xBF\xBF");
            roundtrip(true, "\xF2\x8F\xBF\xBF");
            roundtrip(true, "\xF2\x9F\xBF\xBF");
            roundtrip(true, "\xF2\xAF\xBF\xBF");
        }
    }
}
