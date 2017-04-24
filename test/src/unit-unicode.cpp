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

#include <fstream>

// create and check a JSON string with up to four UTF-8 bytes
void check_utf8string(bool success_expected, int byte1, int byte2 = -1, int byte3 = -1, int byte4 = -1)
{
    std::string json_string = "\"";

    CAPTURE(byte1);
    json_string += std::string(1, static_cast<char>(byte1));

    if (byte2 != -1)
    {
        CAPTURE(byte2);
        json_string += std::string(1, static_cast<char>(byte2));
    }

    if (byte3 != -1)
    {
        CAPTURE(byte3);
        json_string += std::string(1, static_cast<char>(byte3));
    }

    if (byte4 != -1)
    {
        CAPTURE(byte4);
        json_string += std::string(1, static_cast<char>(byte4));
    }

    json_string += "\"";

    CAPTURE(json_string);

    if (success_expected)
    {
        CHECK_NOTHROW(json::parse(json_string));
    }
    else
    {
        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
    }
}

TEST_CASE("Unicode", "[hide]")
{
    SECTION("RFC 3629")
    {
        /*
        RFC 3629 describes in Sect. 4 the syntax of UTF-8 byte sequences as
        follows:

            A UTF-8 string is a sequence of octets representing a sequence of UCS
            characters.  An octet sequence is valid UTF-8 only if it matches the
            following syntax, which is derived from the rules for encoding UTF-8
            and is expressed in the ABNF of [RFC2234].

            UTF8-octets = *( UTF8-char )
            UTF8-char   = UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4
            UTF8-1      = %x00-7F
            UTF8-2      = %xC2-DF UTF8-tail
            UTF8-3      = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
                          %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
            UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /
                          %xF4 %x80-8F 2( UTF8-tail )
            UTF8-tail   = %x80-BF
        */

        SECTION("ill-formed first byte")
        {
            for (int byte1 = 0x80; byte1 <= 0xC1; ++byte1)
            {
                check_utf8string(false, byte1);
            }

            for (int byte1 = 0xF5; byte1 <= 0xFF; ++byte1)
            {
                check_utf8string(false, byte1);
            }
        }

        SECTION("UTF8-1 (x00-x7F)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0x00; byte1 <= 0x7F; ++byte1)
                {
                    // unescaped control characters are parse errors in JSON
                    if (0x00 <= byte1 and byte1 <= 0x1F)
                    {
                        check_utf8string(false, byte1);
                        continue;
                    }

                    // a single quote is a parse error in JSON
                    if (byte1 == 0x22)
                    {
                        check_utf8string(false, byte1);
                        continue;
                    }

                    // a single backslash is a parse error in JSON
                    if (byte1 == 0x5C)
                    {
                        check_utf8string(false, byte1);
                        continue;
                    }

                    // all other characters are OK
                    check_utf8string(true, byte1);
                }
            }
        }

        SECTION("UTF8-2 (xC2-xDF UTF8-tail)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0xC2; byte1 <= 0xDF; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        check_utf8string(true, byte1, byte2);
                    }
                }
            }

            SECTION("ill-formed: missing second byte")
            {
                for (int byte1 = 0xC2; byte1 <= 0xDF; ++byte1)
                {
                    check_utf8string(false, byte1);
                }
            }

            SECTION("ill-formed: wrong second byte")
            {
                for (int byte1 = 0xC2; byte1 <= 0xDF; ++byte1)
                {
                    for (int byte2 = 0x00; byte2 <= 0xFF; ++byte2)
                    {
                        // skip correct second byte
                        if (0x80 <= byte2 and byte2 <= 0xBF)
                        {
                            continue;
                        }

                        check_utf8string(false, byte1, byte2);
                    }
                }
            }
        }

        SECTION("UTF8-3 (xE0 xA0-BF UTF8-tail)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0xE0; byte1 <= 0xE0; ++byte1)
                {
                    for (int byte2 = 0xA0; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(true, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: missing second byte")
            {
                for (int byte1 = 0xE0; byte1 <= 0xE0; ++byte1)
                {
                    check_utf8string(false, byte1);
                }
            }

            SECTION("ill-formed: missing third byte")
            {
                for (int byte1 = 0xE0; byte1 <= 0xE0; ++byte1)
                {
                    for (int byte2 = 0xA0; byte2 <= 0xBF; ++byte2)
                    {
                        check_utf8string(false, byte1, byte2);
                    }
                }
            }

            SECTION("ill-formed: wrong second byte")
            {
                for (int byte1 = 0xE0; byte1 <= 0xE0; ++byte1)
                {
                    for (int byte2 = 0x00; byte2 <= 0xFF; ++byte2)
                    {
                        // skip correct second byte
                        if (0xA0 <= byte2 and byte2 <= 0xBF)
                        {
                            continue;
                        }

                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong third byte")
            {
                for (int byte1 = 0xE0; byte1 <= 0xE0; ++byte1)
                {
                    for (int byte2 = 0xA0; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x00; byte3 <= 0xFF; ++byte3)
                        {
                            // skip correct third byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }
        }

        SECTION("UTF8-3 (xE1-xEC UTF8-tail UTF8-tail)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0xE1; byte1 <= 0xEC; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(true, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: missing second byte")
            {
                for (int byte1 = 0xE1; byte1 <= 0xEC; ++byte1)
                {
                    check_utf8string(false, byte1);
                }
            }

            SECTION("ill-formed: missing third byte")
            {
                for (int byte1 = 0xE1; byte1 <= 0xEC; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        check_utf8string(false, byte1, byte2);
                    }
                }
            }

            SECTION("ill-formed: wrong second byte")
            {
                for (int byte1 = 0xE1; byte1 <= 0xEC; ++byte1)
                {
                    for (int byte2 = 0x00; byte2 <= 0xFF; ++byte2)
                    {
                        // skip correct second byte
                        if (0x80 <= byte2 and byte2 <= 0xBF)
                        {
                            continue;
                        }

                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong third byte")
            {
                for (int byte1 = 0xE1; byte1 <= 0xEC; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x00; byte3 <= 0xFF; ++byte3)
                        {
                            // skip correct third byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }
        }

        SECTION("UTF8-3 (xED x80-9F UTF8-tail)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0xED; byte1 <= 0xED; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0x9F; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(true, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: missing second byte")
            {
                for (int byte1 = 0xED; byte1 <= 0xED; ++byte1)
                {
                    check_utf8string(false, byte1);
                }
            }

            SECTION("ill-formed: missing third byte")
            {
                for (int byte1 = 0xED; byte1 <= 0xED; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0x9F; ++byte2)
                    {
                        check_utf8string(false, byte1, byte2);
                    }
                }
            }

            SECTION("ill-formed: wrong second byte")
            {
                for (int byte1 = 0xED; byte1 <= 0xED; ++byte1)
                {
                    for (int byte2 = 0x00; byte2 <= 0xFF; ++byte2)
                    {
                        // skip correct second byte
                        if (0x80 <= byte2 and byte2 <= 0x9F)
                        {
                            continue;
                        }

                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong third byte")
            {
                for (int byte1 = 0xED; byte1 <= 0xED; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0x9F; ++byte2)
                    {
                        for (int byte3 = 0x00; byte3 <= 0xFF; ++byte3)
                        {
                            // skip correct third byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }
        }

        SECTION("UTF8-3 (xEE-xEF UTF8-tail UTF8-tail)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0xEE; byte1 <= 0xEF; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(true, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: missing second byte")
            {
                for (int byte1 = 0xEE; byte1 <= 0xEF; ++byte1)
                {
                    check_utf8string(false, byte1);
                }
            }

            SECTION("ill-formed: missing third byte")
            {
                for (int byte1 = 0xEE; byte1 <= 0xEF; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        check_utf8string(false, byte1, byte2);
                    }
                }
            }

            SECTION("ill-formed: wrong second byte")
            {
                for (int byte1 = 0xEE; byte1 <= 0xEF; ++byte1)
                {
                    for (int byte2 = 0x00; byte2 <= 0xFF; ++byte2)
                    {
                        // skip correct second byte
                        if (0x80 <= byte2 and byte2 <= 0xBF)
                        {
                            continue;
                        }

                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong third byte")
            {
                for (int byte1 = 0xEE; byte1 <= 0xEF; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x00; byte3 <= 0xFF; ++byte3)
                        {
                            // skip correct third byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }
        }

        SECTION("UTF8-4 (xF0 x90-BF UTF8-tail UTF8-tail)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
                {
                    for (int byte2 = 0x90; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(true, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: missing second byte")
            {
                for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
                {
                    check_utf8string(false, byte1);
                }
            }

            SECTION("ill-formed: missing third byte")
            {
                for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
                {
                    for (int byte2 = 0x90; byte2 <= 0xBF; ++byte2)
                    {
                        check_utf8string(false, byte1, byte2);
                    }
                }
            }

            SECTION("ill-formed: missing fourth byte")
            {
                for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
                {
                    for (int byte2 = 0x90; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong second byte")
            {
                for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
                {
                    for (int byte2 = 0x00; byte2 <= 0xFF; ++byte2)
                    {
                        // skip correct second byte
                        if (0x90 <= byte2 and byte2 <= 0xBF)
                        {
                            continue;
                        }

                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong third byte")
            {
                for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
                {
                    for (int byte2 = 0x90; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x00; byte3 <= 0xFF; ++byte3)
                        {
                            // skip correct third byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong fourth byte")
            {
                for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
                {
                    for (int byte2 = 0x90; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x00; byte4 <= 0xFF; ++byte4)
                            {
                                // skip fourth second byte
                                if (0x80 <= byte3 and byte3 <= 0xBF)
                                {
                                    continue;
                                }

                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }
        }

        SECTION("UTF8-4 (xF1-F3 UTF8-tail UTF8-tail UTF8-tail)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(true, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: missing second byte")
            {
                for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
                {
                    check_utf8string(false, byte1);
                }
            }

            SECTION("ill-formed: missing third byte")
            {
                for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        check_utf8string(false, byte1, byte2);
                    }
                }
            }

            SECTION("ill-formed: missing fourth byte")
            {
                for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong second byte")
            {
                for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
                {
                    for (int byte2 = 0x00; byte2 <= 0xFF; ++byte2)
                    {
                        // skip correct second byte
                        if (0x80 <= byte2 and byte2 <= 0xBF)
                        {
                            continue;
                        }

                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong third byte")
            {
                for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x00; byte3 <= 0xFF; ++byte3)
                        {
                            // skip correct third byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong fourth byte")
            {
                for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x00; byte4 <= 0xFF; ++byte4)
                            {
                                // skip correct fourth byte
                                if (0x80 <= byte3 and byte3 <= 0xBF)
                                {
                                    continue;
                                }

                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }
        }

        SECTION("UTF8-4 (xF4 x80-8F UTF8-tail UTF8-tail)")
        {
            SECTION("well-formed")
            {
                for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0x8F; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(true, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: missing second byte")
            {
                for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
                {
                    check_utf8string(false, byte1);
                }
            }

            SECTION("ill-formed: missing third byte")
            {
                for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0x8F; ++byte2)
                    {
                        check_utf8string(false, byte1, byte2);
                    }
                }
            }

            SECTION("ill-formed: missing fourth byte")
            {
                for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0x8F; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            check_utf8string(false, byte1, byte2, byte3);
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong second byte")
            {
                for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
                {
                    for (int byte2 = 0x00; byte2 <= 0xFF; ++byte2)
                    {
                        // skip correct second byte
                        if (0x80 <= byte2 and byte2 <= 0x8F)
                        {
                            continue;
                        }

                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong third byte")
            {
                for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0x8F; ++byte2)
                    {
                        for (int byte3 = 0x00; byte3 <= 0xFF; ++byte3)
                        {
                            // skip correct third byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            for (int byte4 = 0x80; byte4 <= 0xBF; ++byte4)
                            {
                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }

            SECTION("ill-formed: wrong fourth byte")
            {
                for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
                {
                    for (int byte2 = 0x80; byte2 <= 0x8F; ++byte2)
                    {
                        for (int byte3 = 0x80; byte3 <= 0xBF; ++byte3)
                        {
                            for (int byte4 = 0x00; byte4 <= 0xFF; ++byte4)
                            {
                                // skip correct fourth byte
                                if (0x80 <= byte3 and byte3 <= 0xBF)
                                {
                                    continue;
                                }

                                check_utf8string(false, byte1, byte2, byte3, byte4);
                            }
                        }
                    }
                }
            }
        }
    }

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
                    if (cp >= 0xD800u and cp <= 0xDFFFu)
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
                CAPTURE(json_text);
                CHECK_NOTHROW(json::parse(json_text));
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
                    CAPTURE(json_text);
                    CHECK_THROWS_AS(json::parse(json_text), json::parse_error);
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
                        if (0xDC00u <= cp2 and cp2 <= 0xDFFFu)
                        {
                            continue;
                        }

                        std::string json_text = "\"" + codepoint_to_unicode(cp1) + codepoint_to_unicode(cp2) + "\"";
                        CAPTURE(json_text);
                        CHECK_THROWS_AS(json::parse(json_text), json::parse_error);
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
                    CAPTURE(json_text);
                    CHECK_THROWS_AS(json::parse(json_text), json::parse_error);
                }
            }

        }
#endif
    }

    SECTION("read all unicode characters")
    {
        // read a file with all unicode characters stored as single-character
        // strings in a JSON array
        std::ifstream f("test/data/json_nlohmann_tests/all_unicode.json");
        json j;
        CHECK_NOTHROW(f >> j);

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
        CHECK_NOTHROW(f >> j);
    }

    SECTION("error for incomplete/wrong BOM")
    {
        CHECK_THROWS_AS(json::parse("\xef\xbb"), json::parse_error);
        CHECK_THROWS_AS(json::parse("\xef\xbb\xbb"), json::parse_error);
    }
}
