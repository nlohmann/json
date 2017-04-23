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

TEST_CASE("RFC 3629", "[hide]")
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

    auto create_string = [](int byte1, int byte2 = -1, int byte3 = -1, int byte4 = -1)
    {
        std::string result = "\"" + std::string(1, static_cast<char>(byte1));
        if (byte2 != -1)
        {
            result += std::string(1, static_cast<char>(byte2));
        }
        if (byte3 != -1)
        {
            result += std::string(1, static_cast<char>(byte3));
        }
        if (byte4 != -1)
        {
            result += std::string(1, static_cast<char>(byte4));
        }
        result += "\"";
        return result;
    };

    SECTION("ill-formed first byte")
    {
        for (int byte1 = 0x80; byte1 <= 0xC1; ++byte1)
        {
            const auto json_string = create_string(byte1);
            CAPTURE(byte1);
            CAPTURE(json_string);
            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
        }

        for (int byte1 = 0xF5; byte1 <= 0xFF; ++byte1)
        {
            const auto json_string = create_string(byte1);
            CAPTURE(byte1);
            CAPTURE(json_string);
            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
        }
    }

    SECTION("UTF8-1 (x00-x7F)")
    {
        SECTION("well-formed")
        {
            for (int byte1 = 0x00; byte1 <= 0x7F; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);

                // unescaped control characters are parse errors in JSON
                if (0x00 <= byte1 and byte1 <= 0x1F)
                {
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
                    continue;
                }

                // a single quote is a parse error in JSON
                if (byte1 == 0x22)
                {
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
                    continue;
                }

                // a single backslash is a parse error in JSON
                if (byte1 == 0x5C)
                {
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
                    continue;
                }

                // all other characters are OK
                CHECK_NOTHROW(json::parse(json_string));
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
                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_NOTHROW(json::parse(json_string));
                }
            }
        }

        SECTION("ill-formed: missing second byte")
        {
            for (int byte1 = 0xC2; byte1 <= 0xDF; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);
                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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

                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_NOTHROW(json::parse(json_string));
                    }
                }
            }
        }

        SECTION("ill-formed: missing second byte")
        {
            for (int byte1 = 0xE0; byte1 <= 0xE0; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);
                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
            }
        }

        SECTION("ill-formed: missing third byte")
        {
            for (int byte1 = 0xE0; byte1 <= 0xE0; ++byte1)
            {
                for (int byte2 = 0xA0; byte2 <= 0xBF; ++byte2)
                {
                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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

                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_NOTHROW(json::parse(json_string));
                    }
                }
            }
        }

        SECTION("ill-formed: missing second byte")
        {
            for (int byte1 = 0xE1; byte1 <= 0xEC; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);
                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
            }
        }

        SECTION("ill-formed: missing third byte")
        {
            for (int byte1 = 0xE1; byte1 <= 0xEC; ++byte1)
            {
                for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                {
                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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

                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_NOTHROW(json::parse(json_string));
                    }
                }
            }
        }

        SECTION("ill-formed: missing second byte")
        {
            for (int byte1 = 0xED; byte1 <= 0xED; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);
                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
            }
        }

        SECTION("ill-formed: missing third byte")
        {
            for (int byte1 = 0xED; byte1 <= 0xED; ++byte1)
            {
                for (int byte2 = 0x80; byte2 <= 0x9F; ++byte2)
                {
                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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

                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_NOTHROW(json::parse(json_string));
                    }
                }
            }
        }

        SECTION("ill-formed: missing second byte")
        {
            for (int byte1 = 0xEE; byte1 <= 0xEF; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);
                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
            }
        }

        SECTION("ill-formed: missing third byte")
        {
            for (int byte1 = 0xEE; byte1 <= 0xEF; ++byte1)
            {
                for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                {
                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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

                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_NOTHROW(json::parse(json_string));
                        }
                    }
                }
            }
        }

        SECTION("ill-formed: missing second byte")
        {
            for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);
                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
            }
        }

        SECTION("ill-formed: missing third byte")
        {
            for (int byte1 = 0xF0; byte1 <= 0xF0; ++byte1)
            {
                for (int byte2 = 0x90; byte2 <= 0xBF; ++byte2)
                {
                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        {
                            for (int byte4 = 0x00; byte4 <= 0xFF; ++byte4)
                            {
                                // skip correct second byte
                                if (0x80 <= byte3 and byte3 <= 0xBF)
                                {
                                    continue;
                                }

                                const auto json_string = create_string(byte1, byte2, byte3, byte4);
                                CAPTURE(byte1);
                                CAPTURE(byte2);
                                CAPTURE(byte3);
                                CAPTURE(byte4);
                                CAPTURE(json_string);
                                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
                            }
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_NOTHROW(json::parse(json_string));
                        }
                    }
                }
            }
        }

        SECTION("ill-formed: missing second byte")
        {
            for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);
                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
            }
        }

        SECTION("ill-formed: missing third byte")
        {
            for (int byte1 = 0xF1; byte1 <= 0xF3; ++byte1)
            {
                for (int byte2 = 0x80; byte2 <= 0xBF; ++byte2)
                {
                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            // skip correct second byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_NOTHROW(json::parse(json_string));
                        }
                    }
                }
            }
        }

        SECTION("ill-formed: missing second byte")
        {
            for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
            {
                const auto json_string = create_string(byte1);
                CAPTURE(byte1);
                CAPTURE(json_string);
                CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
            }
        }

        SECTION("ill-formed: missing third byte")
        {
            for (int byte1 = 0xF4; byte1 <= 0xF4; ++byte1)
            {
                for (int byte2 = 0x80; byte2 <= 0x8F; ++byte2)
                {
                    const auto json_string = create_string(byte1, byte2);
                    CAPTURE(byte1);
                    CAPTURE(byte2);
                    CAPTURE(json_string);
                    CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                        const auto json_string = create_string(byte1, byte2, byte3);
                        CAPTURE(byte1);
                        CAPTURE(byte2);
                        CAPTURE(byte3);
                        CAPTURE(json_string);
                        CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
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
                            // skip correct second byte
                            if (0x80 <= byte3 and byte3 <= 0xBF)
                            {
                                continue;
                            }

                            const auto json_string = create_string(byte1, byte2, byte3, byte4);
                            CAPTURE(byte1);
                            CAPTURE(byte2);
                            CAPTURE(byte3);
                            CAPTURE(byte4);
                            CAPTURE(json_string);
                            CHECK_THROWS_AS(json::parse(json_string), json::parse_error);
                        }
                    }
                }
            }
        }
    }
}

TEST_CASE("Unicode", "[hide]")
{
    /* NOTE: to_unicode is not used any more
    SECTION("full enumeration of Unicode code points")
    {
        // lexer to call to_unicode on
        json::lexer dummy_lexer("", 0);

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
                    unescaped_string = dummy_lexer.to_unicode(cp);
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
                unescaped_string += dummy_lexer.to_unicode(codepoint1, codepoint2);
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
     */

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
