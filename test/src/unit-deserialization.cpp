/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.1.0
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2018 Niels Lohmann <http://nlohmann.me>.

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

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <iostream>
#include <valarray>

TEST_CASE("deserialization")
{
    SECTION("successful deserialization")
    {
        SECTION("stream")
        {
            std::stringstream ss1, ss2;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}]";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(ss1);
            CHECK(json::accept(ss2));
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }

        SECTION("string literal")
        {
            auto s = "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(s);
            CHECK(json::accept(s));
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }

        SECTION("string_t")
        {
            json::string_t s = "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(s);
            CHECK(json::accept(s));
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }

        SECTION("operator<<")
        {
            std::stringstream ss;
            ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j;
            j << ss;
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }

        SECTION("operator>>")
        {
            std::stringstream ss;
            ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j;
            ss >> j;
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }

        SECTION("user-defined string literal")
        {
            CHECK("[\"foo\",1,2,3,false,{\"one\":1}]"_json == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }
    }

    SECTION("unsuccessful deserialization")
    {
        SECTION("stream")
        {
            std::stringstream ss1, ss2, ss3, ss4;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss3 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss4 << "[\"foo\",1,2,3,false,{\"one\":1}";
            CHECK_THROWS_AS(json::parse(ss1), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(ss2),
                              "[json.exception.parse_error.101] parse error at 29: syntax error - unexpected end of input; expected ']'");
            CHECK(not json::accept(ss3));

            json j_error;
            CHECK_NOTHROW(j_error = json::parse(ss1, nullptr, false));
            CHECK(j_error.is_discarded());
        }

        SECTION("string")
        {
            json::string_t s = "[\"foo\",1,2,3,false,{\"one\":1}";
            CHECK_THROWS_AS(json::parse(s), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(s),
                              "[json.exception.parse_error.101] parse error at 29: syntax error - unexpected end of input; expected ']'");
            CHECK(not json::accept(s));

            json j_error;
            CHECK_NOTHROW(j_error = json::parse(s, nullptr, false));
            CHECK(j_error.is_discarded());
        }

        SECTION("operator<<")
        {
            std::stringstream ss1, ss2;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            json j;
            CHECK_THROWS_AS(j << ss1, json::parse_error&);
            CHECK_THROWS_WITH(j << ss2,
                              "[json.exception.parse_error.101] parse error at 29: syntax error - unexpected end of input; expected ']'");
        }

        SECTION("operator>>")
        {
            std::stringstream ss1, ss2;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            json j;
            CHECK_THROWS_AS(ss1 >> j, json::parse_error&);
            CHECK_THROWS_WITH(ss2 >> j,
                              "[json.exception.parse_error.101] parse error at 29: syntax error - unexpected end of input; expected ']'");
        }

        SECTION("user-defined string literal")
        {
            CHECK_THROWS_AS("[\"foo\",1,2,3,false,{\"one\":1}"_json, json::parse_error&);
            CHECK_THROWS_WITH("[\"foo\",1,2,3,false,{\"one\":1}"_json,
                              "[json.exception.parse_error.101] parse error at 29: syntax error - unexpected end of input; expected ']'");
        }
    }

    SECTION("contiguous containers")
    {
        SECTION("directly")
        {
            SECTION("from std::vector")
            {
                std::vector<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));
            }

            SECTION("from std::array")
            {
                std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));
            }

            SECTION("from array")
            {
                uint8_t v[] = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));
            }

            SECTION("from chars")
            {
                uint8_t* v = new uint8_t[5];
                v[0] = 't';
                v[1] = 'r';
                v[2] = 'u';
                v[3] = 'e';
                v[4] = '\0';
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));
                delete[] v;
            }

            SECTION("from std::string")
            {
                std::string v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));
            }

            SECTION("from std::initializer_list")
            {
                std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));
            }

            SECTION("empty container")
            {
                std::vector<uint8_t> v;
                CHECK_THROWS_AS(json::parse(v), json::parse_error&);
                CHECK(not json::accept(v));
            }
        }

        SECTION("via iterator range")
        {
            SECTION("from std::vector")
            {
                std::vector<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));
            }

            SECTION("from std::array")
            {
                std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));
            }

            SECTION("from array")
            {
                uint8_t v[] = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));
            }

            SECTION("from std::string")
            {
                std::string v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));
            }

            SECTION("from std::initializer_list")
            {
                std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));
            }

            SECTION("from std::valarray")
            {
                std::valarray<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));
            }

            SECTION("with empty range")
            {
                std::vector<uint8_t> v;
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));
            }
        }

        // these cases are required for 100% line coverage
        SECTION("error cases")
        {
            SECTION("case 1")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', '\\', 'u'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 2")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', '\\', 'u', '1'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 3")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', '\\', 'u', '1', '1', '1', '1', '1', '1', '1', '1'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 4")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', 'u', '1', '1', '1', '1', '1', '1', '1', '1', '\\'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 5")
            {
                uint8_t v[] = {'\"', 0x7F, 0xC1};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 6")
            {
                uint8_t v[] = {'\"', 0x7F, 0xDF, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK_THROWS_WITH(json::parse(std::begin(v), std::end(v)),
                                  "[json.exception.parse_error.101] parse error at 4: syntax error - invalid string: ill-formed UTF-8 byte; last read: '\"\x7f\xdf\x7f'");
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 7")
            {
                uint8_t v[] = {'\"', 0x7F, 0xDF, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 8")
            {
                uint8_t v[] = {'\"', 0x7F, 0xE0, 0x9F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 9")
            {
                uint8_t v[] = {'\"', 0x7F, 0xEF, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 10")
            {
                uint8_t v[] = {'\"', 0x7F, 0xED, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 11")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF0, 0x8F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 12")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF0, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 13")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF3, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 14")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF3, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 15")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF4, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }

            SECTION("case 16")
            {
                uint8_t v[] = {'{', '\"', '\"', ':', '1', '1'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());
            }
        }
    }

    SECTION("ignoring byte-order marks")
    {
        std::string bom = "\xEF\xBB\xBF";

        SECTION("BOM only")
        {
            CHECK_THROWS_AS(json::parse(bom), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(bom),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");

            CHECK_THROWS_AS(json::parse(std::istringstream(bom)), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom)),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
        }

        SECTION("BOM and content")
        {
            CHECK(json::parse(bom + "1") == 1);
            CHECK(json::parse(std::istringstream(bom + "1")) == 1);
        }

        SECTION("2 byte of BOM")
        {
            CHECK_THROWS_AS(json::parse(bom.substr(0, 2)), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(bom),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");

            CHECK_THROWS_AS(json::parse(std::istringstream(bom.substr(0, 2))), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom)),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
        }

        SECTION("1 byte of BOM")
        {
            CHECK_THROWS_AS(json::parse(bom.substr(0, 1)), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(bom),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");

            CHECK_THROWS_AS(json::parse(std::istringstream(bom.substr(0, 1))), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom)),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
        }

        SECTION("variations")
        {
            // calculate variations of each byte of the BOM to make sure
            // that the BOM and only the BOM is skipped
            for (int i0 = -1; i0 < 2; ++i0)
            {
                for (int i1 = -1; i1 < 2; ++i1)
                {
                    for (int i2 = -1; i2 < 2; ++i2)
                    {
                        // debug output for the variations
                        CAPTURE(i0);
                        CAPTURE(i1);
                        CAPTURE(i2);

                        std::string s = "";
                        s.push_back(static_cast<char>(bom[0] + i0));
                        s.push_back(static_cast<char>(bom[1] + i1));
                        s.push_back(static_cast<char>(bom[2] + i2));

                        if (i0 == 0 and i1 == 0 and i2 == 0)
                        {
                            // without any variation, we skip the BOM
                            CHECK(json::parse(s + "null") == json());
                            CHECK(json::parse(std::istringstream(s + "null")) == json());
                        }
                        else
                        {
                            // any variation is an error
                            CHECK_THROWS_AS(json::parse(s + "null"), json::parse_error&);
                            CHECK_THROWS_AS(json::parse(std::istringstream(s + "null")), json::parse_error&);
                        }
                    }
                }
            }
        }

        SECTION("preserve state after parsing")
        {
            std::istringstream s(bom + "123 456");
            json j;
            j << s;
            CHECK(j == 123);
            j << s;
            CHECK(j == 456);
        }
    }
}
