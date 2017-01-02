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

#include "json.hpp"
using nlohmann::json;

#include <valarray>

TEST_CASE("deserialization")
{
    SECTION("successful deserialization")
    {
        SECTION("stream")
        {
            std::stringstream ss;
            ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(ss);
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }

        SECTION("string literal")
        {
            auto s = "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(s);
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
        }

        SECTION("string_t")
        {
            json::string_t s = "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(s);
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
            std::stringstream ss1, ss2;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            CHECK_THROWS_AS(json::parse(ss1), std::invalid_argument);
            CHECK_THROWS_WITH(json::parse(ss2), "parse error - unexpected end of input; expected ']'");
        }

        SECTION("string")
        {
            json::string_t s = "[\"foo\",1,2,3,false,{\"one\":1}";
            CHECK_THROWS_AS(json::parse(s), std::invalid_argument);
            CHECK_THROWS_WITH(json::parse(s), "parse error - unexpected end of input; expected ']'");
        }

        SECTION("operator<<")
        {
            std::stringstream ss1, ss2;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            json j;
            CHECK_THROWS_AS(j << ss1, std::invalid_argument);
            CHECK_THROWS_WITH(j << ss2, "parse error - unexpected end of input; expected ']'");
        }

        SECTION("operator>>")
        {
            std::stringstream ss1, ss2;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            json j;
            CHECK_THROWS_AS(ss1 >> j, std::invalid_argument);
            CHECK_THROWS_WITH(ss2 >> j, "parse error - unexpected end of input; expected ']'");
        }

        SECTION("user-defined string literal")
        {
            CHECK_THROWS_AS("[\"foo\",1,2,3,false,{\"one\":1}"_json, std::invalid_argument);
            CHECK_THROWS_WITH("[\"foo\",1,2,3,false,{\"one\":1}"_json,
                              "parse error - unexpected end of input; expected ']'");
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
            }

            SECTION("from std::array")
            {
                std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
                CHECK(json::parse(v) == json(true));
            }

            SECTION("from array")
            {
                uint8_t v[] = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
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
                delete[] v;
            }

            SECTION("from std::string")
            {
                std::string v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
            }

            SECTION("from std::initializer_list")
            {
                std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
            }

            SECTION("empty container")
            {
                std::vector<uint8_t> v;
                CHECK_THROWS_AS(json::parse(v), std::invalid_argument);
            }
        }

        SECTION("via iterator range")
        {
            SECTION("from std::vector")
            {
                std::vector<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
            }

            SECTION("from std::array")
            {
                std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
            }

            SECTION("from array")
            {
                uint8_t v[] = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
            }

            SECTION("from std::string")
            {
                std::string v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
            }

            SECTION("from std::initializer_list")
            {
                std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
            }

            SECTION("from std::valarray")
            {
                std::valarray<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
            }

            SECTION("with empty range")
            {
                std::vector<uint8_t> v;
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }
        }

        // these cases are required for 100% line coverage
        SECTION("error cases")
        {
            SECTION("case 1")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', '\\', 'u'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 2")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', '\\', 'u', '1'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 3")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', '\\', 'u', '1', '1', '1', '1', '1', '1', '1', '1'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 4")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', 'u', '1', '1', '1', '1', '1', '1', '1', '1', '\\'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 5")
            {
                uint8_t v[] = {'\"', 0x7F, 0xC1};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 6")
            {
                uint8_t v[] = {'\"', 0x7F, 0xDF, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 7")
            {
                uint8_t v[] = {'\"', 0x7F, 0xDF, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 8")
            {
                uint8_t v[] = {'\"', 0x7F, 0xE0, 0x9F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 9")
            {
                uint8_t v[] = {'\"', 0x7F, 0xEF, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 10")
            {
                uint8_t v[] = {'\"', 0x7F, 0xED, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 11")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF0, 0x8F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 12")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF0, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 13")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF3, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 14")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF3, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }

            SECTION("case 15")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF4, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), std::invalid_argument);
            }
        }
    }
}
