/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.1.2
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
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

// HACK to get the tests running if exceptions are disabled on the command line
// using the "-e/--nothrow" flag. In this case the expressions in CHECK_THROWS
// and similar macros is never executed and subsequent checks relying on the
// side effects of the expression may or may not fail.
#define IF_EXCEPTIONS_ENABLED_THEN_CHECK(expr)                                                  \
    {                                                                                           \
        bool _exceptions_enabled_ = false;                                                      \
        /* The next line sets the `_exceptions_enabled_` flag to true, iff the expression in */ \
        /* the CHECK_THROWS macro actually gets ever evaluated. It's not if the "-e" flag    */ \
        /* has been specified on the command line.                                           */ \
        CHECK_THROWS([&](){ _exceptions_enabled_ = true; throw std::runtime_error("ok"); }());  \
        if (_exceptions_enabled_)                                                               \
        {                                                                                       \
            CHECK(expr);                                                                        \
        }                                                                                       \
    }                                                                                           \
    /**/

namespace
{
    // A stringbuf which only ever has a get-area of exactly one character.
    // I.e. multiple successive calls to sungetc will fail.
    // Note that sgetc and sbumpc both update the get-area and count as a "read" operation.
    // (sbumpc is the equivalent to sgetc + gbump(1).)
    class unget_fails_stringbuf : public std::streambuf
    {
        const char* last;

      public:
        explicit unget_fails_stringbuf(char const* str, size_t len)
            : last(str + len)
        {
            char* first = const_cast<char*>(str);
            this->setg(first, first, first);
        }

      protected:
        virtual traits_type::int_type underflow() override
        {
            char* pos = this->gptr();
            if (pos == last)
            {
                this->setg(pos, pos, pos); // empty. and invalid.
                return traits_type::eof();
            }
            this->setg(pos, pos, pos + 1);
            return traits_type::to_int_type(*pos);
        }
    };
}

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
            CHECK(!ss1.fail());
            CHECK(!ss1.bad());
            CHECK(ss1.eof()); // Strict parsing.
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
            CHECK(!ss.fail());
            CHECK(!ss.bad());
            // operator>> uses non-strict parsing.
            // We have read the closing ']' and we're done. The parser should
            // not have read the EOF marker.
            CHECK(!ss.eof());
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
        SECTION("null streambuf")
        {
            std::streambuf* sb = nullptr;
            std::istream iss(sb);
            CHECK(iss.bad());
            CHECK_THROWS_WITH(json::parse(iss),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(iss.fail()); // Tests the badbit too.
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(iss.bad());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!iss.eof());
        }

        SECTION("stream")
        {
            std::stringstream ss1, ss2, ss3, ss4;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss3 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss4 << "[\"foo\",1,2,3,false,{\"one\":1}";
            CHECK_THROWS_AS(json::parse(ss1), json::parse_error&);
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!ss1.fail());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!ss1.bad());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(ss1.eof());
            CHECK_THROWS_WITH(json::parse(ss2),
                              "[json.exception.parse_error.101] parse error at 29: syntax error - unexpected end of input; expected ']'");
            CHECK(not json::accept(ss3));

            json j_error;
            CHECK_NOTHROW(j_error = json::parse(ss4, nullptr, false));
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
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!ss1.fail());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!ss1.bad());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(ss1.eof());
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
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!ss1.fail());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!ss1.bad());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(ss1.eof());
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
        const std::string bom = "\xEF\xBB\xBF";

        SECTION("BOM only")
        {
            CHECK_THROWS_AS(json::parse(bom), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(bom),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");

            std::istringstream iss(bom);
            CHECK_THROWS_AS(json::parse(iss), json::parse_error&);
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!iss.fail());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(!iss.bad());
            IF_EXCEPTIONS_ENABLED_THEN_CHECK(iss.eof());
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom)),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
        }

        SECTION("BOM and content")
        {
            CHECK(json::parse(bom + "1") == 1);

            std::istringstream iss(bom + "1");
            CHECK(json::parse(iss) == 1);
            CHECK(!iss.bad());
            CHECK(!iss.fail());
            // Strict parsing: stream should be at EOF now.
            CHECK(iss.eof());

            iss.str(bom + "1");
            iss.clear();
            json j;
            CHECK_NOTHROW(iss >> j);
            CHECK(j == 1);
            CHECK(!iss.fail());
            CHECK(!iss.bad());
            // Non-strict parsing:
            // EOF bit is set only if we tried to read a character past the end of the file.
            // In this case: parsing the complete number requires reading past the end of the file.
            CHECK(iss.eof());

            iss.str(bom + "\"1\"");
            iss.clear();
            CHECK(json::parse(iss) == "1");
            CHECK(!iss.fail());
            CHECK(!iss.bad());
            CHECK(iss.eof()); // Strict...

            iss.str(bom + "\"1\"");
            iss.clear();
            CHECK_NOTHROW(iss >> j);
            CHECK(j == "1");
            CHECK(!iss.fail());
            CHECK(!iss.bad());
            CHECK(!iss.eof()); // Non-strict...
        }

        SECTION("2 byte of BOM")
        {
            const std::string bom2 = bom.substr(0, 2);

            CHECK_THROWS_AS(json::parse(bom2), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(bom2),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - invalid literal; last read: '\xEF'");

            std::istringstream iss(bom2);
            CHECK_THROWS_AS(json::parse(iss), json::parse_error&);
            CHECK(!iss.fail());
            CHECK(!iss.bad());
            CHECK(!iss.eof()); // EOF bit is set only if we tried to read a character past the end of the file.
            CHECK(iss.good());
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom2)),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - invalid literal; last read: '\xEF'");
        }

        SECTION("2 byte of BOM - incomplete")
        {
            {
                unget_fails_stringbuf sb("\xEF\xBB ", 3);
                std::istream is(&sb);

                json j;
                CHECK_THROWS_WITH(is >> j,
                                "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
                IF_EXCEPTIONS_ENABLED_THEN_CHECK(is.fail()); // Tests the badbit too
                IF_EXCEPTIONS_ENABLED_THEN_CHECK(is.bad());
                // Do not check the eofbit.
                // Some implementations keep the eofbit if is.unget() fails, some do not.
            }
            {
                unget_fails_stringbuf sb("\xEF\xBB", 2);
                std::istream is(&sb);

                json j;
                CHECK_THROWS_WITH(is >> j,
                                "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
                IF_EXCEPTIONS_ENABLED_THEN_CHECK(is.fail()); // Tests the badbit too
                IF_EXCEPTIONS_ENABLED_THEN_CHECK(is.bad());
                // Do not check the eofbit.
                // Some implementations keep the eofbit if is.unget() fails, some do not.
            }
        }

        SECTION("1 byte of BOM")
        {
            const std::string bom1 = bom.substr(0, 1);

            CHECK_THROWS_AS(json::parse(bom1), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(bom1),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - invalid literal; last read: '\xEF'");

            std::istringstream iss(bom1);
            CHECK_THROWS_AS(json::parse(iss), json::parse_error&);
            CHECK(!iss.fail());
            CHECK(!iss.bad());
            CHECK(!iss.eof()); // EOF bit is set only if we tried to read a character past the end of the file.
            CHECK(iss.good());
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom1)),
                              "[json.exception.parse_error.101] parse error at 1: syntax error - invalid literal; last read: '\xEF'");
        }

        SECTION("1 byte of BOM - incomplete")
        {
            {
                unget_fails_stringbuf sb("\xEF  ", 3);
                std::istream is(&sb);

                json j;
                CHECK_THROWS_WITH(is >> j,
                                "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
                IF_EXCEPTIONS_ENABLED_THEN_CHECK(is.fail()); // Tests the badbit too
                IF_EXCEPTIONS_ENABLED_THEN_CHECK(is.bad());
                // Do not check the eofbit.
                // Some implementations keep the eofbit if is.unget() fails, some do not.
            }
            {
                unget_fails_stringbuf sb("\xEF", 1);
                std::istream is(&sb);

                json j;
                CHECK_THROWS_WITH(is >> j,
                                "[json.exception.parse_error.101] parse error at 1: syntax error - unexpected end of input; expected '[', '{', or a literal");
                IF_EXCEPTIONS_ENABLED_THEN_CHECK(is.fail()); // Tests the badbit too
                IF_EXCEPTIONS_ENABLED_THEN_CHECK(is.bad());
                // Do not check the eofbit.
                // Some implementations keep the eofbit if is.unget() fails, some do not.
            }
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

        SECTION("preserve state after parsing - strings")
        {
            std::istringstream s(bom + "\"123\" \"456\"");
            json j;
            s >> j;
            CHECK(j == "123");
            CHECK(s.good());
            s >> j;
            CHECK(j == "456");
            CHECK(s.good());
            s.peek();
            CHECK(s.eof());
        }

        SECTION("preserve state after parsing - numbers (ref)")
        {
            std::istringstream s("123 456");
            int j;
            s >> j;
            CHECK(j == 123);
            CHECK(s.good());
            s >> j;
            CHECK(j == 456);
            CHECK(!s.good());
            CHECK(!s.fail());
            CHECK(!s.bad());
            // The stream now has the eofbit set (since to determine whether the number has completely
            // parsed, the lexer needs to read past the end of the file).
            CHECK(s.eof());
        }
        SECTION("preserve state after parsing - numbers")
        {
            std::istringstream s(bom + "123 456");
            json j;
            s >> j;
            CHECK(j == 123);
            CHECK(s.good());
            s >> j;
            CHECK(j == 456);
            CHECK(!s.good());
            CHECK(!s.fail());
            CHECK(!s.bad());
            // The stream now has the eofbit set (since to determine whether the number has completely
            // parsed, the lexer needs to read past the end of the file).
            CHECK(s.eof());
        }

        SECTION("preserve state after parsing - numbers (trailing space) (ref)")
        {
            std::istringstream s("123 456 ");
            int j;
            s >> j;
            CHECK(j == 123);
            CHECK(s.good());
            s >> j;
            CHECK(j == 456);
            // The trailing space at the end is the end of the number.
            // The stream should not have the eofbit set.
            CHECK(s.good());
            CHECK(s.peek() == static_cast<unsigned char>(' '));
        }
        SECTION("preserve state after parsing - numbers (trailing space)")
        {
            std::istringstream s(bom + "123 456 ");
            json j;
            s >> j;
            CHECK(j == 123);
            CHECK(s.good());
            s >> j;
            CHECK(j == 456);
            // The trailing space at the end is the end of the number.
            // The stream should not have the eofbit set.
            CHECK(s.good());
            CHECK(s.peek() == static_cast<unsigned char>(' '));
        }
    }
}
