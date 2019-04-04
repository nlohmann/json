/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.6.1
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

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <iostream>
#include <sstream>
#include <valarray>

namespace
{
struct SaxEventLogger : public nlohmann::json_sax<json>
{
    bool null() override
    {
        events.push_back("null()");
        return true;
    }

    bool boolean(bool val) override
    {
        events.push_back(val ? "boolean(true)" : "boolean(false)");
        return true;
    }

    bool number_integer(json::number_integer_t val) override
    {
        events.push_back("number_integer(" + std::to_string(val) + ")");
        return true;
    }

    bool number_unsigned(json::number_unsigned_t val) override
    {
        events.push_back("number_unsigned(" + std::to_string(val) + ")");
        return true;
    }

    bool number_float(json::number_float_t, const std::string& s) override
    {
        events.push_back("number_float(" + s + ")");
        return true;
    }

    bool string(std::string& val) override
    {
        events.push_back("string(" + val + ")");
        return true;
    }

    bool start_object(std::size_t elements) override
    {
        if (elements == std::size_t(-1))
        {
            events.push_back("start_object()");
        }
        else
        {
            events.push_back("start_object(" + std::to_string(elements) + ")");
        }
        return true;
    }

    bool key(std::string& val) override
    {
        events.push_back("key(" + val + ")");
        return true;
    }

    bool end_object() override
    {
        events.push_back("end_object()");
        return true;
    }

    bool start_array(std::size_t elements) override
    {
        if (elements == std::size_t(-1))
        {
            events.push_back("start_array()");
        }
        else
        {
            events.push_back("start_array(" + std::to_string(elements) + ")");
        }
        return true;
    }

    bool end_array() override
    {
        events.push_back("end_array()");
        return true;
    }

    bool parse_error(std::size_t position, const std::string&, const json::exception&) override
    {
        events.push_back("parse_error(" + std::to_string(position) + ")");
        return false;
    }

    std::vector<std::string> events {};
};

struct SaxEventLoggerExitAfterStartObject : public SaxEventLogger
{
    bool start_object(std::size_t elements) override
    {
        if (elements == std::size_t(-1))
        {
            events.push_back("start_object()");
        }
        else
        {
            events.push_back("start_object(" + std::to_string(elements) + ")");
        }
        return false;
    }
};

struct SaxEventLoggerExitAfterKey : public SaxEventLogger
{
    bool key(std::string& val) override
    {
        events.push_back("key(" + val + ")");
        return false;
    }
};

struct SaxEventLoggerExitAfterStartArray : public SaxEventLogger
{
    bool start_array(std::size_t elements) override
    {
        if (elements == std::size_t(-1))
        {
            events.push_back("start_array()");
        }
        else
        {
            events.push_back("start_array(" + std::to_string(elements) + ")");
        }
        return false;
    }
};
}

TEST_CASE("deserialization")
{
    SECTION("successful deserialization")
    {
        SECTION("stream")
        {
            std::stringstream ss1, ss2, ss3;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}]";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}]";
            ss3 << "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(ss1);
            CHECK(json::accept(ss2));
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));

            SaxEventLogger l;
            CHECK(json::sax_parse(ss3, &l));
            CHECK(l.events.size() == 11);
            CHECK(l.events == std::vector<std::string>(
            {
                "start_array()", "string(foo)", "number_unsigned(1)",
                "number_unsigned(2)", "number_unsigned(3)", "boolean(false)",
                "start_object()", "key(one)", "number_unsigned(1)",
                "end_object()", "end_array()"
            }));
        }

        SECTION("string literal")
        {
            auto s = "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(s);
            CHECK(json::accept(s));
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));

            SaxEventLogger l;
            CHECK(json::sax_parse(s, &l));
            CHECK(l.events.size() == 11);
            CHECK(l.events == std::vector<std::string>(
            {
                "start_array()", "string(foo)", "number_unsigned(1)",
                "number_unsigned(2)", "number_unsigned(3)", "boolean(false)",
                "start_object()", "key(one)", "number_unsigned(1)",
                "end_object()", "end_array()"
            }));
        }

        SECTION("string_t")
        {
            json::string_t s = "[\"foo\",1,2,3,false,{\"one\":1}]";
            json j = json::parse(s);
            CHECK(json::accept(s));
            CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));

            SaxEventLogger l;
            CHECK(json::sax_parse(s, &l));
            CHECK(l.events.size() == 11);
            CHECK(l.events == std::vector<std::string>(
            {
                "start_array()", "string(foo)", "number_unsigned(1)",
                "number_unsigned(2)", "number_unsigned(3)", "boolean(false)",
                "start_object()", "key(one)", "number_unsigned(1)",
                "end_object()", "end_array()"
            }));
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
            std::stringstream ss1, ss2, ss3, ss4, ss5;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss3 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss4 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss5 << "[\"foo\",1,2,3,false,{\"one\":1}";
            CHECK_THROWS_AS(json::parse(ss1), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(ss2),
                              "[json.exception.parse_error.101] parse error at line 1, column 29: syntax error while parsing array - unexpected end of input; expected ']'");
            CHECK(not json::accept(ss3));

            json j_error;
            CHECK_NOTHROW(j_error = json::parse(ss4, nullptr, false));
            CHECK(j_error.is_discarded());

            SaxEventLogger l;
            CHECK(not json::sax_parse(ss5, &l));
            CHECK(l.events.size() == 11);
            CHECK(l.events == std::vector<std::string>(
            {
                "start_array()", "string(foo)", "number_unsigned(1)",
                "number_unsigned(2)", "number_unsigned(3)", "boolean(false)",
                "start_object()", "key(one)", "number_unsigned(1)",
                "end_object()", "parse_error(29)"
            }));
        }

        SECTION("string")
        {
            json::string_t s = "[\"foo\",1,2,3,false,{\"one\":1}";
            CHECK_THROWS_AS(json::parse(s), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(s),
                              "[json.exception.parse_error.101] parse error at line 1, column 29: syntax error while parsing array - unexpected end of input; expected ']'");
            CHECK(not json::accept(s));

            json j_error;
            CHECK_NOTHROW(j_error = json::parse(s, nullptr, false));
            CHECK(j_error.is_discarded());

            SaxEventLogger l;
            CHECK(not json::sax_parse(s, &l));
            CHECK(l.events.size() == 11);
            CHECK(l.events == std::vector<std::string>(
            {
                "start_array()", "string(foo)", "number_unsigned(1)",
                "number_unsigned(2)", "number_unsigned(3)", "boolean(false)",
                "start_object()", "key(one)", "number_unsigned(1)",
                "end_object()", "parse_error(29)"
            }));
        }

        SECTION("operator<<")
        {
            std::stringstream ss1, ss2;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            json j;
            CHECK_THROWS_AS(j << ss1, json::parse_error&);
            CHECK_THROWS_WITH(j << ss2,
                              "[json.exception.parse_error.101] parse error at line 1, column 29: syntax error while parsing array - unexpected end of input; expected ']'");
        }

        SECTION("operator>>")
        {
            std::stringstream ss1, ss2;
            ss1 << "[\"foo\",1,2,3,false,{\"one\":1}";
            ss2 << "[\"foo\",1,2,3,false,{\"one\":1}";
            json j;
            CHECK_THROWS_AS(ss1 >> j, json::parse_error&);
            CHECK_THROWS_WITH(ss2 >> j,
                              "[json.exception.parse_error.101] parse error at line 1, column 29: syntax error while parsing array - unexpected end of input; expected ']'");
        }

        SECTION("user-defined string literal")
        {
            CHECK_THROWS_AS("[\"foo\",1,2,3,false,{\"one\":1}"_json, json::parse_error&);
            CHECK_THROWS_WITH("[\"foo\",1,2,3,false,{\"one\":1}"_json,
                              "[json.exception.parse_error.101] parse error at line 1, column 29: syntax error while parsing array - unexpected end of input; expected ']'");
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

                SaxEventLogger l;
                CHECK(json::sax_parse(v, &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("from std::array")
            {
                std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));

                SaxEventLogger l;
                CHECK(json::sax_parse(v, &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("from array")
            {
                uint8_t v[] = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));

                SaxEventLogger l;
                CHECK(json::sax_parse(v, &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
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

                SaxEventLogger l;
                CHECK(json::sax_parse(v, &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));

                delete[] v;
            }

            SECTION("from std::string")
            {
                std::string v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));

                SaxEventLogger l;
                CHECK(json::sax_parse(v, &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("from std::initializer_list")
            {
                std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(v) == json(true));
                CHECK(json::accept(v));

                SaxEventLogger l;
                CHECK(json::sax_parse(v, &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("empty container")
            {
                std::vector<uint8_t> v;
                CHECK_THROWS_AS(json::parse(v), json::parse_error&);
                CHECK(not json::accept(v));

                SaxEventLogger l;
                CHECK(not json::sax_parse(v, &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(1)"}));
            }
        }

        SECTION("via iterator range")
        {
            SECTION("from std::vector")
            {
                std::vector<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));

                SaxEventLogger l;
                CHECK(json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));

            }

            SECTION("from std::array")
            {
                std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));

                SaxEventLogger l;
                CHECK(json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("from array")
            {
                uint8_t v[] = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));

                SaxEventLogger l;
                CHECK(json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("from std::string")
            {
                std::string v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));

                SaxEventLogger l;
                CHECK(json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("from std::initializer_list")
            {
                std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));

                SaxEventLogger l;
                CHECK(json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("from std::valarray")
            {
                std::valarray<uint8_t> v = {'t', 'r', 'u', 'e'};
                CHECK(json::parse(std::begin(v), std::end(v)) == json(true));
                CHECK(json::accept(std::begin(v), std::end(v)));

                SaxEventLogger l;
                CHECK(json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
            }

            SECTION("with empty range")
            {
                std::vector<uint8_t> v;
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(1)"}));
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

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(10)"}));
            }

            SECTION("case 2")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', '\\', 'u', '1'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(11)"}));
            }

            SECTION("case 3")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', '\\', 'u', '1', '1', '1', '1', '1', '1', '1', '1'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(18)"}));
            }

            SECTION("case 4")
            {
                uint8_t v[] = {'\"', 'a', 'a', 'a', 'a', 'a', 'a', 'u', '1', '1', '1', '1', '1', '1', '1', '1', '\\'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(18)"}));
            }

            SECTION("case 5")
            {
                uint8_t v[] = {'\"', 0x7F, 0xC1};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(3)"}));
            }

            SECTION("case 6")
            {
                uint8_t v[] = {'\"', 0x7F, 0xDF, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK_THROWS_WITH(json::parse(std::begin(v), std::end(v)),
                                  "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"\x7f\xdf\x7f'");
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 7")
            {
                uint8_t v[] = {'\"', 0x7F, 0xDF, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 8")
            {
                uint8_t v[] = {'\"', 0x7F, 0xE0, 0x9F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 9")
            {
                uint8_t v[] = {'\"', 0x7F, 0xEF, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 10")
            {
                uint8_t v[] = {'\"', 0x7F, 0xED, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 11")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF0, 0x8F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 12")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF0, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 13")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF3, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 14")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF3, 0xC0};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 15")
            {
                uint8_t v[] = {'\"', 0x7F, 0xF4, 0x7F};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 1);
                CHECK(l.events == std::vector<std::string>({"parse_error(4)"}));
            }

            SECTION("case 16")
            {
                uint8_t v[] = {'{', '\"', '\"', ':', '1', '1'};
                CHECK_THROWS_AS(json::parse(std::begin(v), std::end(v)), json::parse_error&);
                CHECK(not json::accept(std::begin(v), std::end(v)));

                json j_error;
                CHECK_NOTHROW(j_error = json::parse(std::begin(v), std::end(v), nullptr, false));
                CHECK(j_error.is_discarded());

                SaxEventLogger l;
                CHECK(not json::sax_parse(std::begin(v), std::end(v), &l));
                CHECK(l.events.size() == 4);
                CHECK(l.events == std::vector<std::string>(
                {
                    "start_object()", "key()", "number_unsigned(11)",
                    "parse_error(7)"
                }));
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
                              "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal");

            CHECK_THROWS_AS(json::parse(std::istringstream(bom)), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom)),
                              "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal");

            SaxEventLogger l;
            CHECK(not json::sax_parse(bom, &l));
            CHECK(l.events.size() == 1);
            CHECK(l.events == std::vector<std::string>(
            {
                "parse_error(4)"
            }));
        }

        SECTION("BOM and content")
        {
            CHECK(json::parse(bom + "1") == 1);
            CHECK(json::parse(std::istringstream(bom + "1")) == 1);

            SaxEventLogger l1, l2;
            CHECK(json::sax_parse(std::istringstream(bom + "1"), &l1));
            CHECK(json::sax_parse(bom + "1", &l2));
            CHECK(l1.events.size() == 1);
            CHECK(l1.events == std::vector<std::string>(
            {
                "number_unsigned(1)"
            }));
            CHECK(l2.events.size() == 1);
            CHECK(l2.events == std::vector<std::string>(
            {
                "number_unsigned(1)"
            }));
        }

        SECTION("2 byte of BOM")
        {
            CHECK_THROWS_AS(json::parse(bom.substr(0, 2)), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(bom.substr(0, 2)),
                              "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid BOM; must be 0xEF 0xBB 0xBF if given; last read: '\xEF\xBB'");

            CHECK_THROWS_AS(json::parse(std::istringstream(bom.substr(0, 2))), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom.substr(0, 2))),
                              "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid BOM; must be 0xEF 0xBB 0xBF if given; last read: '\xEF\xBB'");

            SaxEventLogger l1, l2;
            CHECK(not json::sax_parse(std::istringstream(bom.substr(0, 2)), &l1));
            CHECK(not json::sax_parse(bom.substr(0, 2), &l2));
            CHECK(l1.events.size() == 1);
            CHECK(l1.events == std::vector<std::string>(
            {
                "parse_error(3)"
            }));
            CHECK(l2.events.size() == 1);
            CHECK(l2.events == std::vector<std::string>(
            {
                "parse_error(3)"
            }));
        }

        SECTION("1 byte of BOM")
        {
            CHECK_THROWS_AS(json::parse(bom.substr(0, 1)), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(bom.substr(0, 1)),
                              "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid BOM; must be 0xEF 0xBB 0xBF if given; last read: '\xEF'");

            CHECK_THROWS_AS(json::parse(std::istringstream(bom.substr(0, 1))), json::parse_error&);
            CHECK_THROWS_WITH(json::parse(std::istringstream(bom.substr(0, 1))),
                              "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid BOM; must be 0xEF 0xBB 0xBF if given; last read: '\xEF'");

            SaxEventLogger l1, l2;
            CHECK(not json::sax_parse(std::istringstream(bom.substr(0, 1)), &l1));
            CHECK(not json::sax_parse(bom.substr(0, 1), &l2));
            CHECK(l1.events.size() == 1);
            CHECK(l1.events == std::vector<std::string>(
            {
                "parse_error(2)"
            }));
            CHECK(l2.events.size() == 1);
            CHECK(l2.events == std::vector<std::string>(
            {
                "parse_error(2)"
            }));
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
                        CAPTURE(i0)
                        CAPTURE(i1)
                        CAPTURE(i2)

                        std::string s = "";
                        s.push_back(static_cast<char>(bom[0] + i0));
                        s.push_back(static_cast<char>(bom[1] + i1));
                        s.push_back(static_cast<char>(bom[2] + i2));

                        if (i0 == 0 and i1 == 0 and i2 == 0)
                        {
                            // without any variation, we skip the BOM
                            CHECK(json::parse(s + "null") == json());
                            CHECK(json::parse(std::istringstream(s + "null")) == json());

                            SaxEventLogger l;
                            CHECK(json::sax_parse(s + "null", &l));
                            CHECK(l.events.size() == 1);
                            CHECK(l.events == std::vector<std::string>(
                            {
                                "null()"
                            }));
                        }
                        else
                        {
                            // any variation is an error
                            CHECK_THROWS_AS(json::parse(s + "null"), json::parse_error&);
                            CHECK_THROWS_AS(json::parse(std::istringstream(s + "null")), json::parse_error&);

                            SaxEventLogger l;
                            CHECK(not json::sax_parse(s + "null", &l));
                            CHECK(l.events.size() == 1);

                            if (i0 != 0)
                            {
                                CHECK(l.events == std::vector<std::string>(
                                {
                                    "parse_error(1)"
                                }));
                            }
                            else if (i1 != 0)
                            {
                                CHECK(l.events == std::vector<std::string>(
                                {
                                    "parse_error(2)"
                                }));
                            }
                            else
                            {
                                CHECK(l.events == std::vector<std::string>(
                                {
                                    "parse_error(3)"
                                }));
                            }
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

    SECTION("SAX and early abort")
    {
        std::string s = "[1, [\"string\", 43.12], null, {\"key1\": true, \"key2\": false}]";

        SaxEventLogger default_logger;
        SaxEventLoggerExitAfterStartObject exit_after_start_object;
        SaxEventLoggerExitAfterKey exit_after_key;
        SaxEventLoggerExitAfterStartArray exit_after_start_array;

        json::sax_parse(s, &default_logger);
        CHECK(default_logger.events.size() == 14);
        CHECK(default_logger.events == std::vector<std::string>(
        {
            "start_array()", "number_unsigned(1)", "start_array()",
            "string(string)", "number_float(43.12)", "end_array()", "null()",
            "start_object()", "key(key1)", "boolean(true)", "key(key2)",
            "boolean(false)", "end_object()", "end_array()"
        }));

        json::sax_parse(s, &exit_after_start_object);
        CHECK(exit_after_start_object.events.size() == 8);
        CHECK(exit_after_start_object.events == std::vector<std::string>(
        {
            "start_array()", "number_unsigned(1)", "start_array()",
            "string(string)", "number_float(43.12)", "end_array()", "null()",
            "start_object()"
        }));

        json::sax_parse(s, &exit_after_key);
        CHECK(exit_after_key.events.size() == 9);
        CHECK(exit_after_key.events == std::vector<std::string>(
        {
            "start_array()", "number_unsigned(1)", "start_array()",
            "string(string)", "number_float(43.12)", "end_array()", "null()",
            "start_object()", "key(key1)"
        }));

        json::sax_parse(s, &exit_after_start_array);
        CHECK(exit_after_start_array.events.size() == 1);
        CHECK(exit_after_start_array.events == std::vector<std::string>(
        {
            "start_array()"
        }));
    }
}
