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

#include "catch.hpp"

#define private public
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <valarray>

class SaxEventLogger
{
  public:
    bool null()
    {
        events.push_back("null()");
        return true;
    }

    bool boolean(bool val)
    {
        events.push_back(val ? "boolean(true)" : "boolean(false)");
        return true;
    }

    bool number_integer(json::number_integer_t val)
    {
        events.push_back("number_integer(" + std::to_string(val) + ")");
        return true;
    }

    bool number_unsigned(json::number_unsigned_t val)
    {
        events.push_back("number_unsigned(" + std::to_string(val) + ")");
        return true;
    }

    bool number_float(json::number_float_t, const std::string& s)
    {
        events.push_back("number_float(" + s + ")");
        return true;
    }

    bool string(std::string& val)
    {
        events.push_back("string(" + val + ")");
        return true;
    }

    bool start_object(std::size_t elements)
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

    bool key(std::string& val)
    {
        events.push_back("key(" + val + ")");
        return true;
    }

    bool end_object()
    {
        events.push_back("end_object()");
        return true;
    }

    bool start_array(std::size_t elements)
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

    bool end_array()
    {
        events.push_back("end_array()");
        return true;
    }

    bool parse_error(std::size_t position, const std::string&, const json::exception&)
    {
        errored = true;
        events.push_back("parse_error(" + std::to_string(position) + ")");
        return false;
    }

    std::vector<std::string> events {};
    bool errored = false;
};

class SaxCountdown : public nlohmann::json::json_sax_t
{
  public:
    explicit SaxCountdown(const int count) : events_left(count)
    {}

    bool null() override
    {
        return events_left-- > 0;
    }

    bool boolean(bool) override
    {
        return events_left-- > 0;
    }

    bool number_integer(json::number_integer_t) override
    {
        return events_left-- > 0;
    }

    bool number_unsigned(json::number_unsigned_t) override
    {
        return events_left-- > 0;
    }

    bool number_float(json::number_float_t, const std::string&) override
    {
        return events_left-- > 0;
    }

    bool string(std::string&) override
    {
        return events_left-- > 0;
    }

    bool start_object(std::size_t) override
    {
        return events_left-- > 0;
    }

    bool key(std::string&) override
    {
        return events_left-- > 0;
    }

    bool end_object() override
    {
        return events_left-- > 0;
    }

    bool start_array(std::size_t) override
    {
        return events_left-- > 0;
    }

    bool end_array() override
    {
        return events_left-- > 0;
    }

    bool parse_error(std::size_t, const std::string&, const json::exception&) override
    {
        return false;
    }

  private:
    int events_left = 0;
};

json parser_helper(const std::string& s);
bool accept_helper(const std::string& s);

json parser_helper(const std::string& s)
{
    json j;
    json::parser(nlohmann::detail::input_adapter(s)).parse(true, j);

    // if this line was reached, no exception ocurred
    // -> check if result is the same without exceptions
    json j_nothrow;
    CHECK_NOTHROW(json::parser(nlohmann::detail::input_adapter(s), nullptr, false).parse(true, j_nothrow));
    CHECK(j_nothrow == j);

    json j_sax;
    nlohmann::detail::json_sax_dom_parser<json> sdp(j_sax);
    json::sax_parse(s, &sdp);
    CHECK(j_sax == j);

    return j;
}

bool accept_helper(const std::string& s)
{
    CAPTURE(s)

    // 1. parse s without exceptions
    json j;
    CHECK_NOTHROW(json::parser(nlohmann::detail::input_adapter(s), nullptr, false).parse(true, j));
    const bool ok_noexcept = not j.is_discarded();

    // 2. accept s
    const bool ok_accept = json::parser(nlohmann::detail::input_adapter(s)).accept(true);

    // 3. check if both approaches come to the same result
    CHECK(ok_noexcept == ok_accept);

    // 4. parse with SAX (compare with relaxed accept result)
    SaxEventLogger el;
    CHECK_NOTHROW(json::sax_parse(s, &el, json::input_format_t::json, false));
    CHECK(json::parser(nlohmann::detail::input_adapter(s)).accept(false) == not el.errored);

    // 5. parse with simple callback
    json::parser_callback_t cb = [](int, json::parse_event_t, json&)
    {
        return true;
    };
    json j_cb = json::parse(s, cb, false);
    const bool ok_noexcept_cb = not j_cb.is_discarded();

    // 6. check if this approach came to the same result
    CHECK(ok_noexcept == ok_noexcept_cb);

    // 7. return result
    return ok_accept;
}

TEST_CASE("parser class")
{
    SECTION("parse")
    {
        SECTION("null")
        {
            CHECK(parser_helper("null") == json(nullptr));
        }

        SECTION("true")
        {
            CHECK(parser_helper("true") == json(true));
        }

        SECTION("false")
        {
            CHECK(parser_helper("false") == json(false));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                CHECK(parser_helper("[]") == json(json::value_t::array));
                CHECK(parser_helper("[ ]") == json(json::value_t::array));
            }

            SECTION("nonempty array")
            {
                CHECK(parser_helper("[true, false, null]") == json({true, false, nullptr}));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                CHECK(parser_helper("{}") == json(json::value_t::object));
                CHECK(parser_helper("{ }") == json(json::value_t::object));
            }

            SECTION("nonempty object")
            {
                CHECK(parser_helper("{\"\": true, \"one\": 1, \"two\": null}") == json({{"", true}, {"one", 1}, {"two", nullptr}}));
            }
        }

        SECTION("string")
        {
            // empty string
            CHECK(parser_helper("\"\"") == json(json::value_t::string));

            SECTION("errors")
            {
                // error: tab in string
                CHECK_THROWS_AS(parser_helper("\"\t\""), json::parse_error&);
                CHECK_THROWS_WITH(parser_helper("\"\t\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0009 (HT) must be escaped to \\u0009 or \\t; last read: '\"<U+0009>'");
                // error: newline in string
                CHECK_THROWS_AS(parser_helper("\"\n\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\r\""), json::parse_error&);
                CHECK_THROWS_WITH(parser_helper("\"\n\""),
                                  "[json.exception.parse_error.101] parse error at line 2, column 0: syntax error while parsing value - invalid string: control character U+000A (LF) must be escaped to \\u000A or \\n; last read: '\"<U+000A>'");
                CHECK_THROWS_WITH(parser_helper("\"\r\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000D (CR) must be escaped to \\u000D or \\r; last read: '\"<U+000D>'");
                // error: backspace in string
                CHECK_THROWS_AS(parser_helper("\"\b\""), json::parse_error&);
                CHECK_THROWS_WITH(parser_helper("\"\b\""),
                                  "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0008 (BS) must be escaped to \\u0008 or \\b; last read: '\"<U+0008>'");
                // improve code coverage
                CHECK_THROWS_AS(parser_helper("\uFF01"), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("[-4:1,]"), json::parse_error&);
                // unescaped control characters
                CHECK_THROWS_AS(parser_helper("\"\x00\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x01\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x02\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x03\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x04\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x05\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x06\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x07\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x08\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x09\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x0a\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x0b\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x0c\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x0d\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x0e\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x0f\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x10\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x11\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x12\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x13\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x14\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x15\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x16\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x17\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x18\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x19\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x1a\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x1b\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x1c\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x1d\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x1e\""), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("\"\x1f\""), json::parse_error&);
                CHECK_THROWS_WITH(parser_helper("\"\x00\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: missing closing quote; last read: '\"'");
                CHECK_THROWS_WITH(parser_helper("\"\x01\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0001 (SOH) must be escaped to \\u0001; last read: '\"<U+0001>'");
                CHECK_THROWS_WITH(parser_helper("\"\x02\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0002 (STX) must be escaped to \\u0002; last read: '\"<U+0002>'");
                CHECK_THROWS_WITH(parser_helper("\"\x03\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0003 (ETX) must be escaped to \\u0003; last read: '\"<U+0003>'");
                CHECK_THROWS_WITH(parser_helper("\"\x04\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0004 (EOT) must be escaped to \\u0004; last read: '\"<U+0004>'");
                CHECK_THROWS_WITH(parser_helper("\"\x05\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0005 (ENQ) must be escaped to \\u0005; last read: '\"<U+0005>'");
                CHECK_THROWS_WITH(parser_helper("\"\x06\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0006 (ACK) must be escaped to \\u0006; last read: '\"<U+0006>'");
                CHECK_THROWS_WITH(parser_helper("\"\x07\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0007 (BEL) must be escaped to \\u0007; last read: '\"<U+0007>'");
                CHECK_THROWS_WITH(parser_helper("\"\x08\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0008 (BS) must be escaped to \\u0008 or \\b; last read: '\"<U+0008>'");
                CHECK_THROWS_WITH(parser_helper("\"\x09\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0009 (HT) must be escaped to \\u0009 or \\t; last read: '\"<U+0009>'");
                CHECK_THROWS_WITH(parser_helper("\"\x0a\""), "[json.exception.parse_error.101] parse error at line 2, column 0: syntax error while parsing value - invalid string: control character U+000A (LF) must be escaped to \\u000A or \\n; last read: '\"<U+000A>'");
                CHECK_THROWS_WITH(parser_helper("\"\x0b\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000B (VT) must be escaped to \\u000B; last read: '\"<U+000B>'");
                CHECK_THROWS_WITH(parser_helper("\"\x0c\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000C (FF) must be escaped to \\u000C or \\f; last read: '\"<U+000C>'");
                CHECK_THROWS_WITH(parser_helper("\"\x0d\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000D (CR) must be escaped to \\u000D or \\r; last read: '\"<U+000D>'");
                CHECK_THROWS_WITH(parser_helper("\"\x0e\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000E (SO) must be escaped to \\u000E; last read: '\"<U+000E>'");
                CHECK_THROWS_WITH(parser_helper("\"\x0f\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000F (SI) must be escaped to \\u000F; last read: '\"<U+000F>'");
                CHECK_THROWS_WITH(parser_helper("\"\x10\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0010 (DLE) must be escaped to \\u0010; last read: '\"<U+0010>'");
                CHECK_THROWS_WITH(parser_helper("\"\x11\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0011 (DC1) must be escaped to \\u0011; last read: '\"<U+0011>'");
                CHECK_THROWS_WITH(parser_helper("\"\x12\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0012 (DC2) must be escaped to \\u0012; last read: '\"<U+0012>'");
                CHECK_THROWS_WITH(parser_helper("\"\x13\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0013 (DC3) must be escaped to \\u0013; last read: '\"<U+0013>'");
                CHECK_THROWS_WITH(parser_helper("\"\x14\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0014 (DC4) must be escaped to \\u0014; last read: '\"<U+0014>'");
                CHECK_THROWS_WITH(parser_helper("\"\x15\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0015 (NAK) must be escaped to \\u0015; last read: '\"<U+0015>'");
                CHECK_THROWS_WITH(parser_helper("\"\x16\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0016 (SYN) must be escaped to \\u0016; last read: '\"<U+0016>'");
                CHECK_THROWS_WITH(parser_helper("\"\x17\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0017 (ETB) must be escaped to \\u0017; last read: '\"<U+0017>'");
                CHECK_THROWS_WITH(parser_helper("\"\x18\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0018 (CAN) must be escaped to \\u0018; last read: '\"<U+0018>'");
                CHECK_THROWS_WITH(parser_helper("\"\x19\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0019 (EM) must be escaped to \\u0019; last read: '\"<U+0019>'");
                CHECK_THROWS_WITH(parser_helper("\"\x1a\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001A (SUB) must be escaped to \\u001A; last read: '\"<U+001A>'");
                CHECK_THROWS_WITH(parser_helper("\"\x1b\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001B (ESC) must be escaped to \\u001B; last read: '\"<U+001B>'");
                CHECK_THROWS_WITH(parser_helper("\"\x1c\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001C (FS) must be escaped to \\u001C; last read: '\"<U+001C>'");
                CHECK_THROWS_WITH(parser_helper("\"\x1d\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001D (GS) must be escaped to \\u001D; last read: '\"<U+001D>'");
                CHECK_THROWS_WITH(parser_helper("\"\x1e\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001E (RS) must be escaped to \\u001E; last read: '\"<U+001E>'");
                CHECK_THROWS_WITH(parser_helper("\"\x1f\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001F (US) must be escaped to \\u001F; last read: '\"<U+001F>'");

                SECTION("additional test for null byte")
                {
                    // The test above for the null byte is wrong, because passing
                    // a string to the parser only reads int until it encounters
                    // a null byte. This test inserts the null byte later on and
                    // uses an iterator range.
                    std::string s = "\"1\"";
                    s[1] = '\0';
                    CHECK_THROWS_AS(json::parse(s.begin(), s.end()), json::parse_error&);
                    CHECK_THROWS_WITH(json::parse(s.begin(), s.end()), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0000 (NUL) must be escaped to \\u0000; last read: '\"<U+0000>'");
                }
            }

            SECTION("escaped")
            {
                // quotation mark "\""
                auto r1 = R"("\"")"_json;
                CHECK(parser_helper("\"\\\"\"") == r1);
                // reverse solidus "\\"
                auto r2 = R"("\\")"_json;
                CHECK(parser_helper("\"\\\\\"") == r2);
                // solidus
                CHECK(parser_helper("\"\\/\"") == R"("/")"_json);
                // backspace
                CHECK(parser_helper("\"\\b\"") == json("\b"));
                // formfeed
                CHECK(parser_helper("\"\\f\"") == json("\f"));
                // newline
                CHECK(parser_helper("\"\\n\"") == json("\n"));
                // carriage return
                CHECK(parser_helper("\"\\r\"") == json("\r"));
                // horizontal tab
                CHECK(parser_helper("\"\\t\"") == json("\t"));

                CHECK(parser_helper("\"\\u0001\"").get<json::string_t>() == "\x01");
                CHECK(parser_helper("\"\\u000a\"").get<json::string_t>() == "\n");
                CHECK(parser_helper("\"\\u00b0\"").get<json::string_t>() == "°");
                CHECK(parser_helper("\"\\u0c00\"").get<json::string_t>() == "ఀ");
                CHECK(parser_helper("\"\\ud000\"").get<json::string_t>() == "퀀");
                CHECK(parser_helper("\"\\u000E\"").get<json::string_t>() == "\x0E");
                CHECK(parser_helper("\"\\u00F0\"").get<json::string_t>() == "ð");
                CHECK(parser_helper("\"\\u0100\"").get<json::string_t>() == "Ā");
                CHECK(parser_helper("\"\\u2000\"").get<json::string_t>() == " ");
                CHECK(parser_helper("\"\\uFFFF\"").get<json::string_t>() == "￿");
                CHECK(parser_helper("\"\\u20AC\"").get<json::string_t>() == "€");
                CHECK(parser_helper("\"€\"").get<json::string_t>() == "€");
                CHECK(parser_helper("\"🎈\"").get<json::string_t>() == "🎈");

                CHECK(parser_helper("\"\\ud80c\\udc60\"").get<json::string_t>() == u8"\U00013060");
                CHECK(parser_helper("\"\\ud83c\\udf1e\"").get<json::string_t>() == "🌞");
            }
        }

        SECTION("number")
        {
            SECTION("integers")
            {
                SECTION("without exponent")
                {
                    CHECK(parser_helper("-128") == json(-128));
                    CHECK(parser_helper("-0") == json(-0));
                    CHECK(parser_helper("0") == json(0));
                    CHECK(parser_helper("128") == json(128));
                }

                SECTION("with exponent")
                {
                    CHECK(parser_helper("0e1") == json(0e1));
                    CHECK(parser_helper("0E1") == json(0e1));

                    CHECK(parser_helper("10000E-4") == json(10000e-4));
                    CHECK(parser_helper("10000E-3") == json(10000e-3));
                    CHECK(parser_helper("10000E-2") == json(10000e-2));
                    CHECK(parser_helper("10000E-1") == json(10000e-1));
                    CHECK(parser_helper("10000E0") == json(10000e0));
                    CHECK(parser_helper("10000E1") == json(10000e1));
                    CHECK(parser_helper("10000E2") == json(10000e2));
                    CHECK(parser_helper("10000E3") == json(10000e3));
                    CHECK(parser_helper("10000E4") == json(10000e4));

                    CHECK(parser_helper("10000e-4") == json(10000e-4));
                    CHECK(parser_helper("10000e-3") == json(10000e-3));
                    CHECK(parser_helper("10000e-2") == json(10000e-2));
                    CHECK(parser_helper("10000e-1") == json(10000e-1));
                    CHECK(parser_helper("10000e0") == json(10000e0));
                    CHECK(parser_helper("10000e1") == json(10000e1));
                    CHECK(parser_helper("10000e2") == json(10000e2));
                    CHECK(parser_helper("10000e3") == json(10000e3));
                    CHECK(parser_helper("10000e4") == json(10000e4));

                    CHECK(parser_helper("-0e1") == json(-0e1));
                    CHECK(parser_helper("-0E1") == json(-0e1));
                    CHECK(parser_helper("-0E123") == json(-0e123));

                    // numbers after exponent
                    CHECK(parser_helper("10E0") == json(10e0));
                    CHECK(parser_helper("10E1") == json(10e1));
                    CHECK(parser_helper("10E2") == json(10e2));
                    CHECK(parser_helper("10E3") == json(10e3));
                    CHECK(parser_helper("10E4") == json(10e4));
                    CHECK(parser_helper("10E5") == json(10e5));
                    CHECK(parser_helper("10E6") == json(10e6));
                    CHECK(parser_helper("10E7") == json(10e7));
                    CHECK(parser_helper("10E8") == json(10e8));
                    CHECK(parser_helper("10E9") == json(10e9));
                    CHECK(parser_helper("10E+0") == json(10e0));
                    CHECK(parser_helper("10E+1") == json(10e1));
                    CHECK(parser_helper("10E+2") == json(10e2));
                    CHECK(parser_helper("10E+3") == json(10e3));
                    CHECK(parser_helper("10E+4") == json(10e4));
                    CHECK(parser_helper("10E+5") == json(10e5));
                    CHECK(parser_helper("10E+6") == json(10e6));
                    CHECK(parser_helper("10E+7") == json(10e7));
                    CHECK(parser_helper("10E+8") == json(10e8));
                    CHECK(parser_helper("10E+9") == json(10e9));
                    CHECK(parser_helper("10E-1") == json(10e-1));
                    CHECK(parser_helper("10E-2") == json(10e-2));
                    CHECK(parser_helper("10E-3") == json(10e-3));
                    CHECK(parser_helper("10E-4") == json(10e-4));
                    CHECK(parser_helper("10E-5") == json(10e-5));
                    CHECK(parser_helper("10E-6") == json(10e-6));
                    CHECK(parser_helper("10E-7") == json(10e-7));
                    CHECK(parser_helper("10E-8") == json(10e-8));
                    CHECK(parser_helper("10E-9") == json(10e-9));
                }

                SECTION("edge cases")
                {
                    // From RFC7159, Section 6:
                    // Note that when such software is used, numbers that are
                    // integers and are in the range [-(2**53)+1, (2**53)-1]
                    // are interoperable in the sense that implementations will
                    // agree exactly on their numeric values.

                    // -(2**53)+1
                    CHECK(parser_helper("-9007199254740991").get<int64_t>() == -9007199254740991);
                    // (2**53)-1
                    CHECK(parser_helper("9007199254740991").get<int64_t>() == 9007199254740991);
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
                    CHECK(parser_helper("-9223372036854775808").get<int64_t>() == -9223372036854775807 - 1);
                    // (2**63)-1
                    CHECK(parser_helper("9223372036854775807").get<int64_t>() == 9223372036854775807);
                    // (2**64)-1
                    CHECK(parser_helper("18446744073709551615").get<uint64_t>() == 18446744073709551615u);
                }
            }

            SECTION("floating-point")
            {
                SECTION("without exponent")
                {
                    CHECK(parser_helper("-128.5") == json(-128.5));
                    CHECK(parser_helper("0.999") == json(0.999));
                    CHECK(parser_helper("128.5") == json(128.5));
                    CHECK(parser_helper("-0.0") == json(-0.0));
                }

                SECTION("with exponent")
                {
                    CHECK(parser_helper("-128.5E3") == json(-128.5E3));
                    CHECK(parser_helper("-128.5E-3") == json(-128.5E-3));
                    CHECK(parser_helper("-0.0e1") == json(-0.0e1));
                    CHECK(parser_helper("-0.0E1") == json(-0.0e1));
                }
            }

            SECTION("overflow")
            {
                // overflows during parsing yield an exception
                CHECK_THROWS_AS(parser_helper("1.18973e+4932") == json(), json::out_of_range&);
                CHECK_THROWS_WITH(parser_helper("1.18973e+4932") == json(),
                                  "[json.exception.out_of_range.406] number overflow parsing '1.18973e+4932'");
            }

            SECTION("invalid numbers")
            {
                CHECK_THROWS_AS(parser_helper("01"),      json::parse_error&);
                CHECK_THROWS_AS(parser_helper("--1"),     json::parse_error&);
                CHECK_THROWS_AS(parser_helper("1."),      json::parse_error&);
                CHECK_THROWS_AS(parser_helper("1E"),      json::parse_error&);
                CHECK_THROWS_AS(parser_helper("1E-"),     json::parse_error&);
                CHECK_THROWS_AS(parser_helper("1.E1"),    json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-1E"),     json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0E#"),    json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0E-#"),   json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0#"),     json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0.0:"),   json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0.0Z"),   json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0E123:"), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0e0-:"),  json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0e-:"),   json::parse_error&);
                CHECK_THROWS_AS(parser_helper("-0f"),     json::parse_error&);

                // numbers must not begin with "+"
                CHECK_THROWS_AS(parser_helper("+1"), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("+0"), json::parse_error&);

                CHECK_THROWS_WITH(parser_helper("01"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - unexpected number literal; expected end of input");
                CHECK_THROWS_WITH(parser_helper("-01"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - unexpected number literal; expected end of input");
                CHECK_THROWS_WITH(parser_helper("--1"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '--'");
                CHECK_THROWS_WITH(parser_helper("1."),
                                  "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected digit after '.'; last read: '1.'");
                CHECK_THROWS_WITH(parser_helper("1E"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E'");
                CHECK_THROWS_WITH(parser_helper("1E-"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid number; expected digit after exponent sign; last read: '1E-'");
                CHECK_THROWS_WITH(parser_helper("1.E1"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected digit after '.'; last read: '1.E'");
                CHECK_THROWS_WITH(parser_helper("-1E"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '-1E'");
                CHECK_THROWS_WITH(parser_helper("-0E#"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '-0E#'");
                CHECK_THROWS_WITH(parser_helper("-0E-#"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid number; expected digit after exponent sign; last read: '-0E-#'");
                CHECK_THROWS_WITH(parser_helper("-0#"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid literal; last read: '-0#'; expected end of input");
                CHECK_THROWS_WITH(parser_helper("-0.0:"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - unexpected ':'; expected end of input");
                CHECK_THROWS_WITH(parser_helper("-0.0Z"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: '-0.0Z'; expected end of input");
                CHECK_THROWS_WITH(parser_helper("-0E123:"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - unexpected ':'; expected end of input");
                CHECK_THROWS_WITH(parser_helper("-0e0-:"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid number; expected digit after '-'; last read: '-:'; expected end of input");
                CHECK_THROWS_WITH(parser_helper("-0e-:"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid number; expected digit after exponent sign; last read: '-0e-:'");
                CHECK_THROWS_WITH(parser_helper("-0f"),
                                  "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: '-0f'; expected end of input");
            }
        }
    }

    SECTION("accept")
    {
        SECTION("null")
        {
            CHECK(accept_helper("null"));
        }

        SECTION("true")
        {
            CHECK(accept_helper("true"));
        }

        SECTION("false")
        {
            CHECK(accept_helper("false"));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                CHECK(accept_helper("[]"));
                CHECK(accept_helper("[ ]"));
            }

            SECTION("nonempty array")
            {
                CHECK(accept_helper("[true, false, null]"));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                CHECK(accept_helper("{}"));
                CHECK(accept_helper("{ }"));
            }

            SECTION("nonempty object")
            {
                CHECK(accept_helper("{\"\": true, \"one\": 1, \"two\": null}"));
            }
        }

        SECTION("string")
        {
            // empty string
            CHECK(accept_helper("\"\""));

            SECTION("errors")
            {
                // error: tab in string
                CHECK(accept_helper("\"\t\"") == false);
                // error: newline in string
                CHECK(accept_helper("\"\n\"") == false);
                CHECK(accept_helper("\"\r\"") == false);
                // error: backspace in string
                CHECK(accept_helper("\"\b\"") == false);
                // improve code coverage
                CHECK(accept_helper("\uFF01") == false);
                CHECK(accept_helper("[-4:1,]") == false);
                // unescaped control characters
                CHECK(accept_helper("\"\x00\"") == false);
                CHECK(accept_helper("\"\x01\"") == false);
                CHECK(accept_helper("\"\x02\"") == false);
                CHECK(accept_helper("\"\x03\"") == false);
                CHECK(accept_helper("\"\x04\"") == false);
                CHECK(accept_helper("\"\x05\"") == false);
                CHECK(accept_helper("\"\x06\"") == false);
                CHECK(accept_helper("\"\x07\"") == false);
                CHECK(accept_helper("\"\x08\"") == false);
                CHECK(accept_helper("\"\x09\"") == false);
                CHECK(accept_helper("\"\x0a\"") == false);
                CHECK(accept_helper("\"\x0b\"") == false);
                CHECK(accept_helper("\"\x0c\"") == false);
                CHECK(accept_helper("\"\x0d\"") == false);
                CHECK(accept_helper("\"\x0e\"") == false);
                CHECK(accept_helper("\"\x0f\"") == false);
                CHECK(accept_helper("\"\x10\"") == false);
                CHECK(accept_helper("\"\x11\"") == false);
                CHECK(accept_helper("\"\x12\"") == false);
                CHECK(accept_helper("\"\x13\"") == false);
                CHECK(accept_helper("\"\x14\"") == false);
                CHECK(accept_helper("\"\x15\"") == false);
                CHECK(accept_helper("\"\x16\"") == false);
                CHECK(accept_helper("\"\x17\"") == false);
                CHECK(accept_helper("\"\x18\"") == false);
                CHECK(accept_helper("\"\x19\"") == false);
                CHECK(accept_helper("\"\x1a\"") == false);
                CHECK(accept_helper("\"\x1b\"") == false);
                CHECK(accept_helper("\"\x1c\"") == false);
                CHECK(accept_helper("\"\x1d\"") == false);
                CHECK(accept_helper("\"\x1e\"") == false);
                CHECK(accept_helper("\"\x1f\"") == false);
            }

            SECTION("escaped")
            {
                // quotation mark "\""
                auto r1 = R"("\"")"_json;
                CHECK(accept_helper("\"\\\"\""));
                // reverse solidus "\\"
                auto r2 = R"("\\")"_json;
                CHECK(accept_helper("\"\\\\\""));
                // solidus
                CHECK(accept_helper("\"\\/\""));
                // backspace
                CHECK(accept_helper("\"\\b\""));
                // formfeed
                CHECK(accept_helper("\"\\f\""));
                // newline
                CHECK(accept_helper("\"\\n\""));
                // carriage return
                CHECK(accept_helper("\"\\r\""));
                // horizontal tab
                CHECK(accept_helper("\"\\t\""));

                CHECK(accept_helper("\"\\u0001\""));
                CHECK(accept_helper("\"\\u000a\""));
                CHECK(accept_helper("\"\\u00b0\""));
                CHECK(accept_helper("\"\\u0c00\""));
                CHECK(accept_helper("\"\\ud000\""));
                CHECK(accept_helper("\"\\u000E\""));
                CHECK(accept_helper("\"\\u00F0\""));
                CHECK(accept_helper("\"\\u0100\""));
                CHECK(accept_helper("\"\\u2000\""));
                CHECK(accept_helper("\"\\uFFFF\""));
                CHECK(accept_helper("\"\\u20AC\""));
                CHECK(accept_helper("\"€\""));
                CHECK(accept_helper("\"🎈\""));

                CHECK(accept_helper("\"\\ud80c\\udc60\""));
                CHECK(accept_helper("\"\\ud83c\\udf1e\""));
            }
        }

        SECTION("number")
        {
            SECTION("integers")
            {
                SECTION("without exponent")
                {
                    CHECK(accept_helper("-128"));
                    CHECK(accept_helper("-0"));
                    CHECK(accept_helper("0"));
                    CHECK(accept_helper("128"));
                }

                SECTION("with exponent")
                {
                    CHECK(accept_helper("0e1"));
                    CHECK(accept_helper("0E1"));

                    CHECK(accept_helper("10000E-4"));
                    CHECK(accept_helper("10000E-3"));
                    CHECK(accept_helper("10000E-2"));
                    CHECK(accept_helper("10000E-1"));
                    CHECK(accept_helper("10000E0"));
                    CHECK(accept_helper("10000E1"));
                    CHECK(accept_helper("10000E2"));
                    CHECK(accept_helper("10000E3"));
                    CHECK(accept_helper("10000E4"));

                    CHECK(accept_helper("10000e-4"));
                    CHECK(accept_helper("10000e-3"));
                    CHECK(accept_helper("10000e-2"));
                    CHECK(accept_helper("10000e-1"));
                    CHECK(accept_helper("10000e0"));
                    CHECK(accept_helper("10000e1"));
                    CHECK(accept_helper("10000e2"));
                    CHECK(accept_helper("10000e3"));
                    CHECK(accept_helper("10000e4"));

                    CHECK(accept_helper("-0e1"));
                    CHECK(accept_helper("-0E1"));
                    CHECK(accept_helper("-0E123"));
                }

                SECTION("edge cases")
                {
                    // From RFC7159, Section 6:
                    // Note that when such software is used, numbers that are
                    // integers and are in the range [-(2**53)+1, (2**53)-1]
                    // are interoperable in the sense that implementations will
                    // agree exactly on their numeric values.

                    // -(2**53)+1
                    CHECK(accept_helper("-9007199254740991"));
                    // (2**53)-1
                    CHECK(accept_helper("9007199254740991"));
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
                    CHECK(accept_helper("-9223372036854775808"));
                    // (2**63)-1
                    CHECK(accept_helper("9223372036854775807"));
                    // (2**64)-1
                    CHECK(accept_helper("18446744073709551615"));
                }
            }

            SECTION("floating-point")
            {
                SECTION("without exponent")
                {
                    CHECK(accept_helper("-128.5"));
                    CHECK(accept_helper("0.999"));
                    CHECK(accept_helper("128.5"));
                    CHECK(accept_helper("-0.0"));
                }

                SECTION("with exponent")
                {
                    CHECK(accept_helper("-128.5E3"));
                    CHECK(accept_helper("-128.5E-3"));
                    CHECK(accept_helper("-0.0e1"));
                    CHECK(accept_helper("-0.0E1"));
                }
            }

            SECTION("overflow")
            {
                // overflows during parsing
                CHECK(not accept_helper("1.18973e+4932"));
            }

            SECTION("invalid numbers")
            {
                CHECK(accept_helper("01") == false);
                CHECK(accept_helper("--1") == false);
                CHECK(accept_helper("1.") == false);
                CHECK(accept_helper("1E") == false);
                CHECK(accept_helper("1E-") == false);
                CHECK(accept_helper("1.E1") == false);
                CHECK(accept_helper("-1E") == false);
                CHECK(accept_helper("-0E#") == false);
                CHECK(accept_helper("-0E-#") == false);
                CHECK(accept_helper("-0#") == false);
                CHECK(accept_helper("-0.0:") == false);
                CHECK(accept_helper("-0.0Z") == false);
                CHECK(accept_helper("-0E123:") == false);
                CHECK(accept_helper("-0e0-:") == false);
                CHECK(accept_helper("-0e-:") == false);
                CHECK(accept_helper("-0f") == false);

                // numbers must not begin with "+"
                CHECK(accept_helper("+1") == false);
                CHECK(accept_helper("+0") == false);
            }
        }
    }

    SECTION("parse errors")
    {
        // unexpected end of number
        CHECK_THROWS_AS(parser_helper("0."),  json::parse_error&);
        CHECK_THROWS_AS(parser_helper("-"),   json::parse_error&);
        CHECK_THROWS_AS(parser_helper("--"),  json::parse_error&);
        CHECK_THROWS_AS(parser_helper("-0."), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("-."),  json::parse_error&);
        CHECK_THROWS_AS(parser_helper("-:"),  json::parse_error&);
        CHECK_THROWS_AS(parser_helper("0.:"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("e."),  json::parse_error&);
        CHECK_THROWS_AS(parser_helper("1e."), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("1e/"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("1e:"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("1E."), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("1E/"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("1E:"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("0."),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected digit after '.'; last read: '0.'");
        CHECK_THROWS_WITH(parser_helper("-"),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '-'");
        CHECK_THROWS_WITH(parser_helper("--"),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '--'");
        CHECK_THROWS_WITH(parser_helper("-0."),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid number; expected digit after '.'; last read: '-0.'");
        CHECK_THROWS_WITH(parser_helper("-."),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '-.'");
        CHECK_THROWS_WITH(parser_helper("-:"),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '-:'");
        CHECK_THROWS_WITH(parser_helper("0.:"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected digit after '.'; last read: '0.:'");
        CHECK_THROWS_WITH(parser_helper("e."),
                          "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - invalid literal; last read: 'e'");
        CHECK_THROWS_WITH(parser_helper("1e."),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1e.'");
        CHECK_THROWS_WITH(parser_helper("1e/"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1e/'");
        CHECK_THROWS_WITH(parser_helper("1e:"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1e:'");
        CHECK_THROWS_WITH(parser_helper("1E."),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E.'");
        CHECK_THROWS_WITH(parser_helper("1E/"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E/'");
        CHECK_THROWS_WITH(parser_helper("1E:"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E:'");

        // unexpected end of null
        CHECK_THROWS_AS(parser_helper("n"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("nu"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("nul"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("nulk"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("nulm"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("n"),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 'n'");
        CHECK_THROWS_WITH(parser_helper("nu"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid literal; last read: 'nu'");
        CHECK_THROWS_WITH(parser_helper("nul"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'nul'");
        CHECK_THROWS_WITH(parser_helper("nulk"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'nulk'");
        CHECK_THROWS_WITH(parser_helper("nulm"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'nulm'");

        // unexpected end of true
        CHECK_THROWS_AS(parser_helper("t"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("tr"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("tru"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("trud"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("truf"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("t"),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 't'");
        CHECK_THROWS_WITH(parser_helper("tr"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid literal; last read: 'tr'");
        CHECK_THROWS_WITH(parser_helper("tru"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'tru'");
        CHECK_THROWS_WITH(parser_helper("trud"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'trud'");
        CHECK_THROWS_WITH(parser_helper("truf"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'truf'");

        // unexpected end of false
        CHECK_THROWS_AS(parser_helper("f"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("fa"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("fal"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("fals"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("falsd"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("falsf"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("f"),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 'f'");
        CHECK_THROWS_WITH(parser_helper("fa"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid literal; last read: 'fa'");
        CHECK_THROWS_WITH(parser_helper("fal"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'fal'");
        CHECK_THROWS_WITH(parser_helper("fals"),
                          "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: 'fals'");
        CHECK_THROWS_WITH(parser_helper("falsd"),
                          "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: 'falsd'");
        CHECK_THROWS_WITH(parser_helper("falsf"),
                          "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: 'falsf'");

        // missing/unexpected end of array
        CHECK_THROWS_AS(parser_helper("["), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("[1"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("[1,"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("[1,]"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("]"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("["),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal");
        CHECK_THROWS_WITH(parser_helper("[1"),
                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing array - unexpected end of input; expected ']'");
        CHECK_THROWS_WITH(parser_helper("[1,"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal");
        CHECK_THROWS_WITH(parser_helper("[1,]"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal");
        CHECK_THROWS_WITH(parser_helper("]"),
                          "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal");

        // missing/unexpected end of object
        CHECK_THROWS_AS(parser_helper("{"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("{\"foo\""), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("{\"foo\":"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("{\"foo\":}"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("{\"foo\":1,}"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("}"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("{"),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing object key - unexpected end of input; expected string literal");
        CHECK_THROWS_WITH(parser_helper("{\"foo\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing object separator - unexpected end of input; expected ':'");
        CHECK_THROWS_WITH(parser_helper("{\"foo\":"),
                          "[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal");
        CHECK_THROWS_WITH(parser_helper("{\"foo\":}"),
                          "[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - unexpected '}'; expected '[', '{', or a literal");
        CHECK_THROWS_WITH(parser_helper("{\"foo\":1,}"),
                          "[json.exception.parse_error.101] parse error at line 1, column 10: syntax error while parsing object key - unexpected '}'; expected string literal");
        CHECK_THROWS_WITH(parser_helper("}"),
                          "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected '}'; expected '[', '{', or a literal");

        // missing/unexpected end of string
        CHECK_THROWS_AS(parser_helper("\""), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\\""), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\u\""), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\u0\""), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\u01\""), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\u012\""), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\u"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\u0"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\u01"), json::parse_error&);
        CHECK_THROWS_AS(parser_helper("\"\\u012"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: missing closing quote; last read: '\"'");
        CHECK_THROWS_WITH(parser_helper("\"\\\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: missing closing quote; last read: '\"\\\"'");
        CHECK_THROWS_WITH(parser_helper("\"\\u\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u\"'");
        CHECK_THROWS_WITH(parser_helper("\"\\u0\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u0\"'");
        CHECK_THROWS_WITH(parser_helper("\"\\u01\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u01\"'");
        CHECK_THROWS_WITH(parser_helper("\"\\u012\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u012\"'");
        CHECK_THROWS_WITH(parser_helper("\"\\u"),
                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u'");
        CHECK_THROWS_WITH(parser_helper("\"\\u0"),
                          "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u0'");
        CHECK_THROWS_WITH(parser_helper("\"\\u01"),
                          "[json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u01'");
        CHECK_THROWS_WITH(parser_helper("\"\\u012"),
                          "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u012'");

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
                    CHECK_NOTHROW(parser_helper(s.c_str()));
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
                    CHECK_THROWS_AS(parser_helper(s.c_str()), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parser_helper(s.c_str()),
                                          "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid string: forbidden character after backslash; last read: '\"\\" + std::string(1, static_cast<char>(c)) + "'");
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
                    CAPTURE(s1)
                    CHECK_NOTHROW(parser_helper(s1.c_str()));
                    CAPTURE(s2)
                    CHECK_NOTHROW(parser_helper(s2.c_str()));
                    CAPTURE(s3)
                    CHECK_NOTHROW(parser_helper(s3.c_str()));
                    CAPTURE(s4)
                    CHECK_NOTHROW(parser_helper(s4.c_str()));
                }
                else
                {
                    CAPTURE(s1)
                    CHECK_THROWS_AS(parser_helper(s1.c_str()), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parser_helper(s1.c_str()),
                                          "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '" + s1.substr(0, 7) + "'");
                    }

                    CAPTURE(s2)
                    CHECK_THROWS_AS(parser_helper(s2.c_str()), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parser_helper(s2.c_str()),
                                          "[json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '" + s2.substr(0, 6) + "'");
                    }

                    CAPTURE(s3)
                    CHECK_THROWS_AS(parser_helper(s3.c_str()), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parser_helper(s3.c_str()),
                                          "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '" + s3.substr(0, 5) + "'");
                    }

                    CAPTURE(s4)
                    CHECK_THROWS_AS(parser_helper(s4.c_str()), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH(parser_helper(s4.c_str()),
                                          "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '" + s4.substr(0, 4) + "'");
                    }
                }
            }
        }

        // missing part of a surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\""), json::parse_error&);
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - invalid string: surrogate U+DC00..U+DFFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD80C\"'");
        // invalid surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uD80C\""), json::parse_error&);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\u0000\""), json::parse_error&);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uFFFF\""), json::parse_error&);
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\uD80C\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+DC00..U+DFFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD80C\\uD80C'");
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\u0000\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+DC00..U+DFFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD80C\\u0000'");
        CHECK_THROWS_WITH(json::parse("\"\\uD80C\\uFFFF\""),
                          "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+DC00..U+DFFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD80C\\uFFFF'");
    }

    SECTION("parse errors (accept)")
    {
        // unexpected end of number
        CHECK(accept_helper("0.") == false);
        CHECK(accept_helper("-") == false);
        CHECK(accept_helper("--") == false);
        CHECK(accept_helper("-0.") == false);
        CHECK(accept_helper("-.") == false);
        CHECK(accept_helper("-:") == false);
        CHECK(accept_helper("0.:") == false);
        CHECK(accept_helper("e.") == false);
        CHECK(accept_helper("1e.") == false);
        CHECK(accept_helper("1e/") == false);
        CHECK(accept_helper("1e:") == false);
        CHECK(accept_helper("1E.") == false);
        CHECK(accept_helper("1E/") == false);
        CHECK(accept_helper("1E:") == false);

        // unexpected end of null
        CHECK(accept_helper("n") == false);
        CHECK(accept_helper("nu") == false);
        CHECK(accept_helper("nul") == false);

        // unexpected end of true
        CHECK(accept_helper("t") == false);
        CHECK(accept_helper("tr") == false);
        CHECK(accept_helper("tru") == false);

        // unexpected end of false
        CHECK(accept_helper("f") == false);
        CHECK(accept_helper("fa") == false);
        CHECK(accept_helper("fal") == false);
        CHECK(accept_helper("fals") == false);

        // missing/unexpected end of array
        CHECK(accept_helper("[") == false);
        CHECK(accept_helper("[1") == false);
        CHECK(accept_helper("[1,") == false);
        CHECK(accept_helper("[1,]") == false);
        CHECK(accept_helper("]") == false);

        // missing/unexpected end of object
        CHECK(accept_helper("{") == false);
        CHECK(accept_helper("{\"foo\"") == false);
        CHECK(accept_helper("{\"foo\":") == false);
        CHECK(accept_helper("{\"foo\":}") == false);
        CHECK(accept_helper("{\"foo\":1,}") == false);
        CHECK(accept_helper("}") == false);

        // missing/unexpected end of string
        CHECK(accept_helper("\"") == false);
        CHECK(accept_helper("\"\\\"") == false);
        CHECK(accept_helper("\"\\u\"") == false);
        CHECK(accept_helper("\"\\u0\"") == false);
        CHECK(accept_helper("\"\\u01\"") == false);
        CHECK(accept_helper("\"\\u012\"") == false);
        CHECK(accept_helper("\"\\u") == false);
        CHECK(accept_helper("\"\\u0") == false);
        CHECK(accept_helper("\"\\u01") == false);
        CHECK(accept_helper("\"\\u012") == false);

        // unget of newline
        CHECK(parser_helper("\n123\n") == 123);

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
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s.c_str()))).accept());
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
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s.c_str()))).accept() == false);
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
                    CAPTURE(s1)
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s1.c_str()))).accept());
                    CAPTURE(s2)
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s2.c_str()))).accept());
                    CAPTURE(s3)
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s3.c_str()))).accept());
                    CAPTURE(s4)
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s4.c_str()))).accept());
                }
                else
                {
                    CAPTURE(s1)
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s1.c_str()))).accept() == false);

                    CAPTURE(s2)
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s2.c_str()))).accept() == false);

                    CAPTURE(s3)
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s3.c_str()))).accept() == false);

                    CAPTURE(s4)
                    CHECK(json::parser(nlohmann::detail::input_adapter(std::string(s4.c_str()))).accept() == false);
                }
            }
        }

        // missing part of a surrogate pair
        CHECK(accept_helper("\"\\uD80C\"") == false);
        // invalid surrogate pair
        CHECK(accept_helper("\"\\uD80C\\uD80C\"") == false);
        CHECK(accept_helper("\"\\uD80C\\u0000\"") == false);
        CHECK(accept_helper("\"\\uD80C\\uFFFF\"") == false);
    }

    SECTION("tests found by mutate++")
    {
        // test case to make sure no comma preceeds the first key
        CHECK_THROWS_AS(parser_helper("{,\"key\": false}"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("{,\"key\": false}"),
                          "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing object key - unexpected ','; expected string literal");
        // test case to make sure an object is properly closed
        CHECK_THROWS_AS(parser_helper("[{\"key\": false true]"), json::parse_error&);
        CHECK_THROWS_WITH(parser_helper("[{\"key\": false true]"),
                          "[json.exception.parse_error.101] parse error at line 1, column 19: syntax error while parsing object - unexpected true literal; expected '}'");

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
            json j;
            json::parser(nlohmann::detail::input_adapter(std::begin(v), std::end(v))).parse(true, j);
            CHECK(j == json(true));
        }

        SECTION("from std::array")
        {
            std::array<uint8_t, 5> v { {'t', 'r', 'u', 'e'} };
            json j;
            json::parser(nlohmann::detail::input_adapter(std::begin(v), std::end(v))).parse(true, j);
            CHECK(j == json(true));
        }

        SECTION("from array")
        {
            uint8_t v[] = {'t', 'r', 'u', 'e'};
            json j;
            json::parser(nlohmann::detail::input_adapter(std::begin(v), std::end(v))).parse(true, j);
            CHECK(j == json(true));
        }

        SECTION("from char literal")
        {
            CHECK(parser_helper("true") == json(true));
        }

        SECTION("from std::string")
        {
            std::string v = {'t', 'r', 'u', 'e'};
            json j;
            json::parser(nlohmann::detail::input_adapter(std::begin(v), std::end(v))).parse(true, j);
            CHECK(j == json(true));
        }

        SECTION("from std::initializer_list")
        {
            std::initializer_list<uint8_t> v = {'t', 'r', 'u', 'e'};
            json j;
            json::parser(nlohmann::detail::input_adapter(std::begin(v), std::end(v))).parse(true, j);
            CHECK(j == json(true));
        }

        SECTION("from std::valarray")
        {
            std::valarray<uint8_t> v = {'t', 'r', 'u', 'e'};
            json j;
            json::parser(nlohmann::detail::input_adapter(std::begin(v), std::end(v))).parse(true, j);
            CHECK(j == json(true));
        }
    }

    SECTION("improve test coverage")
    {
        SECTION("parser with callback")
        {
            json::parser_callback_t cb = [](int, json::parse_event_t, json&)
            {
                return true;
            };

            CHECK(json::parse("{\"foo\": true:", cb, false).is_discarded());

            CHECK_THROWS_AS(json::parse("{\"foo\": true:", cb), json::parse_error&);
            CHECK_THROWS_WITH(json::parse("{\"foo\": true:", cb),
                              "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing object - unexpected ':'; expected '}'");

            CHECK_THROWS_AS(json::parse("1.18973e+4932", cb), json::out_of_range&);
            CHECK_THROWS_WITH(json::parse("1.18973e+4932", cb),
                              "[json.exception.out_of_range.406] number overflow parsing '1.18973e+4932'");
        }

        SECTION("SAX parser")
        {
            SECTION("} without value")
            {
                SaxCountdown s(1);
                CHECK(json::sax_parse("{}", &s) == false);
            }

            SECTION("} with value")
            {
                SaxCountdown s(3);
                CHECK(json::sax_parse("{\"k1\": true}", &s) == false);
            }

            SECTION("second key")
            {
                SaxCountdown s(3);
                CHECK(json::sax_parse("{\"k1\": true, \"k2\": false}", &s) == false);
            }

            SECTION("] without value")
            {
                SaxCountdown s(1);
                CHECK(json::sax_parse("[]", &s) == false);
            }

            SECTION("] with value")
            {
                SaxCountdown s(2);
                CHECK(json::sax_parse("[1]", &s) == false);
            }

            SECTION("float")
            {
                SaxCountdown s(0);
                CHECK(json::sax_parse("3.14", &s) == false);
            }

            SECTION("false")
            {
                SaxCountdown s(0);
                CHECK(json::sax_parse("false", &s) == false);
            }

            SECTION("null")
            {
                SaxCountdown s(0);
                CHECK(json::sax_parse("null", &s) == false);
            }

            SECTION("true")
            {
                SaxCountdown s(0);
                CHECK(json::sax_parse("true", &s) == false);
            }

            SECTION("unsigned")
            {
                SaxCountdown s(0);
                CHECK(json::sax_parse("12", &s) == false);
            }

            SECTION("integer")
            {
                SaxCountdown s(0);
                CHECK(json::sax_parse("-12", &s) == false);
            }

            SECTION("string")
            {
                SaxCountdown s(0);
                CHECK(json::sax_parse("\"foo\"", &s) == false);
            }
        }
    }
}
