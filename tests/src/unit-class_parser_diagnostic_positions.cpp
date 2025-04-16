//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"
#define JSON_TESTS_PRIVATE
#ifdef JSON_DIAGNOSTIC_POSITIONS
    #undef JSON_DIAGNOSTIC_POSITIONS
#endif

#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json.hpp>
using nlohmann::json;

#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <valarray>

namespace
{
class SaxEventLogger
{
  public:
    bool null()
    {
        events.emplace_back("null()");
        return true;
    }

    bool boolean(bool val)
    {
        events.emplace_back(val ? "boolean(true)" : "boolean(false)");
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

    bool number_float(json::number_float_t /*unused*/, const std::string& s)
    {
        events.push_back("number_float(" + s + ")");
        return true;
    }

    bool string(std::string& val)
    {
        events.push_back("string(" + val + ")");
        return true;
    }

    bool binary(json::binary_t& val)
    {
        std::string binary_contents = "binary(";
        std::string comma_space;
        for (auto b : val)
        {
            binary_contents.append(comma_space);
            binary_contents.append(std::to_string(static_cast<int>(b)));
            comma_space = ", ";
        }
        binary_contents.append(")");
        events.push_back(binary_contents);
        return true;
    }

    bool start_object(std::size_t elements)
    {
        if (elements == (std::numeric_limits<std::size_t>::max)())
        {
            events.emplace_back("start_object()");
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
        events.emplace_back("end_object()");
        return true;
    }

    bool start_array(std::size_t elements)
    {
        if (elements == (std::numeric_limits<std::size_t>::max)())
        {
            events.emplace_back("start_array()");
        }
        else
        {
            events.push_back("start_array(" + std::to_string(elements) + ")");
        }
        return true;
    }

    bool end_array()
    {
        events.emplace_back("end_array()");
        return true;
    }

    bool parse_error(std::size_t position, const std::string& /*unused*/, const json::exception& /*unused*/)
    {
        errored = true;
        events.push_back("parse_error(" + std::to_string(position) + ")");
        return false;
    }

    std::vector<std::string> events {}; // NOLINT(readability-redundant-member-init)
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

    bool boolean(bool /*val*/) override
    {
        return events_left-- > 0;
    }

    bool number_integer(json::number_integer_t /*val*/) override
    {
        return events_left-- > 0;
    }

    bool number_unsigned(json::number_unsigned_t /*val*/) override
    {
        return events_left-- > 0;
    }

    bool number_float(json::number_float_t /*val*/, const std::string& /*s*/) override
    {
        return events_left-- > 0;
    }

    bool string(std::string& /*val*/) override
    {
        return events_left-- > 0;
    }

    bool binary(json::binary_t& /*val*/) override
    {
        return events_left-- > 0;
    }

    bool start_object(std::size_t /*elements*/) override
    {
        return events_left-- > 0;
    }

    bool key(std::string& /*val*/) override
    {
        return events_left-- > 0;
    }

    bool end_object() override
    {
        return events_left-- > 0;
    }

    bool start_array(std::size_t /*elements*/) override
    {
        return events_left-- > 0;
    }

    bool end_array() override
    {
        return events_left-- > 0;
    }

    bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const json::exception& /*ex*/) override
    {
        return false;
    }

  private:
    int events_left = 0;
};

json parser_helper(const std::string& s);
bool accept_helper(const std::string& s);
void comments_helper(const std::string& s);

json parser_helper(const std::string& s)
{
    json j;
    json::parser(nlohmann::detail::input_adapter(s)).parse(true, j);

    // if this line was reached, no exception occurred
    // -> check if result is the same without exceptions
    json j_nothrow;
    CHECK_NOTHROW(json::parser(nlohmann::detail::input_adapter(s), nullptr, false).parse(true, j_nothrow));
    CHECK(j_nothrow == j);

    json j_sax;
    nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type> sdp(j_sax);
    json::sax_parse(s, &sdp);
    CHECK(j_sax == j);

    comments_helper(s);

    return j;
}

bool accept_helper(const std::string& s)
{
    CAPTURE(s)

    // 1. parse s without exceptions
    json j;
    CHECK_NOTHROW(json::parser(nlohmann::detail::input_adapter(s), nullptr, false).parse(true, j));
    const bool ok_noexcept = !j.is_discarded();

    // 2. accept s
    const bool ok_accept = json::parser(nlohmann::detail::input_adapter(s)).accept(true);

    // 3. check if both approaches come to the same result
    CHECK(ok_noexcept == ok_accept);

    // 4. parse with SAX (compare with relaxed accept result)
    SaxEventLogger el;
    CHECK_NOTHROW(json::sax_parse(s, &el, json::input_format_t::json, false));
    CHECK(json::parser(nlohmann::detail::input_adapter(s)).accept(false) == !el.errored);

    // 5. parse with simple callback
    json::parser_callback_t const cb = [](int /*unused*/, json::parse_event_t /*unused*/, json& /*unused*/) noexcept
    {
        return true;
    };
    json const j_cb = json::parse(s, cb, false);
    const bool ok_noexcept_cb = !j_cb.is_discarded();

    // 6. check if this approach came to the same result
    CHECK(ok_noexcept == ok_noexcept_cb);

    // 7. check if comments are properly ignored
    if (ok_accept)
    {
        comments_helper(s);
    }

    // 8. return result
    return ok_accept;
}

void comments_helper(const std::string& s)
{
    json _;

    // parse/accept with default parser
    CHECK_NOTHROW(_ = json::parse(s));
    CHECK(json::accept(s));

    // parse/accept while skipping comments
    CHECK_NOTHROW(_ = json::parse(s, nullptr, false, true));
    CHECK(json::accept(s, true));

    std::vector<std::string> json_with_comments;

    // start with a comment
    json_with_comments.push_back(std::string("// this is a comment\n") + s);
    json_with_comments.push_back(std::string("/* this is a comment */") + s);
    // end with a comment
    json_with_comments.push_back(s + "// this is a comment");
    json_with_comments.push_back(s + "/* this is a comment */");

    // check all strings
    for (const auto& json_with_comment : json_with_comments)
    {
        CAPTURE(json_with_comment)
        CHECK_THROWS_AS(_ = json::parse(json_with_comment), json::parse_error);
        CHECK(!json::accept(json_with_comment));

        CHECK_NOTHROW(_ = json::parse(json_with_comment, nullptr, true, true));
        CHECK(json::accept(json_with_comment, true));
    }
}

/**
 * Validates that the generated JSON object is the same as expected
 * Validates that the start position and end position match the start and end of the string
 *
 * This check assumes that there is no whitespace around the json object in the original string.
 */
void validate_generated_json_and_start_end_pos_helper(const std::string& original_string, const json& j, const json& check)
{
    CHECK(j == check);
    CHECK(j.start_pos() == 0);
    CHECK(j.end_pos() == original_string.size());
}

/**
 * Parses the root object from the given root string and validates that the start and end positions for the nested object are correct.
 *
 * This checks that whitespace around the nested object is included in the start and end positions of the root object.
 */
void validate_start_end_pos_for_nested_obj_helper(const std::string& nested_type_json_str, const std::string& root_type_json_str, const json& expected_json, const json::parser_callback_t& cb = nullptr)
{
    json j;

    // 1. If callback is provided, use callback version of parse()
    if (cb)
    {
        j = json::parse(root_type_json_str, cb);
    }
    else
    {
        j = json::parse(root_type_json_str);
    }

    // 2. Check if the generated JSON is as expected
    // Assumptions: The root_type_json_str does not have any whitespace around the json object
    validate_generated_json_and_start_end_pos_helper(root_type_json_str, j, expected_json);

    // 3. Get the nested object
    const auto& nested = j["nested"];
    // 4. Check if the start and end positions are generated correctly for nested objects and arrays
    CHECK(nested_type_json_str == root_type_json_str.substr(nested.start_pos(), nested.end_pos() - nested.start_pos()));
}

} // namespace

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
                CHECK_THROWS_WITH_AS(parser_helper("\"\t\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0009 (HT) must be escaped to \\u0009 or \\t; last read: '\"<U+0009>'", json::parse_error&);
                // error: newline in string
                CHECK_THROWS_WITH_AS(parser_helper("\"\n\""), "[json.exception.parse_error.101] parse error at line 2, column 0: syntax error while parsing value - invalid string: control character U+000A (LF) must be escaped to \\u000A or \\n; last read: '\"<U+000A>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\r\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000D (CR) must be escaped to \\u000D or \\r; last read: '\"<U+000D>'", json::parse_error&);
                // error: backspace in string
                CHECK_THROWS_WITH_AS(parser_helper("\"\b\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0008 (BS) must be escaped to \\u0008 or \\b; last read: '\"<U+0008>'", json::parse_error&);
                // improve code coverage
                CHECK_THROWS_AS(parser_helper("\uFF01"), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("[-4:1,]"), json::parse_error&);
                // unescaped control characters
                CHECK_THROWS_WITH_AS(parser_helper("\"\x00\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: missing closing quote; last read: '\"'", json::parse_error&); // NOLINT(bugprone-string-literal-with-embedded-nul)
                CHECK_THROWS_WITH_AS(parser_helper("\"\x01\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0001 (SOH) must be escaped to \\u0001; last read: '\"<U+0001>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x02\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0002 (STX) must be escaped to \\u0002; last read: '\"<U+0002>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x03\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0003 (ETX) must be escaped to \\u0003; last read: '\"<U+0003>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x04\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0004 (EOT) must be escaped to \\u0004; last read: '\"<U+0004>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x05\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0005 (ENQ) must be escaped to \\u0005; last read: '\"<U+0005>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x06\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0006 (ACK) must be escaped to \\u0006; last read: '\"<U+0006>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x07\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0007 (BEL) must be escaped to \\u0007; last read: '\"<U+0007>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x08\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0008 (BS) must be escaped to \\u0008 or \\b; last read: '\"<U+0008>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x09\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0009 (HT) must be escaped to \\u0009 or \\t; last read: '\"<U+0009>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x0a\""), "[json.exception.parse_error.101] parse error at line 2, column 0: syntax error while parsing value - invalid string: control character U+000A (LF) must be escaped to \\u000A or \\n; last read: '\"<U+000A>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x0b\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000B (VT) must be escaped to \\u000B; last read: '\"<U+000B>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x0c\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000C (FF) must be escaped to \\u000C or \\f; last read: '\"<U+000C>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x0d\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000D (CR) must be escaped to \\u000D or \\r; last read: '\"<U+000D>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x0e\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000E (SO) must be escaped to \\u000E; last read: '\"<U+000E>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x0f\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+000F (SI) must be escaped to \\u000F; last read: '\"<U+000F>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x10\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0010 (DLE) must be escaped to \\u0010; last read: '\"<U+0010>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x11\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0011 (DC1) must be escaped to \\u0011; last read: '\"<U+0011>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x12\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0012 (DC2) must be escaped to \\u0012; last read: '\"<U+0012>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x13\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0013 (DC3) must be escaped to \\u0013; last read: '\"<U+0013>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x14\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0014 (DC4) must be escaped to \\u0014; last read: '\"<U+0014>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x15\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0015 (NAK) must be escaped to \\u0015; last read: '\"<U+0015>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x16\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0016 (SYN) must be escaped to \\u0016; last read: '\"<U+0016>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x17\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0017 (ETB) must be escaped to \\u0017; last read: '\"<U+0017>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x18\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0018 (CAN) must be escaped to \\u0018; last read: '\"<U+0018>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x19\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0019 (EM) must be escaped to \\u0019; last read: '\"<U+0019>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x1a\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001A (SUB) must be escaped to \\u001A; last read: '\"<U+001A>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x1b\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001B (ESC) must be escaped to \\u001B; last read: '\"<U+001B>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x1c\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001C (FS) must be escaped to \\u001C; last read: '\"<U+001C>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x1d\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001D (GS) must be escaped to \\u001D; last read: '\"<U+001D>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x1e\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001E (RS) must be escaped to \\u001E; last read: '\"<U+001E>'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("\"\x1f\""), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+001F (US) must be escaped to \\u001F; last read: '\"<U+001F>'", json::parse_error&);

                SECTION("additional test for null byte")
                {
                    // The test above for the null byte is wrong, because passing
                    // a string to the parser only reads int until it encounters
                    // a null byte. This test inserts the null byte later on and
                    // uses an iterator range.
                    std::string s = "\"1\"";
                    s[1] = '\0';
                    json _;
                    CHECK_THROWS_WITH_AS(_ = json::parse(s.begin(), s.end()), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0000 (NUL) must be escaped to \\u0000; last read: '\"<U+0000>'", json::parse_error&);
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

                CHECK(parser_helper("\"\\ud80c\\udc60\"").get<json::string_t>() == "\xf0\x93\x81\xa0");
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
                    // From RFC8259, Section 6:
                    // Note that when such software is used, numbers that are
                    // integers and are in the range [-(2**53)+1, (2**53)-1]
                    // are interoperable in the sense that implementations will
                    // agree exactly on their numeric values.

                    // -(2**53)+1
                    CHECK(parser_helper("-9007199254740991").get<int64_t>() == -9007199254740991);
                    // (2**53)-1
                    CHECK(parser_helper("9007199254740991").get<int64_t>() == 9007199254740991);
                }

                SECTION("over the edge cases")  // issue #178 - Integer conversion to unsigned (incorrect handling of 64-bit integers)
                {
                    // While RFC8259, Section 6 specifies a preference for support
                    // for ranges in range of IEEE 754-2008 binary64 (double precision)
                    // this does not accommodate 64-bit integers without loss of accuracy.
                    // As 64-bit integers are now widely used in software, it is desirable
                    // to expand support to the full 64 bit (signed and unsigned) range
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
                CHECK_THROWS_WITH_AS(parser_helper("1.18973e+4932").empty(), "[json.exception.out_of_range.406] number overflow parsing '1.18973e+4932'", json::out_of_range&);
            }

            SECTION("invalid numbers")
            {
                // numbers must not begin with "+"
                CHECK_THROWS_AS(parser_helper("+1"), json::parse_error&);
                CHECK_THROWS_AS(parser_helper("+0"), json::parse_error&);

                CHECK_THROWS_WITH_AS(parser_helper("01"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - unexpected number literal; expected end of input", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-01"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - unexpected number literal; expected end of input", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("--1"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '--'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("1."),
                                     "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected digit after '.'; last read: '1.'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("1E"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("1E-"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid number; expected digit after exponent sign; last read: '1E-'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("1.E1"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected digit after '.'; last read: '1.E'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-1E"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '-1E'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0E#"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '-0E#'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0E-#"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid number; expected digit after exponent sign; last read: '-0E-#'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0#"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid literal; last read: '-0#'; expected end of input", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0.0:"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - unexpected ':'; expected end of input", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0.0Z"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: '-0.0Z'; expected end of input", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0E123:"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - unexpected ':'; expected end of input", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0e0-:"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid number; expected digit after '-'; last read: '-:'; expected end of input", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0e-:"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid number; expected digit after exponent sign; last read: '-0e-:'", json::parse_error&);
                CHECK_THROWS_WITH_AS(parser_helper("-0f"),
                                     "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: '-0f'; expected end of input", json::parse_error&);
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
                CHECK(accept_helper("\"\x00\"") == false); // NOLINT(bugprone-string-literal-with-embedded-nul)
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
                    // From RFC8259, Section 6:
                    // Note that when such software is used, numbers that are
                    // integers and are in the range [-(2**53)+1, (2**53)-1]
                    // are interoperable in the sense that implementations will
                    // agree exactly on their numeric values.

                    // -(2**53)+1
                    CHECK(accept_helper("-9007199254740991"));
                    // (2**53)-1
                    CHECK(accept_helper("9007199254740991"));
                }

                SECTION("over the edge cases")  // issue #178 - Integer conversion to unsigned (incorrect handling of 64-bit integers)
                {
                    // While RFC8259, Section 6 specifies a preference for support
                    // for ranges in range of IEEE 754-2008 binary64 (double precision)
                    // this does not accommodate 64 bit integers without loss of accuracy.
                    // As 64 bit integers are now widely used in software, it is desirable
                    // to expand support to the full 64 bit (signed and unsigned) range
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
                CHECK(!accept_helper("1.18973e+4932"));
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
        CHECK_THROWS_WITH_AS(parser_helper("0."),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected digit after '.'; last read: '0.'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("-"),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '-'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("--"),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '--'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("-0."),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid number; expected digit after '.'; last read: '-0.'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("-."),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '-.'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("-:"),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid number; expected digit after '-'; last read: '-:'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("0.:"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected digit after '.'; last read: '0.:'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("e."),
                             "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - invalid literal; last read: 'e'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("1e."),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1e.'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("1e/"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1e/'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("1e:"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1e:'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("1E."),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E.'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("1E/"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E/'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("1E:"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E:'", json::parse_error&);

        // unexpected end of null
        CHECK_THROWS_WITH_AS(parser_helper("n"),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 'n'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("nu"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid literal; last read: 'nu'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("nul"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'nul'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("nulk"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'nulk'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("nulm"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'nulm'", json::parse_error&);

        // unexpected end of true
        CHECK_THROWS_WITH_AS(parser_helper("t"),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 't'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("tr"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid literal; last read: 'tr'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("tru"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'tru'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("trud"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'trud'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("truf"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'truf'", json::parse_error&);

        // unexpected end of false
        CHECK_THROWS_WITH_AS(parser_helper("f"),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 'f'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("fa"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid literal; last read: 'fa'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("fal"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: 'fal'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("fals"),
                             "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: 'fals'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("falsd"),
                             "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: 'falsd'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("falsf"),
                             "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: 'falsf'", json::parse_error&);

        // missing/unexpected end of array
        CHECK_THROWS_WITH_AS(parser_helper("["),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("[1"),
                             "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing array - unexpected end of input; expected ']'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("[1,"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("[1,]"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("]"),
                             "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal", json::parse_error&);

        // missing/unexpected end of object
        CHECK_THROWS_WITH_AS(parser_helper("{"),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing object key - unexpected end of input; expected string literal", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("{\"foo\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing object separator - unexpected end of input; expected ':'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("{\"foo\":"),
                             "[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("{\"foo\":}"),
                             "[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - unexpected '}'; expected '[', '{', or a literal", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("{\"foo\":1,}"),
                             "[json.exception.parse_error.101] parse error at line 1, column 10: syntax error while parsing object key - unexpected '}'; expected string literal", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("}"),
                             "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected '}'; expected '[', '{', or a literal", json::parse_error&);

        // missing/unexpected end of string
        CHECK_THROWS_WITH_AS(parser_helper("\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: missing closing quote; last read: '\"'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: missing closing quote; last read: '\"\\\"'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\u\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u\"'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\u0\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u0\"'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\u01\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u01\"'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\u012\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u012\"'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\u"),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\u0"),
                             "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u0'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\u01"),
                             "[json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u01'", json::parse_error&);
        CHECK_THROWS_WITH_AS(parser_helper("\"\\u012"),
                             "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '\"\\u012'", json::parse_error&);

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
                    CHECK_NOTHROW(parser_helper(s));
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
                    CHECK_THROWS_AS(parser_helper(s), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH_STD_STR(parser_helper(s),
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
                std::string const s = "\"\\u";

                // create a string with the iterated character at each position
                auto s1 = s + "000" + std::string(1, static_cast<char>(c)) + "\"";
                auto s2 = s + "00" + std::string(1, static_cast<char>(c)) + "0\"";
                auto s3 = s + "0" + std::string(1, static_cast<char>(c)) + "00\"";
                auto s4 = s + std::string(1, static_cast<char>(c)) + "000\"";

                if (valid(c))
                {
                    CAPTURE(s1)
                    CHECK_NOTHROW(parser_helper(s1));
                    CAPTURE(s2)
                    CHECK_NOTHROW(parser_helper(s2));
                    CAPTURE(s3)
                    CHECK_NOTHROW(parser_helper(s3));
                    CAPTURE(s4)
                    CHECK_NOTHROW(parser_helper(s4));
                }
                else
                {
                    CAPTURE(s1)
                    CHECK_THROWS_AS(parser_helper(s1), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH_STD_STR(parser_helper(s1),
                                                  "[json.exception.parse_error.101] parse error at line 1, column 7: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '" + s1.substr(0, 7) + "'");
                    }

                    CAPTURE(s2)
                    CHECK_THROWS_AS(parser_helper(s2), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH_STD_STR(parser_helper(s2),
                                                  "[json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '" + s2.substr(0, 6) + "'");
                    }

                    CAPTURE(s3)
                    CHECK_THROWS_AS(parser_helper(s3), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH_STD_STR(parser_helper(s3),
                                                  "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '" + s3.substr(0, 5) + "'");
                    }

                    CAPTURE(s4)
                    CHECK_THROWS_AS(parser_helper(s4), json::parse_error&);
                    // only check error message if c is not a control character
                    if (c > 0x1f)
                    {
                        CHECK_THROWS_WITH_STD_STR(parser_helper(s4),
                                                  "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid string: '\\u' must be followed by 4 hex digits; last read: '" + s4.substr(0, 4) + "'");
                    }
                }
            }
        }

        json _;

        // missing part of a surrogate pair
        CHECK_THROWS_WITH_AS(_ = json::parse("\"\\uD80C\""), "[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD80C\"'", json::parse_error&);
        // invalid surrogate pair
        CHECK_THROWS_WITH_AS(_ = json::parse("\"\\uD80C\\uD80C\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD80C\\uD80C'", json::parse_error&);
        CHECK_THROWS_WITH_AS(_ = json::parse("\"\\uD80C\\u0000\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD80C\\u0000'", json::parse_error&);
        CHECK_THROWS_WITH_AS(_ = json::parse("\"\\uD80C\\uFFFF\""),
                             "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF; last read: '\"\\uD80C\\uFFFF'", json::parse_error&);
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
                    CHECK(json::parser(nlohmann::detail::input_adapter(s)).accept());
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
                    CHECK(json::parser(nlohmann::detail::input_adapter(s)).accept() == false);
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
                std::string const s = "\"\\u";

                // create a string with the iterated character at each position
                const auto s1 = s + "000" + std::string(1, static_cast<char>(c)) + "\"";
                const auto s2 = s + "00" + std::string(1, static_cast<char>(c)) + "0\"";
                const auto s3 = s + "0" + std::string(1, static_cast<char>(c)) + "00\"";
                const auto s4 = s + std::string(1, static_cast<char>(c)) + "000\"";

                if (valid(c))
                {
                    CAPTURE(s1)
                    CHECK(json::parser(nlohmann::detail::input_adapter(s1)).accept());
                    CAPTURE(s2)
                    CHECK(json::parser(nlohmann::detail::input_adapter(s2)).accept());
                    CAPTURE(s3)
                    CHECK(json::parser(nlohmann::detail::input_adapter(s3)).accept());
                    CAPTURE(s4)
                    CHECK(json::parser(nlohmann::detail::input_adapter(s4)).accept());
                }
                else
                {
                    CAPTURE(s1)
                    CHECK(json::parser(nlohmann::detail::input_adapter(s1)).accept() == false);

                    CAPTURE(s2)
                    CHECK(json::parser(nlohmann::detail::input_adapter(s2)).accept() == false);

                    CAPTURE(s3)
                    CHECK(json::parser(nlohmann::detail::input_adapter(s3)).accept() == false);

                    CAPTURE(s4)
                    CHECK(json::parser(nlohmann::detail::input_adapter(s4)).accept() == false);
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
        // test case to make sure no comma precedes the first key
        CHECK_THROWS_WITH_AS(parser_helper("{,\"key\": false}"), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing object key - unexpected ','; expected string literal", json::parse_error&);
        // test case to make sure an object is properly closed
        CHECK_THROWS_WITH_AS(parser_helper("[{\"key\": false true]"), "[json.exception.parse_error.101] parse error at line 1, column 19: syntax error while parsing object - unexpected true literal; expected '}'", json::parse_error&);

        // test case to make sure the callback is properly evaluated after reading a key
        {
            json::parser_callback_t const cb = [](int /*unused*/, json::parse_event_t event, json& /*unused*/) noexcept
            {
                return event != json::parse_event_t::key;
            };

            json x = json::parse("{\"key\": false}", cb);
            CHECK(x == json::object());
        }
    }

    SECTION("callback function")
    {
        const auto* s_object = R"(
            {
                "foo": 2,
                "bar": {
                    "baz": 1
                }
            }
        )";

        const auto* s_array = R"(
            [1,2,[3,4,5],4,5]
        )";

        const auto* structured_array = R"(
            [
                1,
                {
                     "foo": "bar"
                },
                {
                     "qux": "baz"
                }
            ]
        )";

        SECTION("filter nothing")
        {
            json j_object = json::parse(s_object, [](int /*unused*/, json::parse_event_t /*unused*/, const json& /*unused*/) noexcept
            {
                return true;
            });

            CHECK (j_object == json({{"foo", 2}, {"bar", {{"baz", 1}}}}));

            json j_array = json::parse(s_array, [](int /*unused*/, json::parse_event_t /*unused*/, const json& /*unused*/) noexcept
            {
                return true;
            });

            CHECK (j_array == json({1, 2, {3, 4, 5}, 4, 5}));
        }

        SECTION("filter everything")
        {
            json const j_object = json::parse(s_object, [](int /*unused*/, json::parse_event_t /*unused*/, const json& /*unused*/) noexcept
            {
                return false;
            });

            // the top-level object will be discarded, leaving a null
            CHECK (j_object.is_null());

            json const j_array = json::parse(s_array, [](int /*unused*/, json::parse_event_t /*unused*/, const json& /*unused*/) noexcept
            {
                return false;
            });

            // the top-level array will be discarded, leaving a null
            CHECK (j_array.is_null());
        }

        SECTION("filter specific element")
        {
            json j_object = json::parse(s_object, [](int /*unused*/, json::parse_event_t event, const json & j) noexcept
            {
                // filter all number(2) elements
                return event != json::parse_event_t::value || j != json(2);
            });

            CHECK (j_object == json({{"bar", {{"baz", 1}}}}));

            json j_array = json::parse(s_array, [](int /*unused*/, json::parse_event_t event, const json & j) noexcept
            {
                return event != json::parse_event_t::value || j != json(2);
            });

            CHECK (j_array == json({1, {3, 4, 5}, 4, 5}));
        }

        SECTION("filter object in array")
        {
            json j_filtered1 = json::parse(structured_array, [](int /*unused*/, json::parse_event_t e, const json & parsed)
            {
                return !(e == json::parse_event_t::object_end && parsed.contains("foo"));
            });

            // the specified object will be discarded, and removed.
            CHECK (j_filtered1.size() == 2);
            CHECK (j_filtered1 == json({1, {{"qux", "baz"}}}));

            json j_filtered2 = json::parse(structured_array, [](int /*unused*/, json::parse_event_t e, const json& /*parsed*/) noexcept
            {
                return e != json::parse_event_t::object_end;
            });

            // removed all objects in array.
            CHECK (j_filtered2.size() == 1);
            CHECK (j_filtered2 == json({1}));
        }

        SECTION("filter specific events")
        {
            SECTION("first closing event")
            {
                {
                    json j_object = json::parse(s_object, [](int /*unused*/, json::parse_event_t e, const json& /*unused*/) noexcept
                    {
                        static bool first = true;
                        if (e == json::parse_event_t::object_end && first)
                        {
                            first = false;
                            return false;
                        }

                        return true;
                    });

                    // the first completed object will be discarded
                    CHECK (j_object == json({{"foo", 2}}));
                }

                {
                    json j_array = json::parse(s_array, [](int /*unused*/, json::parse_event_t e, const json& /*unused*/) noexcept
                    {
                        static bool first = true;
                        if (e == json::parse_event_t::array_end && first)
                        {
                            first = false;
                            return false;
                        }

                        return true;
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

            json j_empty_object = json::parse("{}", [](int /*unused*/, json::parse_event_t e, const json& /*unused*/) noexcept
            {
                return e != json::parse_event_t::object_end;
            });
            CHECK(j_empty_object == json());

            json j_empty_array = json::parse("[]", [](int /*unused*/, json::parse_event_t e, const json& /*unused*/) noexcept
            {
                return e != json::parse_event_t::array_end;
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
            uint8_t v[] = {'t', 'r', 'u', 'e'}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
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
            std::initializer_list<uint8_t> const v = {'t', 'r', 'u', 'e'};
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
            json::parser_callback_t const cb = [](int /*unused*/, json::parse_event_t /*unused*/, json& /*unused*/) noexcept
            {
                return true;
            };

            CHECK(json::parse("{\"foo\": true:", cb, false).is_discarded());

            json _;
            CHECK_THROWS_WITH_AS(_ = json::parse("{\"foo\": true:", cb), "[json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing object - unexpected ':'; expected '}'", json::parse_error&);

            CHECK_THROWS_WITH_AS(_ = json::parse("1.18973e+4932", cb), "[json.exception.out_of_range.406] number overflow parsing '1.18973e+4932'", json::out_of_range&);
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

    SECTION("error messages for comments")
    {
        json _;
        CHECK_THROWS_WITH_AS(_ = json::parse("/a", nullptr, true, true), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid comment; expecting '/' or '*' after '/'; last read: '/a'", json::parse_error);
        CHECK_THROWS_WITH_AS(_ = json::parse("/*", nullptr, true, true), "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid comment; missing closing '*/'; last read: '/*<U+0000>'", json::parse_error);
    }

    // Macro for all test cases for start_pos and end_pos
#define SETUP_TESTCASES() \
    SECTION("with callback") \
    { \
        SECTION("filter nothing") \
        { \
            json::parser_callback_t const cb = [](int /*unused*/, json::parse_event_t /*unused*/, json& /*unused*/) noexcept \
            { \
                return true; \
            }; \
            validate_start_end_pos_for_nested_obj_helper(nested_type_json_str, root_type_json_str, expected, cb); \
        } \
        SECTION("filter element") \
        { \
            json::parser_callback_t const cb = [](int /*unused*/, json::parse_event_t event, json& j) noexcept \
            { \
                return (event != json::parse_event_t::key && event != json::parse_event_t::value) || j != json("a"); \
            }; \
            validate_start_end_pos_for_nested_obj_helper(nested_type_json_str, root_type_json_str, filteredExpected, cb); \
        } \
    } \
    SECTION("without callback") \
    { \
        validate_start_end_pos_for_nested_obj_helper(nested_type_json_str, root_type_json_str, expected); \
    }

    SECTION("retrieve start position and end position")
    {
        SECTION("for object")
        {
            // Create an object with spaces to test the start and end positions. Spaces will not be included in the
            // JSON object, however, the start and end positions should include the spaces from the input JSON string.
            const std::string nested_type_json_str =  R"({    "a":       1,"b"      : "test1"})";
            const std::string root_type_json_str =  R"({    "nested": )" + nested_type_json_str + R"(, "anotherValue": "test2"})";
            auto expected = json({{"nested", {{"a", 1}, {"b", "test1"}}}, {"anotherValue", "test2"}});
            auto filteredExpected = expected;
            filteredExpected["nested"].erase("a");

            SETUP_TESTCASES()
        }

        SECTION("for array")
        {
            const std::string nested_type_json_str =  R"(["a", "test", 45])";
            const std::string root_type_json_str =  R"({   "nested": )" + nested_type_json_str + R"(, "anotherValue": "test" })";
            auto expected = json({{"nested", {"a", "test", 45}}, {"anotherValue", "test"}});
            auto filteredExpected = expected;
            filteredExpected["nested"] = json({"test", 45});
            SETUP_TESTCASES()
        }

        SECTION("for array with objects")
        {
            const std::string nested_type_json_str =  R"([{"a": 1, "b": "test"}, {"c": 2, "d": "test2"}])";
            const std::string root_type_json_str =  R"({   "nested": )" + nested_type_json_str + R"(, "anotherValue": "test" })";
            auto expected = json({{"nested", {{{"a", 1}, {"b", "test"}}, {{"c", 2}, {"d", "test2"}}}}, {"anotherValue", "test"}});
            auto filteredExpected = expected;
            filteredExpected["nested"][0].erase("a");
            SETUP_TESTCASES()

            auto j = json::parse(root_type_json_str);
            auto nested_array = j["nested"];
            const auto& nested_obj = nested_array[0];
            CHECK(nested_type_json_str.substr(1, 21) == root_type_json_str.substr(nested_obj.start_pos(), nested_obj.end_pos() - nested_obj.start_pos()));
            CHECK(nested_type_json_str.substr(24, 22) == root_type_json_str.substr(nested_array[1].start_pos(), nested_array[1].end_pos() - nested_array[1].start_pos()));
        }

        SECTION("for two levels of nesting objects")
        {
            const std::string nested_type_json_str =  R"({"nested2": {"b": "test"}})";
            const std::string root_type_json_str =  R"({   "a": 2, "nested": )" + nested_type_json_str + R"(, "anotherValue": "test" })";
            auto expected = json({{"a", 2}, {"nested", {{"nested2", {{"b", "test"}}}}}, {"anotherValue", "test"}});
            auto filteredExpected = expected;
            filteredExpected.erase("a");
            SETUP_TESTCASES()

            auto j = json::parse(root_type_json_str);
            auto nested_obj = j["nested"]["nested2"];
            CHECK(nested_type_json_str.substr(12, 13) == root_type_json_str.substr(nested_obj.start_pos(), nested_obj.end_pos() - nested_obj.start_pos()));
        }

        SECTION("for simple types")
        {
            SECTION("no nested")
            {
                SECTION("with callback")
                {
                    json::parser_callback_t const cb = [](int /*unused*/, json::parse_event_t /*unused*/, json& /*unused*/) noexcept
                    {
                        return true;
                    };

                    // 1. string type
                    std::string json_str =  R"("test")";
                    auto j = json::parse(json_str, cb);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, "test");

                    // 2. number type
                    json_str =  R"(1)";
                    j = json::parse(json_str, cb);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, 1);

                    // 3. boolean type
                    json_str =  R"(true)";
                    j = json::parse(json_str, cb);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, true);

                    // 4. null type
                    json_str =  R"(null)";
                    j = json::parse(json_str, cb);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, nullptr);
                }

                SECTION("without callback")
                {
                    // 1. string type
                    std::string json_str =  R"("test")";
                    auto j = json::parse(json_str);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, "test");

                    // 2. number type
                    json_str =  R"(1)";
                    j = json::parse(json_str);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, 1);

                    json_str = R"(1.001239923)";
                    j = json::parse(json_str);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, 1.001239923);

                    json_str = R"(1.123812389000000)";
                    j = json::parse(json_str);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, 1.123812389);

                    // 3. boolean type
                    json_str =  R"(true)";
                    j = json::parse(json_str);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, true);

                    json_str =  R"(false)";
                    j = json::parse(json_str);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, false);

                    // 4. null type
                    json_str =  R"(null)";
                    j = json::parse(json_str);
                    validate_generated_json_and_start_end_pos_helper(json_str, j, nullptr);
                }
            }

            SECTION("string type")
            {
                const std::string nested_type_json_str =  R"("test")";
                const std::string root_type_json_str =  R"({ "a": 1,   "nested": )" + nested_type_json_str + R"(, "anotherValue": "test" })";
                auto expected = json({{"nested", "test"}, {"anotherValue", "test"}, {"a", 1}});
                auto filteredExpected = expected;
                filteredExpected.erase("a");
                SETUP_TESTCASES()
            }

            SECTION("number type")
            {
                const std::string nested_type_json_str =  R"(2)";
                const std::string root_type_json_str =  R"({ "a": 1,   "nested": )" + nested_type_json_str + R"(, "anotherValue": "test" })";
                auto expected = json({{"nested", 2}, {"anotherValue", "test"}, {"a", 1}});
                auto filteredExpected = expected;
                filteredExpected.erase("a");
                SETUP_TESTCASES()
            }

            SECTION("boolean type")
            {
                const std::string nested_type_json_str =  R"(true)";
                const std::string root_type_json_str =  R"({ "a": 1,   "nested": )" + nested_type_json_str + R"(, "anotherValue": "test" })";
                auto expected = json({{"nested", true}, {"anotherValue", "test"}, {"a", 1}});
                auto filteredExpected = expected;
                filteredExpected.erase("a");
                SETUP_TESTCASES()
            }

            SECTION("null type")
            {
                const std::string nested_type_json_str =  R"(null)";
                const std::string root_type_json_str =  R"({ "a": 1,   "nested": )" + nested_type_json_str + R"(, "anotherValue": "test" })";
                auto expected = json({{"nested", nullptr}, {"anotherValue", "test"}, {"a", 1}});
                auto filteredExpected = expected;
                filteredExpected.erase("a");
                SETUP_TESTCASES()
            }
        }
        SECTION("with leading whitespace and newlines around root JSON")
        {
            const std::string initial_whitespace = R"(
                
            )";
            const std::string nested_type_json_str = R"({
                "a": 1,
                "nested": {
                    "b": "test"
                },
                "anotherValue": "test"
            })";
            const std::string end_whitespace = R"(
                
            )";
            const std::string root_type_json_str = initial_whitespace + nested_type_json_str + end_whitespace;

            auto expected = json({{"a", 1}, {"nested", {{"b", "test"}}}, {"anotherValue", "test"}});

            auto j = json::parse(root_type_json_str);

            // 2. Check if the generated JSON is as expected
            CHECK(j == expected);

            // 3. Check if the start and end positions do not include the surrounding whitespace
            CHECK(j.start_pos() == initial_whitespace.size());
            CHECK(j.end_pos() == root_type_json_str.size() - end_whitespace.size());
        }
    }
}
