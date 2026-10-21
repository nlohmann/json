//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// the library undefines its configuration macros at the end of the header
#if defined(JSON_DISABLE_STREAM_BULK_SCAN) && JSON_DISABLE_STREAM_BULK_SCAN
    #define TEST_STREAM_BULK_SCAN 0
#else
    #define TEST_STREAM_BULK_SCAN 1
#endif

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <istream>
#include <random>
#include <sstream>
#include <streambuf>
#include <string>
#include <utility>
#include <vector>

// The lexer scans the characters in the get area of a std::istream's
// streambuf directly instead of reading them one at a time. These tests pin
// that this is not observable: for any get area size - including a streambuf
// without a get area, which still takes the character-at-a-time path - the
// parsed values, the exception messages (including the "last read" token),
// the stream state, and the characters left in the stream are the same. See
// unit-stream-bulk-scan-disabled.cpp for JSON_DISABLE_STREAM_BULK_SCAN.

namespace
{
// A streambuf that serves its input in get areas of a fixed size, so that
// tokens, numbers, UTF-8 sequences, and indentation cross the end of the get
// area at every possible offset. With a size of 0, it keeps no get area at all
// and serves every character from underflow()/uflow().
class chunked_streambuf : public std::streambuf
{
  public:
    chunked_streambuf(std::string s, std::size_t chunk_size)
        : m_data(std::move(s)), m_chunk_size(chunk_size)
    {}

  protected:
    int_type underflow() override
    {
        if (m_chunk_size == 0)
        {
            return m_pos < m_data.size() ? traits_type::to_int_type(m_data[m_pos]) : traits_type::eof();
        }
        if (gptr() < egptr())
        {
            return traits_type::to_int_type(*gptr());
        }
        // the previous get area has been consumed
        m_pos += static_cast<std::size_t>(egptr() - eback());
        if (m_pos >= m_data.size())
        {
            setg(nullptr, nullptr, nullptr);
            return traits_type::eof();
        }
        char* const begin = &m_data[m_pos];
        setg(begin, begin, begin + (std::min)(m_chunk_size, m_data.size() - m_pos));
        return traits_type::to_int_type(*gptr());
    }

    int_type uflow() override
    {
        if (m_chunk_size == 0)
        {
            return m_pos < m_data.size() ? traits_type::to_int_type(m_data[m_pos++]) : traits_type::eof();
        }
        return std::streambuf::uflow();
    }

  private:
    std::string m_data;
    std::size_t m_pos = 0;
    std::size_t m_chunk_size;
};

// how a test reads from the stream
enum class read_mode
{
    extract,         // up to four times operator>>, as for concatenated values
    parse,           // json::parse(stream)
    parse_lenient,   // json::parse(stream) with comments
};

// Read @a input from a chunked_streambuf and describe everything observable:
// the values or the exception, the stream state after each value, and the
// characters left in the stream.
std::string observe(const std::string& input, std::size_t chunk_size, read_mode mode)
{
    chunked_streambuf buf(input, chunk_size);
    std::istream is(&buf);
    std::string result;
    for (int i = 0; i < 4; ++i)
    {
        json j;
        try
        {
            if (mode == read_mode::extract)
            {
                is >> j;
            }
            else
            {
                j = json::parse(is, nullptr, true, mode == read_mode::parse_lenient);
            }
            result += "value " + j.dump() + "; state " + std::to_string(static_cast<unsigned int>(is.rdstate())) + "\n";
        }
        catch (const json::exception& e)
        {
            result += std::string("exception ") + e.what() + "\n";
            break;
        }
        if (mode != read_mode::extract)
        {
            break;
        }
        is.clear();
    }

    is.clear();
    result += "remaining ";
    char c = 0;
    while (is.get(c))
    {
        result += c;
    }
    return result;
}

// get area sizes that put every boundary everywhere in short inputs, plus one
// that holds most inputs completely
std::vector<std::size_t> chunk_sizes()
{
    return {1, 2, 3, 4, 5, 7, 8, 9, 13, 16, 64, 4096};
}

// valid and invalid inputs covering every token type and every bulk path:
// strings (plain runs, escapes, UTF-8), numbers (all grammar parts, too large
// for an integer), and indentation
std::vector<std::string> corpus()
{
    return
    {
        // numbers, terminated in every way
        "0", "-0", "123", "-123", "1.5", "-1.5e+10", "2E-3", "123456789012345678901234567890",
        "18446744073709551615", "18446744073709551616", "-9223372036854775809",
        "123 456", "123,456", "123]", "1true", "42\nfoo", "1.25e3}", "7\t8\r9",
        // malformed numbers
        "1.", "-", "1e", "1e+", "01", "-a", "1.x", "1ee5",
        // strings
        R"("")", R"("abc")", R"("a long string with a run of ordinary characters to scan in bulk")",
        R"("escapes \" \\ \/ \b \f \n \r \t é 😀")",
        "\"UTF-8: \xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80 done\"",
        // malformed strings
        R"("unterminated)", "\"control\x01character\"", "\"ill-formed \xc3\x28 UTF-8\"", R"("bad \x escape")",
        R"("\ud800 lone surrogate")",
        // literals
        "true", "false", "null", "tru", "nul", "falsey",
        // structures
        "[]", "{}", "[1,2,3]", R"({"a":1,"b":[true,false,null],"c":{"d":"e"}})", "[1,]", R"({"a" 1})", "[[[[[]]]]]",
        // pretty-printed
        "{\n    \"key\": [\n        1,\n        -2.5,\n        \"three\"\n    ]\n}",
        "[\n                                \"deep\"\n                                ]",
        "{\n    \"a\": 1,\n    \"b\": 2x\n}",
        // concatenated values and whitespace
        "1 2 3", R"("a""b")", "[1][2]", "{}{}", " \n\t 42 \n\t ", "",
        // comments (only accepted by parse_lenient)
        "/* comment */ 1", "// comment\n[1, /* c */ 2]",
        // byte order mark
        "\xef\xbb\xbf[1]",
    };
}
}  // namespace

TEST_CASE("parsing from a std::istream scans the get area in bulk")
{
#if !defined(JSON_NOEXCEPTION)
    SECTION("results do not depend on the get area")
    {
        const std::vector<read_mode> read_modes = {read_mode::extract, read_mode::parse, read_mode::parse_lenient};
        for (const auto& input : corpus())
        {
            for (const read_mode mode : read_modes)
            {
                // no get area: the character-at-a-time path
                const std::string expected = observe(input, 0, mode);
                for (const std::size_t chunk_size : chunk_sizes())
                {
                    CAPTURE(input)
                    CAPTURE(chunk_size)
                    CAPTURE(static_cast<int>(mode))
                    CHECK(observe(input, chunk_size, mode) == expected);
                }
            }
        }
    }

#endif // !defined(JSON_NOEXCEPTION)

    SECTION("values are the same as when parsing from a string")
    {
        const std::string input = R"({"name": "nlohmann::json", "numbers": [1, -2, 3.5, 4e10, 18446744073709551615],)"
                                  "\n    \"text\": \"caf\xc3\xa9 \\u00e9 \\\"quoted\\\"\", \"nested\": [[{}], [[]]], \"flags\": [true, false, null]}";
        const json expected = json::parse(input);
        for (const std::size_t chunk_size : chunk_sizes())
        {
            CAPTURE(chunk_size)
            chunked_streambuf buf(input, chunk_size);
            std::istream is(&buf);
            CHECK(json::parse(is) == expected);
        }

        std::istringstream ss(input);
        CHECK(json::parse(ss) == expected);
    }

#if !defined(JSON_NOEXCEPTION)
    SECTION("a token that spans several get areas is reported completely")
    {
        // the error is found after the string has crossed many get areas; the
        // token string holds everything since the start of the last token
        const std::string input = R"(["this string is longer than every get area", tru])";
        for (const std::size_t chunk_size : chunk_sizes())
        {
            CAPTURE(chunk_size)
            chunked_streambuf buf(input, chunk_size);
            std::istream is(&buf);
            json j;
            CHECK_THROWS_WITH_AS(is >> j,
                                 "[json.exception.parse_error.101] parse error at line 1, column 50: syntax error while parsing value - invalid literal; last read: '\"this string is longer than every get area\", tru]'",
                                 json::parse_error&);
        }

        const std::string unterminated = R"("this string is longer than every get area)";
        for (const std::size_t chunk_size : chunk_sizes())
        {
            CAPTURE(chunk_size)
            chunked_streambuf buf(unterminated, chunk_size);
            std::istream is(&buf);
            json j;
            CHECK_THROWS_WITH_AS(is >> j,
                                 "[json.exception.parse_error.101] parse error at line 1, column 43: syntax error while parsing value - invalid string: missing closing quote; last read: '\"this string is longer than every get area'",
                                 json::parse_error&);
        }
    }

    SECTION("an error before the first token reports everything read")
    {
        chunked_streambuf buf("  \n  x", 2);
        std::istream is(&buf);
        json j;
        CHECK_THROWS_WITH_AS(is >> j,
                             "[json.exception.parse_error.101] parse error at line 2, column 3: syntax error while parsing value - invalid literal; last read: '  <U+000A>  x'",
                             json::parse_error&);
    }

    SECTION("lines and columns are counted across get areas")
    {
        const std::string input = "[\n    1,\n    \"two\",\n    3.0,\n    x\n]";
        for (const std::size_t chunk_size : chunk_sizes())
        {
            CAPTURE(chunk_size)
            chunked_streambuf buf(input, chunk_size);
            std::istream is(&buf);
            json j;
            CHECK_THROWS_WITH_AS(is >> j,
                                 "[json.exception.parse_error.101] parse error at line 5, column 5: syntax error while parsing value - invalid literal; last read: '3.0,<U+000A>    x'",
                                 json::parse_error&);
        }
    }

#endif // !defined(JSON_NOEXCEPTION)

    SECTION("many values from one stream")
    {
        std::string input;
        for (int i = 0; i < 200; ++i)
        {
            input += R"({"id":)" + std::to_string(i) + R"(,"name":"user)" + std::to_string(i) + R"(","score":)" + std::to_string(i) + ".5}\n";
            input += std::to_string(i * 7919) + "\n";
        }

        for (const std::size_t chunk_size : chunk_sizes())
        {
            CAPTURE(chunk_size)
            chunked_streambuf buf(input, chunk_size);
            std::istream is(&buf);
            json j;
            int count = 0;
            while (!(is >> std::ws).eof())
            {
                is >> j;
                if (count % 2 == 0)
                {
                    CHECK(j["id"] == count / 2);
                }
                else
                {
                    CHECK(j == (count / 2) * 7919);
                }
                ++count;
            }
            CHECK(count == 400);
        }
    }

    SECTION("the stream can be used after parsing")
    {
        for (const std::size_t chunk_size : chunk_sizes())
        {
            CAPTURE(chunk_size)
            chunked_streambuf buf(R"({"a": "some text"} trailing words 42)", chunk_size);
            std::istream is(&buf);
            json j;
            is >> j;
            CHECK(j == json({{"a", "some text"}}));

            std::string word;
            int number = 0;
            is >> word;
            CHECK(word == "trailing");
            is >> word >> number;
            CHECK(word == "words");
            CHECK(number == 42);
        }
    }

    SECTION("std::stringstream and std::ifstream")
    {
        const std::string input = R"([1, 2.5, "three", {"four": [true, null]}] 5)";

        std::stringstream ss(input);
        json j1;
        json j2;
        ss >> j1 >> j2;
        CHECK(j1 == json::parse(R"([1, 2.5, "three", {"four": [true, null]}])"));
        CHECK(j2 == 5);
        CHECK(ss.eof());

        // a file name of its own for every run: the test runs for several C++
        // standards and configurations at the same time, in the same directory
        std::random_device rd;
        const std::string temp_name = "unit-stream-bulk-scan-" + std::to_string(rd()) + ".tmp";
        const char* const filename = temp_name.c_str();
        {
            std::ofstream file(filename);
            file << input;
        }
        {
            std::ifstream file(filename);
            json k1;
            json k2;
            file >> k1 >> k2;
            CHECK(k1 == j1);
            CHECK(k2 == j2);
        }
        static_cast<void>(std::remove(filename));
    }

    SECTION("binary formats read from a stream")
    {
        const json j = {{"string", std::string(300, 'x')}, {"array", {1, 2, 3}}, {"number", 1.5}};
        const std::vector<std::uint8_t> cbor = json::to_cbor(j);
        const std::string bytes(reinterpret_cast<const char*>(cbor.data()), cbor.size());
        for (const std::size_t chunk_size : chunk_sizes())
        {
            CAPTURE(chunk_size)
            chunked_streambuf buf(bytes, chunk_size);
            std::istream is(&buf);
            CHECK(json::from_cbor(is) == j);
        }
    }

#if TEST_STREAM_BULK_SCAN
    SECTION("the adapter keeps no token unless the lexer starts one")
    {
        // the binary readers read through the same adapter, but never start a
        // token; refilling the get area must then not collect the input
        chunked_streambuf buf(std::string(1000, 'x'), 7);
        std::istream is(&buf);
        nlohmann::detail::input_stream_adapter ia(is);
        for (int i = 0; i < 1000; ++i)
        {
            CHECK(ia.get_character() == 'x');
        }

        std::vector<char> token;
        ia.copy_token(token, false);
        CHECK(token.empty());
    }
#endif

    SECTION("SAX parsing from a stream")
    {
        const std::string input = R"({"a": [1, "two", 3.5]} rest)";
        for (const std::size_t chunk_size : chunk_sizes())
        {
            CAPTURE(chunk_size)
            chunked_streambuf buf(input, chunk_size);
            std::istream is(&buf);
            json j;
            nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type> sax(j);
            CHECK(json::sax_parse(is, &sax, json::input_format_t::json, false));
            CHECK(j == json::parse(R"({"a": [1, "two", 3.5]})"));
        }
    }
}
