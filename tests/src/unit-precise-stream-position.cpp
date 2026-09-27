//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// This file tests the opt-in JSON_PRECISE_STREAM_POSITION, so it defines the
// macro itself rather than relying on a -D flag, and runs in every build. The
// default behavior is pinned in unit-deserialization.cpp.
#ifdef JSON_PRECISE_STREAM_POSITION
    #undef JSON_PRECISE_STREAM_POSITION
#endif

#define JSON_PRECISE_STREAM_POSITION 1

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <cstddef>
#include <sstream>
#include <streambuf>
#include <string>
#include <utility>
#include <vector>

#define STRINGIZE_EX(x) #x
#define STRINGIZE(x) STRINGIZE_EX(x)

namespace
{
// A streambuf that keeps no get area at all and refuses every putback: with an
// empty get area, sungetc() always ends up in pbackfail(). Used to check that
// the character terminating a number is left in the input without relying on
// the streambuf being able to put a consumed character back.
class no_putback_streambuf : public std::streambuf
{
  public:
    explicit no_putback_streambuf(std::string s) : m_data(std::move(s)) {}

  protected:
    // peek at the next character without consuming it
    int_type underflow() override
    {
        if (m_pos >= m_data.size())
        {
            return traits_type::eof();
        }
        return traits_type::to_int_type(m_data[m_pos]);
    }

    // consume the next character
    int_type uflow() override
    {
        if (m_pos >= m_data.size())
        {
            return traits_type::eof();
        }
        return traits_type::to_int_type(m_data[m_pos++]);
    }

    int_type pbackfail(int_type /*c*/) override
    {
        return traits_type::eof();
    }

  private:
    std::string m_data;
    std::size_t m_pos = 0;
};

// read the characters that are left in a stream
std::string remaining(std::istream& is)
{
    std::string result;
    char c = 0;
    while (is.get(c))
    {
        result += c;
    }
    return result;
}
}  // namespace

TEST_CASE("JSON_PRECISE_STREAM_POSITION")
{
    SECTION("the macro is part of the ABI tag")
    {
        const std::string ns = STRINGIZE(NLOHMANN_JSON_NAMESPACE);
        // other tags may come before it, e.g. json_abi_diag_psp
        CHECK(ns.find("_psp") != std::string::npos);
    }

    SECTION("a number does not consume the character that terminates it")
    {
        // a number is only terminated by the character following it; that
        // character must be given back so the stream is positioned right
        // after the value
        const std::vector<std::pair<std::string, std::string>> tests =
        {
            {"1true", "true"},
            {"1[2]", "[2]"},
            {"1{}", "{}"},
            {R"(1"a")", R"("a")"},
            {"1 true", " true"},
            {"12,", ","},
            {"-0.5e3x", "x"},
            {"1null", "null"}
        };

        for (const auto& test : tests)
        {
            CAPTURE(test.first);
            std::istringstream ss(test.first);
            json j;
            ss >> j;
            CHECK(j == json::parse(test.first.substr(0, test.first.size() - test.second.size())));
            CHECK(remaining(ss) == test.second);
        }
    }

    SECTION("values that are self-delimiting are unaffected")
    {
        const std::vector<std::pair<std::string, std::string>> tests =
        {
            {"truefalse", "false"},
            {"[1][2]", "[2]"},
            {R"({"a":1}{"b":2})", R"({"b":2})"},
            {R"("a""b")", R"("b")"},
            {"null null", " null"}
        };

        for (const auto& test : tests)
        {
            CAPTURE(test.first);
            std::istringstream ss(test.first);
            json j;
            ss >> j;
            CHECK(remaining(ss) == test.second);
        }
    }

    SECTION("a number at the end of the input leaves nothing behind")
    {
        for (const std::string s :
                {"1", "12", "-3.5e2", " 7 "
                })
        {
            CAPTURE(s);
            std::istringstream ss(s);
            json j;
            ss >> j;
            CHECK(remaining(ss).find_first_not_of(" \t\n\r") == std::string::npos);
        }
    }

    SECTION("repeated extraction of concatenated values")
    {
        std::istringstream ss(R"(1true[2]3"x"{"a":4}5)");
        const std::vector<json> expected =
        {
            json(1), json(true), json::parse("[2]"), json(3),
            json("x"), json::parse(R"({"a":4})"), json(5)
        };

        for (const auto& e : expected)
        {
            json j;
            ss >> j;
            CHECK(j == e);
        }
    }

    SECTION("differences to the default behavior")
    {
        // both of these work by accident without the macro, because the
        // character after a number is swallowed; see unit-deserialization.cpp

        SECTION("a separator after a number is not skipped")
        {
            std::istringstream ss("1,2");
            json j;
            ss >> j;
            CHECK(j == 1);
            CHECK_THROWS_AS(ss >> j, json::parse_error&);
        }

        SECTION("std::getline after a number sees the line break")
        {
            std::istringstream ss("42\nfoo");
            json j;
            std::string line;
            ss >> j;
            std::getline(ss, line);
            CHECK(j == 42);
            CHECK(line.empty());
            std::getline(ss, line);
            CHECK(line == "foo");
        }
    }

    SECTION("sax_parse with strict == false")
    {
        std::istringstream ss("1true");
        json j;
        nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::input_stream_adapter> sdp(j, true);
        CHECK(json::sax_parse(ss, &sdp, nlohmann::detail::input_format_t::json, false));
        CHECK(j == 1);
        CHECK(remaining(ss) == "true");
    }

    SECTION("strict parsing still rejects trailing data")
    {
        std::istringstream ss("1true");
        json _;
        CHECK_THROWS_WITH_AS(_ = json::parse(ss),
                             "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - unexpected true literal; expected end of input", json::parse_error&);

        std::istringstream ss2("1true");
        CHECK_FALSE(json::accept(ss2));
    }

    SECTION("a streambuf that cannot put back is not needed")
    {
        // the terminating character is never consumed, so no putback
        // position is required
        no_putback_streambuf buf("1true");
        std::istream is(&buf);
        json j;
        is >> j;
        CHECK(j == json(1));
        CHECK(remaining(is) == "true");
    }
}
