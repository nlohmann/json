/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.9.1
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
using json = nlohmann::json;

/////////////////////////////////////////////////////////////////////
// for #2824
/////////////////////////////////////////////////////////////////////

class sax_no_exception : public nlohmann::detail::json_sax_dom_parser<json>
{
  public:
    explicit sax_no_exception(json& j) : nlohmann::detail::json_sax_dom_parser<json>(j, false) {}

    static bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const json::exception& ex)
    {
        error_string = new std::string(ex.what()); // NOLINT(cppcoreguidelines-owning-memory)
        return false;
    }

    static std::string* error_string;
};

std::string* sax_no_exception::error_string = nullptr;

//
#include <cstddef> // size_t
#include <exception> // exception
#include <stdexcept> // runtime_error
#include <string> // to_string
#include <vector> // vector

//
namespace nlohmann
{
namespace detail2
{

struct position_t
{
    std::size_t chars_read_total = 0;
    std::size_t chars_read_current_line = 0;
    std::size_t lines_read = 0;

    constexpr operator size_t() const
    {
        return chars_read_total;
    }
};

class exception : public std::exception
{
  public:
    const char* what() const noexcept override
    {
        return m.what();
    }

    const int id; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

  protected:
    exception(int id_, const char* what_arg) : id(id_), m(what_arg) {}

    static std::string name(const std::string& ename, int id_)
    {
        return "[json.exception." + ename + "." + std::to_string(id_) + "] ";
    }

  private:
    std::runtime_error m;
};

class parse_error : public exception
{
  public:
    static parse_error create(int id_, const position_t& pos, const std::string& what_arg)
    {
        std::string w = exception::name("parse_error", id_) + "parse error" +
                        position_string(pos) + ": " + what_arg;
        return parse_error(id_, pos.chars_read_total, w.c_str());
    }

    const std::size_t byte;

  private:
    parse_error(int id_, std::size_t byte_, const char* what_arg)
        : exception(id_, what_arg), byte(byte_) {}

    static std::string position_string(const position_t& pos)
    {
        return " at line " + std::to_string(pos.lines_read + 1) +
               ", column " + std::to_string(pos.chars_read_current_line);
    }
};

}  // namespace detail2
}  // namespace nlohmann
//

TEST_CASE("Tests with disabled exceptions")
{
    SECTION("issue #2824 - encoding of json::exception::what()")
    {
        json j;
        sax_no_exception sax(j);

        CHECK (!json::sax_parse("xyz", &sax));
        //CHECK(*sax_no_exception::error_string == "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - invalid literal; last read: 'x'");
        delete sax_no_exception::error_string; // NOLINT(cppcoreguidelines-owning-memory)
    }

    SECTION("test")
    {
        nlohmann::detail2::position_t pos;
        pos.chars_read_total = 100;
        pos.chars_read_current_line = 50;
        pos.lines_read = 1;

        auto error = nlohmann::detail2::parse_error::create(100, pos, "foo");
        CHECK(std::string(error.what()) == "[json.exception.parse_error.100] parse error at line 2, column 50: foo");
    }
}
