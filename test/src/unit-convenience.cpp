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

#define private public
#include "json.hpp"
using nlohmann::json;

TEST_CASE("convenience functions")
{
    SECTION("type name as string")
    {
        CHECK(json(json::value_t::null).type_name() == "null");
        CHECK(json(json::value_t::object).type_name() == "object");
        CHECK(json(json::value_t::array).type_name() == "array");
        CHECK(json(json::value_t::number_integer).type_name() == "number");
        CHECK(json(json::value_t::number_unsigned).type_name() == "number");
        CHECK(json(json::value_t::number_float).type_name() == "number");
        CHECK(json(json::value_t::boolean).type_name() == "boolean");
        CHECK(json(json::value_t::string).type_name() == "string");
        CHECK(json(json::value_t::discarded).type_name() == "discarded");
    }

    SECTION("string escape")
    {
        CHECK(json::escape_string("\"") == "\\\"");
        CHECK(json::escape_string("\\") == "\\\\");
        CHECK(json::escape_string("\b") == "\\b");
        CHECK(json::escape_string("\f") == "\\f");
        CHECK(json::escape_string("\n") == "\\n");
        CHECK(json::escape_string("\r") == "\\r");
        CHECK(json::escape_string("\t") == "\\t");

        CHECK(json::escape_string("\x01") == "\\u0001");
        CHECK(json::escape_string("\x02") == "\\u0002");
        CHECK(json::escape_string("\x03") == "\\u0003");
        CHECK(json::escape_string("\x04") == "\\u0004");
        CHECK(json::escape_string("\x05") == "\\u0005");
        CHECK(json::escape_string("\x06") == "\\u0006");
        CHECK(json::escape_string("\x07") == "\\u0007");
        CHECK(json::escape_string("\x08") == "\\b");
        CHECK(json::escape_string("\x09") == "\\t");
        CHECK(json::escape_string("\x0a") == "\\n");
        CHECK(json::escape_string("\x0b") == "\\u000b");
        CHECK(json::escape_string("\x0c") == "\\f");
        CHECK(json::escape_string("\x0d") == "\\r");
        CHECK(json::escape_string("\x0e") == "\\u000e");
        CHECK(json::escape_string("\x0f") == "\\u000f");
        CHECK(json::escape_string("\x10") == "\\u0010");
        CHECK(json::escape_string("\x11") == "\\u0011");
        CHECK(json::escape_string("\x12") == "\\u0012");
        CHECK(json::escape_string("\x13") == "\\u0013");
        CHECK(json::escape_string("\x14") == "\\u0014");
        CHECK(json::escape_string("\x15") == "\\u0015");
        CHECK(json::escape_string("\x16") == "\\u0016");
        CHECK(json::escape_string("\x17") == "\\u0017");
        CHECK(json::escape_string("\x18") == "\\u0018");
        CHECK(json::escape_string("\x19") == "\\u0019");
        CHECK(json::escape_string("\x1a") == "\\u001a");
        CHECK(json::escape_string("\x1b") == "\\u001b");
        CHECK(json::escape_string("\x1c") == "\\u001c");
        CHECK(json::escape_string("\x1d") == "\\u001d");
        CHECK(json::escape_string("\x1e") == "\\u001e");
        CHECK(json::escape_string("\x1f") == "\\u001f");
    }
}
