/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.1.1
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
        const auto check_escaped = [](const char* original,
                                      const char* escaped)
        {
            std::stringstream ss;
            json::serializer s(ss);
            s.dump_escaped(original);
            CHECK(ss.str() == escaped);
        };

        check_escaped("\"", "\\\"");
        check_escaped("\\", "\\\\");
        check_escaped("\b", "\\b");
        check_escaped("\f", "\\f");
        check_escaped("\n", "\\n");
        check_escaped("\r", "\\r");
        check_escaped("\t", "\\t");

        check_escaped("\x01", "\\u0001");
        check_escaped("\x02", "\\u0002");
        check_escaped("\x03", "\\u0003");
        check_escaped("\x04", "\\u0004");
        check_escaped("\x05", "\\u0005");
        check_escaped("\x06", "\\u0006");
        check_escaped("\x07", "\\u0007");
        check_escaped("\x08", "\\b");
        check_escaped("\x09", "\\t");
        check_escaped("\x0a", "\\n");
        check_escaped("\x0b", "\\u000b");
        check_escaped("\x0c", "\\f");
        check_escaped("\x0d", "\\r");
        check_escaped("\x0e", "\\u000e");
        check_escaped("\x0f", "\\u000f");
        check_escaped("\x10", "\\u0010");
        check_escaped("\x11", "\\u0011");
        check_escaped("\x12", "\\u0012");
        check_escaped("\x13", "\\u0013");
        check_escaped("\x14", "\\u0014");
        check_escaped("\x15", "\\u0015");
        check_escaped("\x16", "\\u0016");
        check_escaped("\x17", "\\u0017");
        check_escaped("\x18", "\\u0018");
        check_escaped("\x19", "\\u0019");
        check_escaped("\x1a", "\\u001a");
        check_escaped("\x1b", "\\u001b");
        check_escaped("\x1c", "\\u001c");
        check_escaped("\x1d", "\\u001d");
        check_escaped("\x1e", "\\u001e");
        check_escaped("\x1f", "\\u001f");
    }
}
