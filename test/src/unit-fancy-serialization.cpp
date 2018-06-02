/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.1.2
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2018 Evan Driscoll <evaned@gmail.com>

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
using nlohmann::fancy_dump;

TEST_CASE("serialization")
{
    SECTION("primitives")
    {
        SECTION("null")
        {
            std::stringstream ss;
            json j;
            fancy_dump(ss, j);
            CHECK(ss.str() == "null");
        }

        SECTION("true")
        {
            std::stringstream ss;
            json j = true;
            fancy_dump(ss, j);
            CHECK(ss.str() == "true");
        }

        SECTION("false")
        {
            std::stringstream ss;
            json j = false;
            fancy_dump(ss, j);
            CHECK(ss.str() == "false");
        }

        SECTION("integer")
        {
            std::stringstream ss;
            json j = 10;
            fancy_dump(ss, j);
            CHECK(ss.str() == "10");
        }

        SECTION("floating point")
        {
            std::stringstream ss;
            json j = 7.5;
            fancy_dump(ss, j);
            CHECK(ss.str() == "7.5");
        }
    }
}
