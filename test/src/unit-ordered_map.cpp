/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.9.0
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
using nlohmann::ordered_map;


TEST_CASE("ordered_map")
{
    SECTION("constructor")
    {
        SECTION("constructor from iterator range")
        {
            std::map<std::string, std::string> m {{"eins", "one"}, {"zwei", "two"}, {"drei", "three"}};
            ordered_map<std::string, std::string> om(m.begin(), m.end());
            CHECK(om.size() == 3);
        }

        SECTION("copy assignment")
        {
            std::map<std::string, std::string> m {{"eins", "one"}, {"zwei", "two"}, {"drei", "three"}};
            ordered_map<std::string, std::string> om(m.begin(), m.end());
            const auto com = om;
            CHECK(com.size() == 3);
        }
    }

    SECTION("at")
    {
        std::map<std::string, std::string> m {{"eins", "one"}, {"zwei", "two"}, {"drei", "three"}};
        ordered_map<std::string, std::string> om(m.begin(), m.end());
        const auto com = om;

        SECTION("with Key&&")
        {
            CHECK(om.at(std::string("eins")) == std::string("one"));
            CHECK(com.at(std::string("eins")) == std::string("one"));
            CHECK_THROWS_AS(om.at(std::string("vier")), std::out_of_range);
            CHECK_THROWS_AS(com.at(std::string("vier")), std::out_of_range);
        }

        SECTION("with const Key&&")
        {
            const std::string eins = "eins";
            const std::string vier = "vier";
            CHECK(om.at(eins) == std::string("one"));
            CHECK(com.at(eins) == std::string("one"));
            CHECK_THROWS_AS(om.at(vier), std::out_of_range);
            CHECK_THROWS_AS(com.at(vier), std::out_of_range);
        }

        SECTION("with string literal")
        {
            CHECK(om.at("eins") == std::string("one"));
            CHECK(com.at("eins") == std::string("one"));
            CHECK_THROWS_AS(om.at("vier"), std::out_of_range);
            CHECK_THROWS_AS(com.at("vier"), std::out_of_range);
        }
    }

    SECTION("operator[]")
    {
        std::map<std::string, std::string> m {{"eins", "one"}, {"zwei", "two"}, {"drei", "three"}};
        ordered_map<std::string, std::string> om(m.begin(), m.end());
        const auto com = om;

        SECTION("with Key&&")
        {
            CHECK(om[std::string("eins")] == std::string("one"));
            CHECK(com[std::string("eins")] == std::string("one"));

            CHECK(om[std::string("vier")] == std::string(""));
            CHECK(om.size() == 4);
        }

        SECTION("with const Key&&")
        {
            const std::string eins = "eins";
            const std::string vier = "vier";

            CHECK(om[eins] == std::string("one"));
            CHECK(com[eins] == std::string("one"));

            CHECK(om[vier] == std::string(""));
            CHECK(om.size() == 4);
        }

        SECTION("with string literal")
        {
            CHECK(om["eins"] == std::string("one"));
            CHECK(com["eins"] == std::string("one"));

            CHECK(om["vier"] == std::string(""));
            CHECK(om.size() == 4);
        }
    }
}
