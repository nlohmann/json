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

#ifdef JSON_DIAGNOSTICS
    #undef JSON_DIAGNOSTICS
#endif

#define JSON_DIAGNOSTICS 1

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("Better diagnostics")
{
    SECTION("empty JSON Pointer")
    {
        json j = 1;
        std::string s;
        CHECK_THROWS_WITH_AS(s = j.get<std::string>(), "[json.exception.type_error.302] type must be string, but is number", json::type_error);
    }

    SECTION("invalid type")
    {
        json j;
        j["a"]["b"]["c"] = 1;
        std::string s;
        CHECK_THROWS_WITH_AS(s = j["a"]["b"]["c"].get<std::string>(), "[json.exception.type_error.302] (/a/b/c) type must be string, but is number", json::type_error);
    }

    SECTION("missing key")
    {
        json j;
        j["object"]["object"] = true;
        CHECK_THROWS_WITH_AS(j["object"].at("not_found"), "[json.exception.out_of_range.403] (/object) key 'not_found' not found", json::out_of_range);
    }

    SECTION("array index out of range")
    {
        json j;
        j["array"][4] = true;
        CHECK_THROWS_WITH_AS(j["array"].at(5), "[json.exception.out_of_range.401] (/array) array index 5 is out of range", json::out_of_range);
    }

    SECTION("array index at wrong type")
    {
        json j;
        j["array"][4] = true;
        CHECK_THROWS_WITH_AS(j["array"][4][5], "[json.exception.type_error.305] (/array/4) cannot use operator[] with a numeric argument with boolean", json::type_error);
    }

    SECTION("wrong iterator")
    {
        json j;
        j["array"] = json::array();
        CHECK_THROWS_WITH_AS(j["array"].erase(j.begin()), "[json.exception.invalid_iterator.202] (/array) iterator does not fit current value", json::invalid_iterator);
    }

    SECTION("JSON Pointer escaping")
    {
        json j;
        j["a/b"]["m~n"] = 1;
        std::string s;
        CHECK_THROWS_WITH_AS(s = j["a/b"]["m~n"].get<std::string>(), "[json.exception.type_error.302] (/a~1b/m~0n) type must be string, but is number", json::type_error);
    }

    SECTION("Parse error")
    {
        json _;
        CHECK_THROWS_WITH_AS(_ = json::parse(""), "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal", json::parse_error);
    }

    SECTION("Regression test for https://github.com/nlohmann/json/pull/2562#pullrequestreview-574858448")
    {
        CHECK_THROWS_WITH_AS(json({"0", "0"})[1].get<int>(), "[json.exception.type_error.302] (/1) type must be number, but is string", json::type_error);
        CHECK_THROWS_WITH_AS(json({"0", "1"})[1].get<int>(), "[json.exception.type_error.302] (/1) type must be number, but is string", json::type_error);
    }

    SECTION("Regression test for https://github.com/nlohmann/json/pull/2562/files/380a613f2b5d32425021129cd1f371ddcfd54ddf#r563259793")
    {
        json j;
        j["/foo"] = {1, 2, 3};
        CHECK_THROWS_WITH_AS(j.unflatten(), "[json.exception.type_error.315] (/~1foo) values in object must be primitive", json::type_error);
    }
}
