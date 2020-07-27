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
using nlohmann::json;
using nlohmann::ordered_json;


TEST_CASE("ordered_json")
{
    json j;
    ordered_json oj;

    j["element3"] = 3;
    j["element1"] = 1;
    j["element2"] = 2;

    oj["element3"] = 3;
    oj["element1"] = 1;
    oj["element2"] = 2;

    CHECK(j.dump() == "{\"element1\":1,\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element1\":1,\"element2\":2}");

    CHECK(j == json(oj));
    CHECK(ordered_json(json(oj)) == ordered_json(j));

    j.erase("element1");
    oj.erase("element1");

    CHECK(j.dump() == "{\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element2\":2}");

    // remove again and nothing changes
    j.erase("element1");
    oj.erase("element1");

    CHECK(j.dump() == "{\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element2\":2}");

    // There are no dup keys cause constructor calls emplace...
    json multi {{"z", 1}, {"m", 2}, {"m", 3}, {"y", 4}, {"m", 5}};
    CHECK(multi.size() == 3);
    CHECK(multi.dump() == "{\"m\":2,\"y\":4,\"z\":1}");

    ordered_json multi_ordered {{"z", 1}, {"m", 2}, {"m", 3}, {"y", 4}, {"m", 5}};
    CHECK(multi_ordered.size() == 3);
    CHECK(multi_ordered.dump() == "{\"z\":1,\"m\":2,\"y\":4}");
    CHECK(multi_ordered.erase("m") == 1);
    CHECK(multi_ordered.dump() == "{\"z\":1,\"y\":4}");
}
