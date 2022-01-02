/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.5
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2022 Niels Lohmann <http://nlohmann.me>.

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

    // Ranged insert test.
    // It seems that values shouldn't be overwritten. Only new values are added
    json j1 {{"c", 1}, {"b", 2}, {"a", 3}};
    const json j2 {{"c", 77}, {"d", 42}, {"a", 4}};
    j1.insert( j2.cbegin(), j2.cend() );
    CHECK(j1.size() == 4);
    CHECK(j1.dump() == "{\"a\":3,\"b\":2,\"c\":1,\"d\":42}");

    ordered_json oj1 {{"c", 1}, {"b", 2}, {"a", 3}};
    const ordered_json oj2 {{"c", 77}, {"d", 42}, {"a", 4}};
    oj1.insert( oj2.cbegin(), oj2.cend() );
    CHECK(oj1.size() == 4);
    CHECK(oj1.dump() == "{\"c\":1,\"b\":2,\"a\":3,\"d\":42}");
}
