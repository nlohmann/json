/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.2
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

#include <set>

TEST_CASE("hash")
{
    // Collect hashes for different JSON values and make sure that they are distinct
    // We cannot compare against fixed values, because the implementation of
    // std::hash may differ between compilers.

    std::set<std::size_t> hashes;

    // null
    hashes.insert(std::hash<json> {}(json(nullptr)));

    // boolean
    hashes.insert(std::hash<json> {}(json(true)));
    hashes.insert(std::hash<json> {}(json(false)));

    // string
    hashes.insert(std::hash<json> {}(json("")));
    hashes.insert(std::hash<json> {}(json("foo")));

    // number
    hashes.insert(std::hash<json> {}(json(0)));
    hashes.insert(std::hash<json> {}(json(unsigned(0))));

    hashes.insert(std::hash<json> {}(json(-1)));
    hashes.insert(std::hash<json> {}(json(0.0)));
    hashes.insert(std::hash<json> {}(json(42.23)));

    // array
    hashes.insert(std::hash<json> {}(json::array()));
    hashes.insert(std::hash<json> {}(json::array({1, 2, 3})));

    // object
    hashes.insert(std::hash<json> {}(json::object()));
    hashes.insert(std::hash<json> {}(json::object({{"foo", "bar"}})));

    // binary
    hashes.insert(std::hash<json> {}(json::binary({})));
    hashes.insert(std::hash<json> {}(json::binary({}, 0)));
    hashes.insert(std::hash<json> {}(json::binary({}, 42)));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3})));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3}, 0)));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3}, 42)));

    // discarded
    hashes.insert(std::hash<json> {}(json(json::value_t::discarded)));

    CHECK(hashes.size() == 21);
}
