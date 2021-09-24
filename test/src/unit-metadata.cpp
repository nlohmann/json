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

template<class T>
using json_with_metadata =
    nlohmann::basic_json <
    std::map,
    std::vector,
    std::string,
    bool,
    std::int64_t,
    std::uint64_t,
    double,
    std::allocator,
    nlohmann::adl_serializer,
    std::vector<std::uint8_t>,
    T
    >;

TEST_CASE("JSON Node Metadata")
{
    SECTION("type int")
    {
        using json = json_with_metadata<int>;
        json null;
        auto obj   = json::object();
        auto array = json::array();

        null.metadata()  = 1;
        obj.metadata()   = 2;
        array.metadata() = 3;
        auto copy = array;

        CHECK(null.metadata()  == 1);
        CHECK(obj.metadata()   == 2);
        CHECK(array.metadata() == 3);
        CHECK(copy.metadata()  == 3);
    }
    SECTION("type vector<int>")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        auto copy = value;
        value.metadata().emplace_back(2);

        CHECK(copy.metadata().size()  == 1);
        CHECK(copy.metadata().at(0)   == 1);
        CHECK(value.metadata().size() == 2);
        CHECK(value.metadata().at(0)  == 1);
        CHECK(value.metadata().at(1)  == 2);
    }
    SECTION("copy ctor")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        json copy = value;

        CHECK(copy.metadata().size()  == 2);
        CHECK(copy.metadata().at(0)   == 1);
        CHECK(copy.metadata().at(1)   == 2);
        CHECK(value.metadata().size() == 2);
        CHECK(value.metadata().at(0)  == 1);
        CHECK(value.metadata().at(1)  == 2);

        value.metadata().clear();
        CHECK(copy.metadata().size()  == 2);
        CHECK(value.metadata().size() == 0);
    }
    SECTION("move ctor")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        const json moved = std::move(value);

        CHECK(moved.metadata().size()  == 2);
        CHECK(moved.metadata().at(0)   == 1);
        CHECK(moved.metadata().at(1)   == 2);
        CHECK(value.metadata().size()  == 0);
    }
    SECTION("move assign")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        json moved;
        moved = std::move(value);

        CHECK(moved.metadata().size()  == 2);
        CHECK(moved.metadata().at(0)   == 1);
        CHECK(moved.metadata().at(1)   == 2);
        CHECK(value.metadata().size()  == 0);
    }
    SECTION("copy assign")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        json copy;
        copy = value;

        CHECK(copy.metadata().size()  == 2);
        CHECK(copy.metadata().at(0)   == 1);
        CHECK(copy.metadata().at(1)   == 2);
        CHECK(value.metadata().size() == 2);
        CHECK(value.metadata().at(0)  == 1);
        CHECK(value.metadata().at(1)  == 2);

        value.metadata().clear();
        CHECK(copy.metadata().size()  == 2);
        CHECK(value.metadata().size() == 0);
    }
    SECTION("type unique_ptr<int>")
    {
        using json = json_with_metadata<std::unique_ptr<int>>;
        json value;
        value.metadata().reset(new int);
        (*value.metadata()) = 42;
        auto moved = std::move(value);

        CHECK(value.metadata() == nullptr);
        CHECK(moved.metadata() != nullptr);
        CHECK(*moved.metadata() == 42);
    }
    SECTION("type vector<int> in json array")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        json array(10, value);

        CHECK(value.metadata().size() == 2);
        CHECK(value.metadata().at(0)  == 1);
        CHECK(value.metadata().at(1)  == 2);

        for (const auto& val : array)
        {
            CHECK(val.metadata().size() == 2);
            CHECK(val.metadata().at(0)  == 1);
            CHECK(val.metadata().at(1)  == 2);
        }
    }
}
