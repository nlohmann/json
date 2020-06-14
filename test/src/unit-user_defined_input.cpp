/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.8.0
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

#include <list>

namespace
{
TEST_CASE("Use arbitrary stdlib container")
{
    std::string raw_data = "[1,2,3,4]";
    std::list<char> data(raw_data.begin(), raw_data.end());

    json as_json = json::parse(data.begin(), data.end());
    CHECK(as_json.at(0) == 1);
    CHECK(as_json.at(1) == 2);
    CHECK(as_json.at(2) == 3);
    CHECK(as_json.at(3) == 4);
}

struct MyContainer
{
    const char* data;
};

const char* begin(const MyContainer& c)
{
    return c.data;
}

const char* end(const MyContainer& c)
{
    return c.data + strlen(c.data);
}

TEST_CASE("Custom container")
{

    MyContainer data{"[1,2,3,4]"};
    json as_json = json::parse(data);
    CHECK(as_json.at(0) == 1);
    CHECK(as_json.at(1) == 2);
    CHECK(as_json.at(2) == 3);
    CHECK(as_json.at(3) == 4);

}

TEST_CASE("Custom iterator")
{
    const char* raw_data = "[1,2,3,4]";

    struct MyIterator
    {
        using difference_type = std::size_t;
        using value_type = char;
        using pointer = const char*;
        using reference = const char&;
        using iterator_category = std::input_iterator_tag;

        MyIterator& operator++()
        {
            ++ptr;
            return *this;
        }

        reference operator*() const
        {
            return *ptr;
        }

        bool operator!=(const MyIterator& rhs) const
        {
            return ptr != rhs.ptr;
        }

        const char* ptr;
    };

    MyIterator begin{raw_data};
    MyIterator end{raw_data + strlen(raw_data)};

    json as_json = json::parse(begin, end);
    CHECK(as_json.at(0) == 1);
    CHECK(as_json.at(1) == 2);
    CHECK(as_json.at(2) == 3);
    CHECK(as_json.at(3) == 4);
}

} // namespace
