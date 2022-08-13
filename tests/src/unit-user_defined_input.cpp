//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

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
    return c.data + strlen(c.data); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

TEST_CASE("Custom container non-member begin/end")
{

    MyContainer data{"[1,2,3,4]"};
    json as_json = json::parse(data);
    CHECK(as_json.at(0) == 1);
    CHECK(as_json.at(1) == 2);
    CHECK(as_json.at(2) == 3);
    CHECK(as_json.at(3) == 4);

}

TEST_CASE("Custom container member begin/end")
{
    struct MyContainer2
    {
        const char* data;

        const char* begin() const
        {
            return data;
        }

        const char* end() const
        {
            return data + strlen(data); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }
    };

    MyContainer2 data{"[1,2,3,4]"};
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
            ++ptr; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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

    // avoid -Wunused-local-typedefs
    CHECK(std::is_same<MyIterator::difference_type, std::size_t>::value);
    CHECK(std::is_same<MyIterator::value_type, char>::value);
    CHECK(std::is_same<MyIterator::pointer, const char*>::value);
    CHECK(std::is_same<MyIterator::reference, const char&>::value);
    CHECK(std::is_same<MyIterator::iterator_category, std::input_iterator_tag>::value);

    MyIterator begin{raw_data};
    MyIterator end{raw_data + strlen(raw_data)}; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    json as_json = json::parse(begin, end);
    CHECK(as_json.at(0) == 1);
    CHECK(as_json.at(1) == 2);
    CHECK(as_json.at(2) == 3);
    CHECK(as_json.at(3) == 4);
}

} // namespace
