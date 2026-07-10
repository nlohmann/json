//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
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

    const MyContainer data{"[1,2,3,4]"};
    json as_json = json::parse(data);
    CHECK(as_json.at(0) == 1);
    CHECK(as_json.at(1) == 2);
    CHECK(as_json.at(2) == 3);
    CHECK(as_json.at(3) == 4);

}

struct MyContainerNonConstADL
{
    char* data;
    std::size_t size;
};

char* begin(MyContainerNonConstADL& c)
{
    return c.data;
}

char* end(MyContainerNonConstADL& c)
{
    return c.data + c.size; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

TEST_CASE("Custom container non-member non-const begin/end")
{
    // Container with lvalue-only non-const ADL begin/end (bug reproduction)
    std::string raw_data = "[1,2,3,4]";
    MyContainerNonConstADL data{&raw_data[0], raw_data.size()}; // NOLINT(readability-container-data-pointer)
    const json as_json = json::parse(data);
    CHECK(as_json.at(0) == 1);
    CHECK(as_json.at(1) == 2);
    CHECK(as_json.at(2) == 3);
    CHECK(as_json.at(3) == 4);

    // Same container with accept()
    CHECK(json::accept(data));
}

TEST_CASE("Custom container non-member begin/end, rvalue")
{
    // Regression check: rvalue container parsing should still work
    const json as_json = json::parse(MyContainer{"[1,2,3,4]"});
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

        const char* begin() const noexcept
        {
            return data;
        }

        const char* end() const noexcept
        {
            return data + strlen(data); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }
    };

    const MyContainer2 data{"[1,2,3,4]"};
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

    const MyIterator begin{raw_data};
    const MyIterator end{raw_data + strlen(raw_data)}; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    json as_json = json::parse(begin, end);
    CHECK(as_json.at(0) == 1);
    CHECK(as_json.at(1) == 2);
    CHECK(as_json.at(2) == 3);
    CHECK(as_json.at(3) == 4);
}

// Custom sentinel type for testing heterogeneous iterator+sentinel support
struct CustomSentinel
{
    const char* end_ptr;

    // only the iterator-first direction (it != sentinel) is ever evaluated by
    // the library's parse loop; a reversed-order overload would go unused and
    // trip -Wunneeded-internal-declaration under -Weverything
    friend bool operator!=(const char* it, const CustomSentinel& sentinel)
    {
        return it != sentinel.end_ptr;
    }
};

TEST_CASE("Parse with heterogeneous iterator and sentinel types")
{
    std::string json_str = R"({"key":"value"})";
    const char* end_ptr = json_str.data() + json_str.size();

    // Parse using pointer and sentinel (different types)
    json j = json::parse(json_str.data(), CustomSentinel{end_ptr});
    CHECK(j["key"] == "value");

    // Accept using pointer and sentinel
    CHECK(json::accept(json_str.data(), CustomSentinel{end_ptr}));

    // Test that the same-type case still works
    std::string raw_data = R"([1,2,3])";
    std::list<char> data(raw_data.begin(), raw_data.end());
    json j2 = json::parse(data.begin(), data.end());
    CHECK(j2.at(0) == 1);
}

} // namespace
