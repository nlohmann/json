//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake selects the C++ standard versions with which to build a
// unit test based on the presence of JSON_HAS_CPP_<VERSION> macros.
// When using macros that are only defined for particular versions of the standard
// (e.g., JSON_HAS_FILESYSTEM for C++17 and up), please mention the corresponding
// version macro in a comment close by, like this:
// JSON_HAS_CPP_<VERSION> (do not remove; see note at top of file)

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <list>

#if defined(__cpp_lib_concepts) && defined(JSON_HAS_CPP_20)
    #include <iterator>
#endif

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
    const std::string json_str = R"({"key":"value"})";
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

#if defined(__cpp_lib_concepts) && defined(JSON_HAS_CPP_20)
// JSON_HAS_CPP_20 (do not remove; see note at top of file)
TEST_CASE("Parse with std::counted_iterator and std::default_sentinel_t")
{
    using iterator_type = std::string::const_iterator;
    const std::string json_str = R"({"key":"value","array":[1,2,3]})";
    const auto len = static_cast<std::iter_difference_t<iterator_type>>(json_str.size());

    const std::counted_iterator<iterator_type> first(json_str.begin(), len);
    const json j = json::parse(first, std::default_sentinel);
    CHECK(j["key"] == "value");
    CHECK(j["array"].size() == 3);

    const std::counted_iterator<iterator_type> first2(json_str.begin(), len);
    CHECK(json::accept(first2, std::default_sentinel));
}

TEST_CASE("std::counted_iterator reaches the contiguous fast paths")
{
    // A sized sentinel makes the remaining element count computable in O(1), so
    // std::counted_iterator over a contiguous iterator must reach the same bulk
    // string/number scanners as a plain pointer - not just the byte-at-a-time
    // fallback (see #5268 for the equivalent memcpy fast path).
    using adapter_type = nlohmann::detail::iterator_input_adapter<std::counted_iterator<const char*>, std::default_sentinel_t>;
    CHECK(adapter_type::supports_bulk_scan);
    CHECK(adapter_type::supports_seek);

    // exercise every fast path: long ASCII run, multibyte UTF-8, escapes, and
    // integer/floating-point numbers
    const std::string json_str =
        R"({"ascii":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",)"
        "\"utf8\":\"\xe4\xb8\xad\xe6\x96\x87\xf0\x9f\x98\x80\xc3\xa9\","
        R"("escaped":"aéb\n\\","ints":[0,-1,18446744073709551615,-9223372036854775808],)"
        R"("floats":[1.5,-2.25e3,0.30000000000000004]})";
    const auto len = static_cast<std::iter_difference_t<const char*>>(json_str.size());

    const std::counted_iterator<const char*> first(json_str.data(), len);
    const json j = json::parse(first, std::default_sentinel);

    // parsing through the pointer adapter must give exactly the same result
    CHECK(j == json::parse(json_str));

    // and errors must still be reported identically
    const std::string bad = "[01\n]";
    const std::counted_iterator<const char*> bad_first(bad.data(), static_cast<std::iter_difference_t<const char*>>(bad.size()));
    std::string counted_what;
    std::string string_what;
    try
    {
        const json j = json::parse(bad_first, std::default_sentinel);
        static_cast<void>(j);
    }
    catch (const json::parse_error& e)
    {
        counted_what = e.what();
    }
    try
    {
        const json j = json::parse(bad);
        static_cast<void>(j);
    }
    catch (const json::parse_error& e)
    {
        string_what = e.what();
    }
    CHECK_FALSE(counted_what.empty());
    CHECK(counted_what == string_what);
}
#endif

} // namespace
