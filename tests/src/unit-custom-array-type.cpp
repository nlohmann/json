//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <deque>
#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

// TEMPORARY: this translation unit is disabled to narrow down an AppVeyor
// failure on MSVC 2015/2017 whose build log this environment cannot reach.
// The guard is removed again as soon as the cause is known.
#if 0

namespace
{

// std::deque has no capacity() member function, which the library only needs
// to detect a reallocation for JSON_DIAGNOSTICS
using deque_json = nlohmann::basic_json<std::map, std::deque>;

// a std::vector whose at() is hidden: the library performs its own bounds
// check and must not fall back to the container's checked accessor
template<class T, class Allocator = std::allocator<T>>
class vector_without_at : public std::vector<T, Allocator>
{
  public:
    vector_without_at() = default;

    // the array of an initializer list is built from a range
    template<class InputIt>
    vector_without_at(InputIt first, InputIt last) : std::vector<T, Allocator>(first, last) {}

    void at() = delete;
};

using no_at_json = nlohmann::basic_json<std::map, vector_without_at>;

} // namespace

TEST_CASE("array type without capacity()")
{
    SECTION("the iterators take their exception specification from the container")
    {
        // basic_json's iterators move exactly as the container iterators do:
        // their move operations are defaulted without a declared noexcept,
        // because an array or object type whose iterator is not nothrow move
        // constructible would otherwise have them deleted (std::deque's is not
        // with libstdc++ before 11, and neither are MSVC's debug iterators)
        CHECK(std::is_nothrow_move_constructible<nlohmann::json::iterator>::value ==
              (std::is_nothrow_move_constructible<nlohmann::json::object_t::iterator>::value
               && std::is_nothrow_move_constructible<nlohmann::json::array_t::iterator>::value));
        CHECK(std::is_nothrow_move_assignable<nlohmann::json::iterator>::value ==
              (std::is_nothrow_move_assignable<nlohmann::json::object_t::iterator>::value
               && std::is_nothrow_move_assignable<nlohmann::json::array_t::iterator>::value));
        CHECK(std::is_nothrow_move_constructible<nlohmann::json::const_iterator>::value ==
              (std::is_nothrow_move_constructible<nlohmann::json::object_t::const_iterator>::value
               && std::is_nothrow_move_constructible<nlohmann::json::array_t::const_iterator>::value));

        // and they are movable at all, which is what dropping the declared
        // noexcept buys for a std::deque array
        CHECK(std::is_move_constructible<deque_json::iterator>::value);
        CHECK(std::is_move_assignable<deque_json::iterator>::value);
    }

    SECTION("adding elements")
    {
        deque_json j = deque_json::array();
        j.push_back(1);
        j.push_back("two");
        j.emplace_back(3);
        j += 4;

        CHECK(j.size() == 4);
        CHECK(j == deque_json({1, "two", 3, 4}));
        CHECK(j.back() == 4);
        CHECK(j.front() == 1);
    }

    SECTION("accessing and modifying elements")
    {
        auto j = deque_json::parse(R"([1,2,3])");

        CHECK(j[1] == 2);
        CHECK(j.at(2) == 3);

        // growing through operator[] fills up with null values
        j[5] = 6;
        CHECK(j.size() == 6);
        CHECK(j[4].is_null());
        CHECK(j[5] == 6);

        j.erase(0);
        CHECK(j == deque_json({2, 3, nullptr, nullptr, 6}));

        auto it = j.erase(j.begin());
        CHECK(*it == 3);

        j.insert(j.begin(), 1);
        CHECK(j.front() == 1);
    }

    SECTION("serialization and deserialization")
    {
        const auto j = deque_json::parse(R"({"a":[1,[2,3]],"b":[]})");
        CHECK(j.dump() == R"({"a":[1,[2,3]],"b":[]})");
        CHECK(deque_json::parse(j.dump()) == j);
        CHECK(deque_json::from_cbor(deque_json::to_cbor(j)) == j);

        // empty containers are flattened to null and cannot be restored
        const auto nested = deque_json::parse(R"({"a":[1,[2,3]]})");
        CHECK(nested.flatten().unflatten() == nested);
    }

    SECTION("references stay valid while the array grows")
    {
        deque_json j = deque_json::array();
        j.push_back(1);
        auto& first = j[0];
        for (int i = 0; i < 100; ++i)
        {
            j.push_back(i);
        }
        CHECK(&first == &j[0]);
        CHECK(first == 1);
    }
}

TEST_CASE("array type without at()")
{
    // built in memory rather than parsed, so that the exception message does
    // not gain a byte range with JSON_DIAGNOSTIC_POSITIONS
    no_at_json j = {1, 2, 3};
    const auto& jc = j;

    CHECK(j.at(0) == 1);
    CHECK(j.at(2) == 3);
    CHECK(jc.at(2) == 3);

    CHECK_THROWS_WITH_AS(j.at(3), "[json.exception.out_of_range.401] array index 3 is out of range", no_at_json::out_of_range);
    CHECK_THROWS_WITH_AS(jc.at(3), "[json.exception.out_of_range.401] array index 3 is out of range", no_at_json::out_of_range);

    CHECK(j.at(no_at_json::json_pointer("/1")) == 2);
    CHECK_THROWS_AS(j.at(no_at_json::json_pointer("/3")), no_at_json::out_of_range);
}

#endif
