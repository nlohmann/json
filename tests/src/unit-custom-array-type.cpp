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
#include <string>

namespace
{

// std::deque has no capacity() member function, which the library only needs
// to detect a reallocation for JSON_DIAGNOSTICS
using deque_json = nlohmann::basic_json<std::map, std::deque>;

} // namespace

TEST_CASE("array type without capacity()")
{
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
