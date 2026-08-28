//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{

// An ObjectType that does *not* define a key_compare member type. It adapts
// std::unordered_map to the template argument order expected by basic_json,
// where the third argument is a comparator rather than a hash function.
template<class Key, class T, class IgnoredCompare, class Allocator>
struct unordered_map_object
    : std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, Allocator>
{
    using base_t = std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, Allocator>;
    using base_t::base_t;
};

using unordered_json = nlohmann::basic_json<unordered_map_object>;

// An ObjectType whose erase(iterator) returns void rather than the following
// iterator, as for instance Abseil's hash maps do
template<class Key, class T, class Compare, class Allocator>
struct void_erase_map : std::map<Key, T, Compare, Allocator>
{
    using base_t = std::map<Key, T, Compare, Allocator>;
    using base_t::base_t;
    using iterator = typename base_t::iterator;
    using base_t::erase;

    void erase(iterator pos)
    {
        base_t::erase(pos);
    }
};

using void_erase_json = nlohmann::basic_json<void_erase_map>;

} // namespace

TEST_CASE("object type whose erase() returns void")
{
    SECTION("erasing every element through the returned iterator")
    {
        void_erase_json j;
        for (int i = 0; i < 8; ++i)
        {
            j["k" + std::to_string(i)] = i;
        }

        std::size_t erased = 0;
        for (auto it = j.begin(); it != j.end(); ++erased)
        {
            it = j.erase(it);
        }
        CHECK(erased == 8);
        CHECK(j.empty());
    }

    SECTION("erasing in the middle returns the following element")
    {
        void_erase_json j;
        for (int i = 0; i < 4; ++i)
        {
            j["k" + std::to_string(i)] = i;
        }

        auto it = j.begin();
        ++it;
        const auto after = j.erase(it);
        CHECK(j.size() == 3);
        CHECK(after.key() == "k2");
        CHECK(after.value() == 2);
        CHECK(!j.contains("k1"));
    }

    SECTION("the other erase overloads are unaffected")
    {
        void_erase_json j;
        j["a"] = 1;
        j["b"] = 2;
        j["c"] = 3;

        CHECK(j.erase("a") == 1);
        CHECK(j.erase("nope") == 0);
        j.erase(j.begin(), j.end());
        CHECK(j.empty());
    }
}

TEST_CASE("object type without key_compare")
{
    SECTION("object_comparator_t falls back to default_object_comparator_t")
    {
        CHECK(std::is_same < unordered_json::object_comparator_t,
              unordered_json::default_object_comparator_t >::value);
    }

    SECTION("object types defining key_compare are unaffected")
    {
        CHECK(std::is_same<nlohmann::json::object_comparator_t,
              nlohmann::json::object_t::key_compare>::value);
        CHECK(std::is_same<nlohmann::ordered_json::object_comparator_t,
              nlohmann::ordered_json::object_t::key_compare>::value);
    }

    SECTION("creating and accessing values")
    {
        unordered_json j;
        j["one"] = 1;
        j["two"] = "zwei";
        j["three"]["nested"] = true;

        CHECK(j.size() == 3);
        CHECK(j.at("one") == 1);
        CHECK(j["two"] == "zwei");
        CHECK(j["three"]["nested"] == true);
        CHECK(j.contains("one"));
        CHECK(!j.contains("four"));
        CHECK(j.find("one") != j.end());
        CHECK(j.count("one") == 1);
        CHECK(j.erase("one") == 1);
        CHECK(j.size() == 2);
    }

    SECTION("serialization and deserialization")
    {
        const auto j = unordered_json::parse(R"({"a":[1,2,3],"b":{"c":null}})");
        CHECK(j["a"].size() == 3);
        CHECK(j["a"][2] == 3);
        CHECK(j["b"]["c"].is_null());
        CHECK(unordered_json::parse(j.dump()) == j);
    }

    SECTION("binary formats")
    {
        const auto j = unordered_json::parse(R"({"a":[1,2,3],"b":"x"})");
        CHECK(unordered_json::from_cbor(unordered_json::to_cbor(j)) == j);
        CHECK(unordered_json::from_msgpack(unordered_json::to_msgpack(j)) == j);
    }

    SECTION("flatten and unflatten do not depend on the iteration order")
    {
        // the flattened object is iterated in an unspecified order, so
        // unflatten() must not decide between array and object based on
        // whichever reference token it happens to see first
        const auto j = unordered_json::parse(
                           R"({"c":[1,2,3],"d":{"e":"s"},"n":[[0,1],[2]],"o":{"2":"x"}})");
        CHECK(j.flatten().unflatten() == j);
    }

    SECTION("conversion to and from nlohmann::json")
    {
        const auto j = unordered_json::parse(R"({"a":1,"b":[true,null]})");
        const nlohmann::json converted(j);

        CHECK(converted.is_object());
        CHECK(converted["a"] == 1);
        CHECK(converted["b"][0] == true);
        CHECK(converted["b"][1].is_null());
        CHECK(unordered_json(converted) == j);
    }
}
