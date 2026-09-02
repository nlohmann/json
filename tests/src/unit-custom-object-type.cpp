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
#include <map>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>


namespace
{

// An ObjectType that does *not* define a key_compare member type, which is
// what every hash map looks like to the library.
//
// A hash map is deliberately not used here: object_t is probed for
// key_compare inside the definition of basic_json, that is, while basic_json
// is still an incomplete type, and whether a hash map can be instantiated
// with an incomplete mapped type depends on the standard library (libstdc++ 9
// needs the size of the mapped type for its node type and rejects it). So the
// object type wraps a std::map instead of inheriting from it: an earlier
// version derived from std::map and shadowed the inherited key_compare type
// with a same-named member function, relying on ordinary member hiding to
// make key_compare unreachable as a type. MSVC 2017 (AppVeyor, /std:c++17)
// does not honor that hiding for a typename-qualified lookup performed from
// outside the class and still resolves key_compare to the base's comparator
// type, so the library's probe incorrectly found one. Composition sidesteps
// the question entirely: with no base class, there is no key_compare to find
// under any lookup rule.
template<class Key, class T, class Compare, class Allocator>
class no_key_compare_map
{
    using map_t = std::map<Key, T, Compare, Allocator>;
    map_t data;

  public:
    using key_type = typename map_t::key_type;
    using mapped_type = typename map_t::mapped_type;
    using value_type = typename map_t::value_type;
    using size_type = typename map_t::size_type;
    using allocator_type = typename map_t::allocator_type;
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;

    no_key_compare_map() = default;

    // converting between two basic_json types builds the object from a range
    template<class InputIt>
    no_key_compare_map(InputIt first, InputIt last) : data(first, last) {}

    iterator begin()
    {
        return data.begin();
    }
    iterator end()
    {
        return data.end();
    }
    const_iterator begin() const
    {
        return data.begin();
    }
    const_iterator end() const
    {
        return data.end();
    }
    const_iterator cbegin() const
    {
        return data.cbegin();
    }
    const_iterator cend() const
    {
        return data.cend();
    }

    bool empty() const
    {
        return data.empty();
    }
    size_type size() const
    {
        return data.size();
    }
    size_type max_size() const
    {
        return data.max_size();
    }
    void clear()
    {
        data.clear();
    }

    iterator find(const key_type& key)
    {
        return data.find(key);
    }
    const_iterator find(const key_type& key) const
    {
        return data.find(key);
    }
    size_type count(const key_type& key) const
    {
        return data.count(key);
    }

    std::pair<iterator, bool> emplace(const key_type& key, const mapped_type& value)
    {
        return data.emplace(key, value);
    }

    std::pair<iterator, bool> insert(const value_type& value)
    {
        return data.insert(value);
    }

    template<class InputIt>
    void insert(InputIt first, InputIt last)
    {
        data.insert(first, last);
    }

    mapped_type& operator[](const key_type& key)
    {
        return data[key];
    }

    mapped_type& at(const key_type& key)
    {
        return data.at(key);
    }
    const mapped_type& at(const key_type& key) const
    {
        return data.at(key);
    }

    iterator erase(iterator pos)
    {
        return data.erase(pos);
    }
    iterator erase(iterator first, iterator last)
    {
        return data.erase(first, last);
    }
    size_type erase(const key_type& key)
    {
        return data.erase(key);
    }

    void swap(no_key_compare_map& other)
    {
        data.swap(other.data);
    }

    friend bool operator==(const no_key_compare_map& lhs, const no_key_compare_map& rhs)
    {
        return lhs.data == rhs.data;
    }
    friend bool operator<(const no_key_compare_map& lhs, const no_key_compare_map& rhs)
    {
        return lhs.data < rhs.data;
    }
};

using no_key_compare_json = nlohmann::basic_json<no_key_compare_map>;

// An ObjectType whose erase(iterator) returns void rather than the following
// iterator, as for instance Abseil's hash maps do
template<class Key, class T, class Compare, class Allocator>
struct void_erase_map : std::map<Key, T, Compare, Allocator>
{
    using base_t = std::map<Key, T, Compare, Allocator>;
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
        CHECK(std::is_same < no_key_compare_json::object_comparator_t,
              no_key_compare_json::default_object_comparator_t >::value);
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
        no_key_compare_json j;
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
        const auto j = no_key_compare_json::parse(R"({"a":[1,2,3],"b":{"c":null}})");
        CHECK(j["a"].size() == 3);
        CHECK(j["a"][2] == 3);
        CHECK(j["b"]["c"].is_null());
        CHECK(no_key_compare_json::parse(j.dump()) == j);
    }

    SECTION("binary formats")
    {
        const auto j = no_key_compare_json::parse(R"({"a":[1,2,3],"b":"x"})");
        CHECK(no_key_compare_json::from_cbor(no_key_compare_json::to_cbor(j)) == j);
        CHECK(no_key_compare_json::from_msgpack(no_key_compare_json::to_msgpack(j)) == j);
    }

    SECTION("flatten and unflatten")
    {
        // "o" has a key that looks like an array index, so unflatten() must
        // not turn it into an array
        const auto j = no_key_compare_json::parse(
                           R"({"c":[1,2,3],"d":{"e":"s"},"n":[[0,1],[2]],"o":{"2":"x"}})");
        CHECK(j.flatten().unflatten() == j);
    }

    SECTION("conversion to and from nlohmann::json")
    {
        const auto j = no_key_compare_json::parse(R"({"a":1,"b":[true,null]})");
        const nlohmann::json converted(j);

        CHECK(converted.is_object());
        CHECK(converted["a"] == 1);
        CHECK(converted["b"][0] == true);
        CHECK(converted["b"][1].is_null());
        CHECK(no_key_compare_json(converted) == j);
    }
}

