//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <iterator>
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

    // -Weffc++ asks for the member to be initialized in the member
    // initialization list, which a defaulted constructor does not do; the
    // exception specification a defaulted one would have carried has to be
    // written out as well, or -Wnoexcept objects where the standard library
    // takes noexcept(construct(...))
    no_key_compare_map() noexcept(std::is_nothrow_default_constructible<map_t>::value) : data() {}

    // converting between two basic_json types builds the object from a range
    template<class InputIt>
    no_key_compare_map(InputIt first, InputIt last) : data(first, last) {}

    iterator begin() noexcept
    {
        return data.begin();
    }
    iterator end() noexcept
    {
        return data.end();
    }
    const_iterator begin() const noexcept
    {
        return data.begin();
    }
    const_iterator end() const noexcept
    {
        return data.end();
    }
    const_iterator cbegin() const noexcept
    {
        return data.cbegin();
    }
    const_iterator cend() const noexcept
    {
        return data.cend();
    }

    bool empty() const noexcept
    {
        return data.empty();
    }
    size_type size() const noexcept
    {
        return data.size();
    }
    size_type max_size() const noexcept
    {
        return data.max_size();
    }
    void clear() noexcept
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

    void swap(no_key_compare_map& other) noexcept(noexcept(data.swap(other.data)))
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

// wraps an iterator, but only offers the LegacyForwardIterator operations,
// like the iterators of std::unordered_map and other hash maps
template<class BaseIterator>
class forward_only_iterator
{
    BaseIterator m_it{};

  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = typename std::iterator_traits<BaseIterator>::value_type;
    using difference_type = typename std::iterator_traits<BaseIterator>::difference_type;
    using pointer = typename std::iterator_traits<BaseIterator>::pointer;
    using reference = typename std::iterator_traits<BaseIterator>::reference;

    forward_only_iterator() = default;
    explicit forward_only_iterator(BaseIterator it) : m_it(it) {}

    BaseIterator base() const
    {
        return m_it;
    }

    reference operator*() const
    {
        return *m_it;
    }
    pointer operator->() const
    {
        return &*m_it;
    }
    forward_only_iterator& operator++()
    {
        ++m_it;
        return *this;
    }
    forward_only_iterator operator++(int)
    {
        auto result = *this;
        ++m_it;
        return result;
    }

    friend bool operator==(const forward_only_iterator& lhs, const forward_only_iterator& rhs)
    {
        return lhs.m_it == rhs.m_it;
    }
    friend bool operator!=(const forward_only_iterator& lhs, const forward_only_iterator& rhs)
    {
        return lhs.m_it != rhs.m_it;
    }
};

// An ObjectType whose iterators are forward-only, as those of hash maps are;
// it has no rbegin() and its iterators no operator--. A hash map is not used
// directly for the same reason as in no_key_compare_map above.
template<class Key, class T, class Compare, class Allocator>
class forward_only_map
{
    using map_t = std::map<Key, T, Compare, Allocator>;
    map_t data;

  public:
    using key_type = typename map_t::key_type;
    using mapped_type = typename map_t::mapped_type;
    using value_type = typename map_t::value_type;
    using size_type = typename map_t::size_type;
    using allocator_type = typename map_t::allocator_type;
    using iterator = forward_only_iterator<typename map_t::iterator>;
    using const_iterator = forward_only_iterator<typename map_t::const_iterator>;

    forward_only_map() noexcept(std::is_nothrow_default_constructible<map_t>::value) : data() {}

    template<class InputIt>
    forward_only_map(InputIt first, InputIt last) : data(first, last) {}

    iterator begin() noexcept
    {
        return iterator(data.begin());
    }
    iterator end() noexcept
    {
        return iterator(data.end());
    }
    const_iterator begin() const noexcept
    {
        return const_iterator(data.begin());
    }
    const_iterator end() const noexcept
    {
        return const_iterator(data.end());
    }
    const_iterator cbegin() const noexcept
    {
        return const_iterator(data.cbegin());
    }
    const_iterator cend() const noexcept
    {
        return const_iterator(data.cend());
    }

    bool empty() const noexcept
    {
        return data.empty();
    }
    size_type size() const noexcept
    {
        return data.size();
    }
    size_type max_size() const noexcept
    {
        return data.max_size();
    }
    void clear() noexcept
    {
        data.clear();
    }

    iterator find(const key_type& key)
    {
        return iterator(data.find(key));
    }
    const_iterator find(const key_type& key) const
    {
        return const_iterator(data.find(key));
    }
    size_type count(const key_type& key) const
    {
        return data.count(key);
    }

    std::pair<iterator, bool> emplace(const key_type& key, const mapped_type& value)
    {
        const auto result = data.emplace(key, value);
        return {iterator(result.first), result.second};
    }

    std::pair<iterator, bool> insert(const value_type& value)
    {
        const auto result = data.insert(value);
        return {iterator(result.first), result.second};
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
        return iterator(data.erase(pos.base()));
    }
    iterator erase(iterator first, iterator last)
    {
        return iterator(data.erase(first.base(), last.base()));
    }
    size_type erase(const key_type& key)
    {
        return data.erase(key);
    }

    void swap(forward_only_map& other) noexcept(noexcept(data.swap(other.data)))
    {
        data.swap(other.data);
    }

    friend bool operator==(const forward_only_map& lhs, const forward_only_map& rhs)
    {
        return lhs.data == rhs.data;
    }
    friend bool operator<(const forward_only_map& lhs, const forward_only_map& rhs)
    {
        return lhs.data < rhs.data;
    }
};

using forward_only_json = nlohmann::basic_json<forward_only_map>;

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
        CHECK(no_key_compare_json::from_bon8(no_key_compare_json::to_bon8(j)) == j);
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


TEST_CASE("object type with forward-only iterators")
{
    CHECK(std::is_same<std::iterator_traits<forward_only_json::object_t::iterator>::iterator_category,
          std::forward_iterator_tag>::value);

    SECTION("destroying nested objects and arrays")
    {
        forward_only_json j;
        j["a"] = 1;
        j["b"]["c"] = "x";
        j["b"]["d"] = forward_only_json::array();
        j["b"]["d"].push_back(forward_only_json::object());
        j["b"]["d"].push_back(true);
        j["b"]["e"]["f"]["g"] = nullptr;
        j["h"] = forward_only_json::object();
        j["i"]["j"] = 2;

        CHECK(j.size() == 4);
        CHECK(j["b"].size() == 3);
        CHECK(j["b"]["d"].size() == 2);
        CHECK(j["b"]["e"]["f"]["g"].is_null());

        CHECK(j.erase("b") == 1);
        CHECK(j.size() == 3);
        j = 42;
        CHECK(j == 42);
    }

    SECTION("destroying a deeply nested object")
    {
        constexpr std::size_t depth = 100000;
        forward_only_json j;
        forward_only_json* cur = &j;
        for (std::size_t i = 0; i < depth; ++i)
        {
            (*cur)["s"] = i;
            cur = &(*cur)["o"];
        }
        CHECK(j["o"]["o"]["s"] == 2);
        // destroyed at the end of scope without recursing per level
    }
}
