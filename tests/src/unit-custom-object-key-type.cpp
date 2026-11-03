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
#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "custom_object_key_type.hpp"

// These tests instantiate a second basic_json specialization. They live in
// their own file rather than in unit-cbor.cpp and unit-msgpack.cpp to keep
// those objects below 65535 sections: the MinGW linker stores the section a
// COMDAT section is associated with in 16 bits, so it misplaces the jump
// tables of larger objects (see the clang job in windows.yml).

TEST_CASE("CBOR supports custom object key types")
{
    using custom_json = custom_object_key_test::json;
    using custom_key = custom_object_key_test::key;

    custom_json::object_t object;
    object.emplace(custom_key{"short"}, 1);
    object.emplace(
              custom_key{"a key longer than twenty-three characters"},
              2);

    const custom_json value(std::move(object));
    const auto encoded = custom_json::to_cbor(value);

    CHECK(nlohmann::json::from_cbor(encoded) == nlohmann::json
    {
        {"short", 1},
        {"a key longer than twenty-three characters", 2}
    });
}

TEST_CASE("CBOR supports custom object key types nested deeper than the recursion depth limit")
{
    // below detail::recursion_depth_limit(), keys are written by
    // write_cbor_iterative instead of write_cbor
    using custom_json = custom_object_key_test::json;
    using custom_key = custom_object_key_test::key;

    const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 10;

    custom_json value = 1;
    nlohmann::json expected = 1;
    for (std::size_t i = 0; i < depth; ++i)
    {
        // alternate short keys with ones long enough to need a length byte
        const std::string name = (i % 2 == 0) ? "k" + std::to_string(i)
                                 : "a key longer than thirty-one characters " + std::to_string(i);

        custom_json::object_t object;
        object.emplace(custom_key{name}, std::move(value));
        value = custom_json(std::move(object));

        nlohmann::json::object_t expected_object;
        expected_object.emplace(name, std::move(expected));
        expected = nlohmann::json(std::move(expected_object));
    }

    const auto encoded = custom_json::to_cbor(value);
    CHECK(encoded == nlohmann::json::to_cbor(expected));
    CHECK(nlohmann::json::from_cbor(encoded) == expected);
}

TEST_CASE("MessagePack supports custom object key types")
{
    using custom_json = custom_object_key_test::json;
    using custom_key = custom_object_key_test::key;

    custom_json::object_t object;
    object.emplace(custom_key{"short"}, 1);
    object.emplace(
              custom_key{"a key longer than thirty-one characters"},
              2);

    const custom_json value(std::move(object));
    const auto encoded = custom_json::to_msgpack(value);

    CHECK(nlohmann::json::from_msgpack(encoded) == nlohmann::json
    {
        {"short", 1},
        {"a key longer than thirty-one characters", 2}
    });
}

TEST_CASE("MessagePack supports custom object key types nested deeper than the recursion depth limit")
{
    // below detail::recursion_depth_limit(), keys are written by
    // write_msgpack_iterative instead of write_msgpack
    using custom_json = custom_object_key_test::json;
    using custom_key = custom_object_key_test::key;

    const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 10;

    custom_json value = 1;
    nlohmann::json expected = 1;
    for (std::size_t i = 0; i < depth; ++i)
    {
        // alternate short keys with ones long enough to need a length byte
        const std::string name = (i % 2 == 0) ? "k" + std::to_string(i)
                                 : "a key longer than thirty-one characters " + std::to_string(i);

        custom_json::object_t object;
        object.emplace(custom_key{name}, std::move(value));
        value = custom_json(std::move(object));

        nlohmann::json::object_t expected_object;
        expected_object.emplace(name, std::move(expected));
        expected = nlohmann::json(std::move(expected_object));
    }

    const auto encoded = custom_json::to_msgpack(value);
    CHECK(encoded == nlohmann::json::to_msgpack(expected));
    CHECK(nlohmann::json::from_msgpack(encoded) == expected);
}

namespace
{
// A key type that cannot be constructed from a std::string, so that a value
// with such keys cannot be converted from a nlohmann::json by the range
// constructor of its object type: the serializer converts the object instead.
class strict_key
{
  public:
    strict_key(const char* value)
        : m_value(value)
    {}

    strict_key(const std::string& /*value*/) = delete;

#if JSON_DIAGNOSTICS
    // Required by JSON_DIAGNOSTICS, which reads object keys through data()
    // when building the path of an exception.
    const char* data() const noexcept
    {
        return m_value.data();
    }
#endif

    friend bool operator<(const strict_key& lhs, const strict_key& rhs)
    {
        return lhs.m_value < rhs.m_value;
    }

  private:
    std::string m_value;
};

strict_key make_strict_key(const std::string& key)
{
    return {key.c_str()};
}

template<class Key, class Value, class Compare, class Allocator>
class strict_object
    : public std::map <
      strict_key,
      Value,
      std::less<strict_key>, // NOLINT(modernize-use-transparent-functors)
      typename std::allocator_traits<Allocator>::template rebind_alloc <
          std::pair<const strict_key, Value >>>
{
  public:
    strict_object() = default;
};

template<typename T, typename = void>
struct strict_serializer : nlohmann::adl_serializer<T> {};

using strict_json = nlohmann::basic_json < strict_object, std::vector, std::string, bool, std::int64_t,
      std::uint64_t, double, std::allocator, strict_serializer, std::vector<std::uint8_t >>;

// the members of an object are converted one by one, their keys by make_strict_key()
template<>
struct strict_serializer<nlohmann::json::object_t, void>
{
    static void to_json(strict_json& j, const nlohmann::json::object_t& object)
    {
        strict_json::object_t converted;
        for (const auto& member : object)
        {
            converted.emplace(make_strict_key(member.first), strict_json(member.second));
        }
        j = strict_json(std::move(converted));
    }
};
} // namespace

TEST_CASE("converting a value with keys that cannot be made from a std::string nested deeper than the recursion depth limit")
{
    static_assert(!std::is_constructible<strict_key, const std::string&>::value, "the keys cannot be made from a std::string");

    // below detail::recursion_depth_limit(), objects and arrays are converted
    // by the serializers instead of the range constructors
    const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 10;

    nlohmann::json value = 1;
    for (std::size_t i = 0; i < depth; ++i)
    {
        if (i % 2 == 0)
        {
            value = nlohmann::json::object({{"a", std::move(value)}, {"b", true}});
        }
        else
        {
            value = nlohmann::json::array({std::move(value), "sibling"});
        }
    }

    // direct-initialization: a copy-initialization makes GCC 4.8 instantiate the
    // copy constructor, which needs a range constructor strict_object lacks
    const strict_json converted(value);

    // at() needs to make a std::string of a key for its error message
    const auto member = [](const strict_json & object, const char* name) -> const strict_json &
    {
        const auto it = object.find(strict_key(name));
        REQUIRE(it != object.end());
        return *it;
    };

    // walk down the nesting levels without recursion
    const strict_json* current = &converted;
    for (std::size_t i = depth; i > 0; --i)
    {
        if (i % 2 == 1)
        {
            REQUIRE(current->is_object());
            CHECK(current->size() == 2);
            CHECK(member(*current, "b").get<bool>());
            current = &member(*current, "a");
        }
        else
        {
            REQUIRE(current->is_array());
            CHECK(current->size() == 2);
            CHECK(current->at(1).get<std::string>() == "sibling");
            current = &current->at(0);
        }
    }
    CHECK(current->get<int>() == 1);
}

namespace
{
// shorter keys come first
struct shortlex_less
{
    bool operator()(const std::string& lhs, const std::string& rhs) const
    {
        return lhs.size() != rhs.size() ? lhs.size() < rhs.size() : lhs < rhs;
    }
};

template<class Key, class Value, class Compare, class Allocator>
using shortlex_map = std::map<Key, Value, shortlex_less, Allocator>;

using shortlex_json = nlohmann::json::with_object_t<shortlex_map>;
} // namespace

TEST_CASE("unflatten with an object type that does not sort the keys alphabetically")
{
    // the keys of /a come before and after one of /b: unlike in an object
    // sorted alphabetically, the values below a prefix are not found one
    // after the other, so the value of /a must be looked up again
    shortlex_json flat = shortlex_json::object();
    flat["/a/p"] = 1;
    flat["/b/qq"] = 2;
    flat["/a/pqr"] = 3;
    REQUIRE(flat.begin().key() == "/a/p");
    REQUIRE((++flat.begin()).key() == "/b/qq");

    CHECK(flat.unflatten().dump() == R"({"a":{"p":1,"pqr":3},"b":{"qq":2}})");
    CHECK(flat.unflatten().flatten() == flat);
}
