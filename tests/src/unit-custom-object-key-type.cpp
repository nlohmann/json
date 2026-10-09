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
#include <utility>
#include <vector>

// Object types with a user-defined key type. The key types differ in what they
// offer to the library: a conversion to std::string (implicit or explicit), a
// comparison with ==, a to_json overload, or a c_str() member.

namespace custom_key_test
{
class key_base
{
  public:
    key_base() = default;

    key_base(const char* value)
        : m_value(value)
    {}

    key_base(std::string value)
        : m_value(std::move(value))
    {}

    // Required by JSON_DIAGNOSTICS, which reads object keys through data()
    // when building the path of an exception.
    const char* data() const noexcept
    {
        return m_value.data();
    }

    friend bool operator<(const key_base& lhs, const key_base& rhs)
    {
        return lhs.m_value < rhs.m_value;
    }

  protected:
    std::string m_value;
};

// implicit conversion to std::string and operator==
class key_full : public key_base
{
  public:
    key_full() = default;
    using key_base::key_base;

    operator std::string() const
    {
        return m_value;
    }

    friend bool operator==(const key_full& lhs, const key_full& rhs)
    {
        return lhs.m_value == rhs.m_value;
    }
};

// implicit conversion to std::string, but no operator==
class key_no_eq : public key_base
{
  public:
    key_no_eq() = default;
    using key_base::key_base;

    operator std::string() const
    {
        return m_value;
    }
};

// explicit conversion to std::string, no operator==
class key_explicit : public key_base
{
  public:
    key_explicit() = default;
    using key_base::key_base;

    explicit operator std::string() const
    {
        return m_value;
    }
};

// no conversion at all, only a to_json overload, no operator==
class key_to_json : public key_base
{
  public:
    key_to_json() = default;
    using key_base::key_base;

    const std::string& value() const
    {
        return m_value;
    }
};

template<typename BasicJsonType>
void to_json(BasicJsonType& j, const key_to_json& k)
{
    j = k.value();
}

// like key_to_json, but with size() and c_str()
class key_c_str : public key_base
{
  public:
    key_c_str() = default;
    using key_base::key_base;

    const std::string& value() const
    {
        return m_value;
    }

    std::size_t size() const
    {
        return m_value.size();
    }

    const char* c_str() const
    {
        return m_value.c_str();
    }
};

template<typename BasicJsonType>
void to_json(BasicJsonType& j, const key_c_str& k)
{
    j = k.value();
}

// std::map with key type K, ignoring the key type basic_json passes
template<class K>
struct object_for
{
    template<class Key, class Value, class Compare, class Allocator>
    using pair_allocator = typename std::allocator_traits<Allocator>::template rebind_alloc<std::pair<const K, Value>>;

    template<class Key, class Value, class Compare, class Allocator>
    using type = std::map<K, Value, std::less<K>, pair_allocator<Key, Value, Compare, Allocator>>; // NOLINT(modernize-use-transparent-functors)
};

using json_full = nlohmann::json::with_object_t<object_for<key_full>::type>;
using json_no_eq = nlohmann::json::with_object_t<object_for<key_no_eq>::type>;
using json_explicit = nlohmann::json::with_object_t<object_for<key_explicit>::type>;
using json_to_json = nlohmann::json::with_object_t<object_for<key_to_json>::type>;
using json_c_str = nlohmann::json::with_object_t<object_for<key_c_str>::type>;

// a key that is long enough to need a length byte in CBOR and MessagePack
const char* long_key_name(std::size_t i, std::string& storage);
const char* long_key_name(std::size_t i, std::string& storage)
{
    storage = "a key longer than thirty-one characters " + std::to_string(i);
    return storage.c_str();
}

// name of the key at nesting level i of a deep value
std::string deep_name(std::size_t i, bool long_keys);
std::string deep_name(std::size_t i, bool long_keys)
{
    std::string storage;
    return (long_keys && i % 2 == 1) ? std::string(long_key_name(i, storage)) : "k" + std::to_string(i);
}

// {"a": 1, "b": [true, null, "x"], "c": {"d": 2.5}, <keys of 23, 36, and 300 characters>}
// 23 is the longest CBOR length stored in the initial byte; 36 needs one
// length byte in CBOR and MessagePack, 300 needs two
template<class J>
J make_shallow()
{
    using key_t = typename J::object_t::key_type;

    J array = J::array();
    array.push_back(J(true));
    array.push_back(J(nullptr));
    array.push_back(J("x"));

    typename J::object_t inner;
    inner.emplace(key_t("d"), J(2.5));

    typename J::object_t object;
    object.emplace(key_t("a"), J(1));
    object.emplace(key_t("b"), std::move(array));
    object.emplace(key_t("c"), J(std::move(inner)));
    object.emplace(key_t(std::string(23, 'x')), J(2));
    object.emplace(key_t(std::string(36, 'y')), J(3));
    object.emplace(key_t(std::string(300, 'z')), J(4));
    return J(std::move(object));
}

// {"k0": {"k1": {... {"k<depth-1>": 1} ...}}}
template<class J>
J make_deep(std::size_t depth, bool long_keys)
{
    using key_t = typename J::object_t::key_type;

    J value = 1;
    for (std::size_t i = depth; i > 0; --i)
    {
        typename J::object_t object;
        object.emplace(key_t(deep_name(i - 1, long_keys)), std::move(value));
        value = J(std::move(object));
    }
    return value;
}

std::size_t deep_depth();
std::size_t deep_depth()
{
    return nlohmann::detail::recursion_depth_limit() + 10;
}

// walk down the nesting levels without recursion and check the leaf
template<class J>
bool check_deep(const J& value, std::size_t depth, bool long_keys)
{
    using key_t = typename J::object_t::key_type;

    const J* current = &value;
    for (std::size_t i = 0; i < depth; ++i)
    {
        if (!current->is_object() || current->size() != 1)
        {
            return false;
        }
        const auto it = current->find(key_t(deep_name(i, long_keys)));
        if (it == current->end())
        {
            return false;
        }
        current = &it.value();
    }
    return current->is_number_integer() && current->template get<int>() == 1;
}

template<class J>
bool check_shallow(const J& value)
{
    using key_t = typename J::object_t::key_type;

    if (!value.is_object() || value.size() != 6)
    {
        return false;
    }

    const auto a = value.find(key_t("a"));
    const auto b = value.find(key_t("b"));
    const auto c = value.find(key_t("c"));
    if (a == value.end() || b == value.end() || c == value.end())
    {
        return false;
    }

    const auto d = c->find(key_t("d"));
    // basic_json::operator== needs operator== on the keys, which most of the
    // key types do not have, so the values are checked through get<>()
    return a->template get<int>() == 1
    && b->is_array() && b->size() == 3 && (*b)[0].template get<bool>() && (*b)[1].is_null()
    && (*b)[2].template get<std::string>() == "x"
    && d != c->end() && d->template get<double>() == 2.5
    && value.find(key_t(std::string(23, 'x')))->template get<int>() == 2
    && value.find(key_t(std::string(36, 'y')))->template get<int>() == 3
    && value.find(key_t(std::string(300, 'z')))->template get<int>() == 4;
}

template<class J>
bool is_missing(const J& value, const char* name)
{
    return value.find(typename J::object_t::key_type(name)) == value.end();
}

// member access through find(): at() does not compile for key types without
// size() or a conversion to string_t (key_to_json), as in version 3.12.0
template<class J>
const J& member(const J& value, const char* name)
{
    const auto it = value.find(typename J::object_t::key_type(name));
    REQUIRE(it != value.end());
    return *it;
}
} // namespace custom_key_test

TEST_CASE_TEMPLATE("custom object key types: copy", J,
                   custom_key_test::json_full, custom_key_test::json_no_eq, custom_key_test::json_explicit,
                   custom_key_test::json_to_json, custom_key_test::json_c_str)
{
    SECTION("shallow")
    {
        const J original = custom_key_test::make_shallow<J>();
        REQUIRE(custom_key_test::check_shallow(original));

        const J copy(original); // NOLINT(performance-unnecessary-copy-initialization)
        CHECK(custom_key_test::check_shallow(copy));

        J assigned;
        assigned = original;
        CHECK(custom_key_test::check_shallow(assigned));

        // the original is unchanged
        CHECK(custom_key_test::check_shallow(original));
    }

    SECTION("deep")
    {
        const std::size_t depth = custom_key_test::deep_depth();

        const J original = custom_key_test::make_deep<J>(depth, false);
        REQUIRE(custom_key_test::check_deep(original, depth, false));

        const J copy(original); // NOLINT(performance-unnecessary-copy-initialization)
        CHECK(custom_key_test::check_deep(copy, depth, false));

        J assigned;
        assigned = original;
        CHECK(custom_key_test::check_deep(assigned, depth, false));

        CHECK(custom_key_test::check_deep(original, depth, false));
    }
}

TEST_CASE_TEMPLATE("custom object key types: parse", J,
                   custom_key_test::json_full, custom_key_test::json_no_eq, custom_key_test::json_explicit,
                   custom_key_test::json_to_json, custom_key_test::json_c_str)
{
    const J j = J::parse(R"({"a":1,"b":{"c":[1,2]}})");

    CHECK(j.size() == 2);
    CHECK(custom_key_test::member(j, "a").template get<int>() == 1);
    CHECK(custom_key_test::member(custom_key_test::member(j, "b"), "c").size() == 2);
    CHECK(custom_key_test::member(custom_key_test::member(j, "b"), "c")[1].template get<int>() == 2);

    // a deeply nested document
    const std::size_t depth = custom_key_test::deep_depth();
    std::string text;
    for (std::size_t i = 0; i < depth; ++i)
    {
        text += "{\"k" + std::to_string(i) + "\":";
    }
    text += "1";
    text.append(depth, '}');
    CHECK(custom_key_test::check_deep(J::parse(text), depth, false));
}

TEST_CASE_TEMPLATE("custom object key types: merge_patch, update, and insert", J,
                   custom_key_test::json_full, custom_key_test::json_no_eq, custom_key_test::json_explicit,
                   custom_key_test::json_to_json, custom_key_test::json_c_str)
{
    SECTION("merge_patch")
    {
        J j = J::parse(R"({"a":1,"b":2,"n":{"x":1,"y":2}})");
        j.merge_patch(J::parse(R"({"b":null,"c":3,"n":{"y":null,"z":3}})"));

        CHECK(j.size() == 3);
        CHECK(custom_key_test::member(j, "a").template get<int>() == 1);
        CHECK(custom_key_test::is_missing(j, "b"));
        CHECK(custom_key_test::member(j, "c").template get<int>() == 3);
        CHECK(custom_key_test::member(j, "n").size() == 2);
        CHECK(custom_key_test::member(custom_key_test::member(j, "n"), "x").template get<int>() == 1);
        CHECK(custom_key_test::member(custom_key_test::member(j, "n"), "z").template get<int>() == 3);
    }

    SECTION("update")
    {
        J j = J::parse(R"({"a":1,"b":2,"n":{"x":1}})");
        const J other = J::parse(R"({"b":3,"c":4,"n":{"y":2}})");

        J replaced = j;
        replaced.update(other);
        CHECK(replaced.size() == 4);
        CHECK(custom_key_test::member(replaced, "a").template get<int>() == 1);
        CHECK(custom_key_test::member(replaced, "b").template get<int>() == 3);
        CHECK(custom_key_test::member(replaced, "c").template get<int>() == 4);
        CHECK(custom_key_test::member(replaced, "n").size() == 1);
        CHECK(custom_key_test::member(custom_key_test::member(replaced, "n"), "y").template get<int>() == 2);

        j.update(other, true);
        CHECK(j.size() == 4);
        CHECK(custom_key_test::member(j, "n").size() == 2);
        CHECK(custom_key_test::member(custom_key_test::member(j, "n"), "x").template get<int>() == 1);
        CHECK(custom_key_test::member(custom_key_test::member(j, "n"), "y").template get<int>() == 2);
    }

    SECTION("insert")
    {
        J j = J::parse(R"({"a":1,"b":2})");
        const J other = J::parse(R"({"b":3,"c":4})");
        j.insert(other.begin(), other.end());

        CHECK(j.size() == 3);
        CHECK(custom_key_test::member(j, "b").template get<int>() == 2);
        CHECK(custom_key_test::member(j, "c").template get<int>() == 4);
    }
}

TEST_CASE_TEMPLATE("custom object key types: at() reports a missing key", J,
                   custom_key_test::json_full, custom_key_test::json_no_eq, custom_key_test::json_explicit,
                   custom_key_test::json_c_str)
{
    // not for key_to_json: at() needs the key's size() or a conversion to
    // string_t for its error message, which also was the case in version 3.12.0
    J j = J::parse(R"({"a":1})");
    const J& j_const = j;

    CHECK(j.at("a").template get<int>() == 1);
    CHECK(j_const.at("a").template get<int>() == 1);
    CHECK_THROWS_WITH_AS(j.at("missing"), "[json.exception.out_of_range.403] key 'missing' not found", typename J::out_of_range&);
    CHECK_THROWS_WITH_AS(j_const.at("missing"), "[json.exception.out_of_range.403] key 'missing' not found", typename J::out_of_range&);
}

TEST_CASE_TEMPLATE("custom object key types: BSON", J,
                   custom_key_test::json_full, custom_key_test::json_no_eq)
{
    SECTION("shallow")
    {
        const J value = custom_key_test::make_shallow<J>();
        const nlohmann::json expected = custom_key_test::make_shallow<nlohmann::json>();

        const std::vector<std::uint8_t> encoded = J::to_bson(value);
        CHECK(encoded == nlohmann::json::to_bson(expected));
        CHECK(nlohmann::json::from_bson(encoded) == expected);
    }

    SECTION("deep")
    {
        const std::size_t depth = custom_key_test::deep_depth();
        const J value = custom_key_test::make_deep<J>(depth, false);
        const nlohmann::json expected = custom_key_test::make_deep<nlohmann::json>(depth, false);

        const std::vector<std::uint8_t> encoded = J::to_bson(value);
        CHECK(encoded == nlohmann::json::to_bson(expected));
        CHECK(nlohmann::json::from_bson(encoded) == expected);
    }
}

TEST_CASE_TEMPLATE("custom object key types: CBOR", J,
                   custom_key_test::json_full, custom_key_test::json_no_eq, custom_key_test::json_explicit,
                   custom_key_test::json_to_json, custom_key_test::json_c_str)
{
    SECTION("shallow")
    {
        const J value = custom_key_test::make_shallow<J>();
        const nlohmann::json expected = custom_key_test::make_shallow<nlohmann::json>();

        const std::vector<std::uint8_t> encoded = J::to_cbor(value);
        CHECK(encoded == nlohmann::json::to_cbor(expected));
        CHECK(nlohmann::json::from_cbor(encoded) == expected);
    }

    SECTION("deeper than the recursion depth limit")
    {
        const std::size_t depth = custom_key_test::deep_depth();
        const J value = custom_key_test::make_deep<J>(depth, true);
        const nlohmann::json expected = custom_key_test::make_deep<nlohmann::json>(depth, true);

        const std::vector<std::uint8_t> encoded = J::to_cbor(value);
        CHECK(encoded == nlohmann::json::to_cbor(expected));
        CHECK(nlohmann::json::from_cbor(encoded) == expected);
    }
}

TEST_CASE_TEMPLATE("custom object key types: MessagePack", J,
                   custom_key_test::json_full, custom_key_test::json_no_eq, custom_key_test::json_explicit,
                   custom_key_test::json_to_json, custom_key_test::json_c_str)
{
    SECTION("shallow")
    {
        const J value = custom_key_test::make_shallow<J>();
        const nlohmann::json expected = custom_key_test::make_shallow<nlohmann::json>();

        const std::vector<std::uint8_t> encoded = J::to_msgpack(value);
        CHECK(encoded == nlohmann::json::to_msgpack(expected));
        CHECK(nlohmann::json::from_msgpack(encoded) == expected);
    }

    SECTION("deeper than the recursion depth limit")
    {
        const std::size_t depth = custom_key_test::deep_depth();
        const J value = custom_key_test::make_deep<J>(depth, true);
        const nlohmann::json expected = custom_key_test::make_deep<nlohmann::json>(depth, true);

        const std::vector<std::uint8_t> encoded = J::to_msgpack(value);
        CHECK(encoded == nlohmann::json::to_msgpack(expected));
        CHECK(nlohmann::json::from_msgpack(encoded) == expected);
    }
}
