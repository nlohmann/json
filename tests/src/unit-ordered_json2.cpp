//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2018 Vitaliy Manushkin <agri@akamo.info>
// SPDX-License-Identifier: MIT

// This file closes a test-coverage gap described in GitHub issue #5421:
// nlohmann::ordered_json (and other non-default basic_json specializations,
// such as the alt_string-based one from unit-alt-string.cpp) were never
// exercised through the binary formats (CBOR/MessagePack/UBJSON/BSON/BJData)
// or through flatten()/unflatten()/diff()/patch()/merge_patch().

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using nlohmann::json;
using nlohmann::ordered_json;

/////////////////////////////////////////////////////////////////////////////
// alt_json: a second, independent copy of the custom-string_t basic_json
// specialization defined in unit-alt-string.cpp.
//
// It is duplicated here (rather than shared via a header) because every
// unit-*.cpp file in this test suite is compiled into its own standalone
// executable (see tests/CMakeLists.txt), so there is no ODR concern in
// having the same class name defined in multiple translation units.
//
// Two members had to be added relative to the original alt_string
// (a constructor from std::string, and a find(char, pos) overload) because
// the original type was never used with the binary writers/readers before
// this file: BSON's array/document writer converts std::to_string() results
// and checks for embedded NUL characters via find(char), and the UBJSON/BSON
// high-precision-number path constructs the SAX string_t argument from a
// std::string. Neither path is exercised anywhere else in the test suite for
// this type, which is presumably why the gap was never noticed.
/////////////////////////////////////////////////////////////////////////////

class alt_string;
bool operator<(const char* op1, const alt_string& op2) noexcept; // NOLINT(misc-use-internal-linkage)
void int_to_string(alt_string& target, std::size_t value); // NOLINT(misc-use-internal-linkage)

class alt_string
{
  public:
    using value_type = std::string::value_type;

    static constexpr auto npos = (std::numeric_limits<std::size_t>::max)();

    alt_string(const char* str): str_impl(str) {}
    alt_string(const char* str, std::size_t count): str_impl(str, count) {}
    alt_string(const std::string& str): str_impl(str) {}
    alt_string(size_t count, char chr): str_impl(count, chr) {}
    alt_string() = default;

    alt_string& append(char ch)
    {
        str_impl.push_back(ch);
        return *this;
    }

    alt_string& append(const alt_string& str)
    {
        str_impl.append(str.str_impl);
        return *this;
    }

    alt_string& append(const char* s, std::size_t length)
    {
        str_impl.append(s, length);
        return *this;
    }

    void push_back(char c)
    {
        str_impl.push_back(c);
    }

    template <typename op_type>
    bool operator==(const op_type& op) const
    {
        return str_impl == op;
    }

    bool operator==(const alt_string& op) const
    {
        return str_impl == op.str_impl;
    }

    template <typename op_type>
    bool operator!=(const op_type& op) const
    {
        return str_impl != op;
    }

    bool operator!=(const alt_string& op) const
    {
        return str_impl != op.str_impl;
    }

    std::size_t size() const noexcept
    {
        return str_impl.size();
    }

    void resize(std::size_t n)
    {
        str_impl.resize(n);
    }

    void resize(std::size_t n, char c)
    {
        str_impl.resize(n, c);
    }

    template <typename op_type>
    bool operator<(const op_type& op) const noexcept
    {
        return str_impl < op;
    }

    bool operator<(const alt_string& op) const noexcept
    {
        return str_impl < op.str_impl;
    }

    const char* c_str() const
    {
        return str_impl.c_str();
    }

    char& operator[](std::size_t index)
    {
        return str_impl[index];
    }

    const char& operator[](std::size_t index) const
    {
        return str_impl[index];
    }

    char& back()
    {
        return str_impl.back();
    }

    const char& back() const
    {
        return str_impl.back();
    }

    void clear()
    {
        str_impl.clear();
    }

    const value_type* data() const
    {
        return str_impl.data();
    }

    bool empty() const
    {
        return str_impl.empty();
    }

    std::size_t find(const alt_string& str, std::size_t pos = 0) const
    {
        return str_impl.find(str.str_impl, pos);
    }

    // needed by binary_writer's BSON support, which probes string keys for
    // embedded NUL characters via find(char)
    std::size_t find(char c, std::size_t pos = 0) const
    {
        return str_impl.find(c, pos);
    }

    std::size_t find_first_of(char c, std::size_t pos = 0) const
    {
        return str_impl.find_first_of(c, pos);
    }

    alt_string substr(std::size_t pos = 0, std::size_t count = npos) const
    {
        const std::string s = str_impl.substr(pos, count);
        return {s.data(), s.size()};
    }

    alt_string& replace(std::size_t pos, std::size_t count, const alt_string& str)
    {
        str_impl.replace(pos, count, str.str_impl);
        return *this;
    }

    void reserve(std::size_t new_cap = 0)
    {
        str_impl.reserve(new_cap);
    }

  private:
    std::string str_impl {}; // NOLINT(readability-redundant-member-init)

    friend bool operator<(const char* /*op1*/, const alt_string& /*op2*/) noexcept;
};

void int_to_string(alt_string& target, std::size_t value)
{
    target = std::to_string(value).c_str();
}

using alt_json = nlohmann::basic_json <
                 std::map,
                 std::vector,
                 alt_string,
                 bool,
                 std::int64_t,
                 std::uint64_t,
                 double,
                 std::allocator,
                 nlohmann::adl_serializer >;

bool operator<(const char* op1, const alt_string& op2) noexcept
{
    return op1 < op2.str_impl;
}

namespace
{

// collects the object keys of j, in iteration order
std::vector<std::string> collect_keys(const ordered_json& j)
{
    std::vector<std::string> result;
    for (auto it = j.cbegin(); it != j.cend(); ++it)
    {
        result.push_back(it.key());
    }
    return result;
}

// a nested object/array value with keys inserted in non-alphabetical order,
// used to check both round-trip equality and (for ordered_json) that
// insertion order survives a trip through a binary format
ordered_json make_rich_ordered_json()
{
    ordered_json j;
    j["zebra"] = 1;
    j["apple"] = ordered_json::array({1, 2, 3});
    j["mango"]["z_nested"] = true;
    j["mango"]["a_nested"] = nullptr;
    j["banana"] = "some text";
    j["cherry"] = 3.14;
    return j;
}

alt_json make_rich_alt_json()
{
    alt_json j;
    j["zebra"] = 1;
    j["apple"] = alt_json::array({1, 2, 3});
    j["mango"]["z_nested"] = true;
    j["mango"]["a_nested"] = nullptr;
    j["banana"] = "some text";
    j["cherry"] = 3.14;
    return j;
}

} // namespace

TEST_CASE("ordered_json across binary formats")
{
    const ordered_json original = make_rich_ordered_json();
    const std::vector<std::string> original_keys = collect_keys(original);
    const std::vector<std::string> original_mango_keys = collect_keys(original["mango"]);

    SECTION("CBOR")
    {
        const auto bytes = ordered_json::to_cbor(original);
        const auto restored = ordered_json::from_cbor(bytes);
        CHECK(restored == original);
        CHECK(collect_keys(restored) == original_keys);
        CHECK(collect_keys(restored["mango"]) == original_mango_keys);
    }

    SECTION("MessagePack")
    {
        const auto bytes = ordered_json::to_msgpack(original);
        const auto restored = ordered_json::from_msgpack(bytes);
        CHECK(restored == original);
        CHECK(collect_keys(restored) == original_keys);
        CHECK(collect_keys(restored["mango"]) == original_mango_keys);
    }

    SECTION("UBJSON")
    {
        const auto bytes = ordered_json::to_ubjson(original);
        const auto restored = ordered_json::from_ubjson(bytes);
        CHECK(restored == original);
        CHECK(collect_keys(restored) == original_keys);
        CHECK(collect_keys(restored["mango"]) == original_mango_keys);
    }

    SECTION("BSON")
    {
        const auto bytes = ordered_json::to_bson(original);
        const auto restored = ordered_json::from_bson(bytes);
        CHECK(restored == original);
        CHECK(collect_keys(restored) == original_keys);
        CHECK(collect_keys(restored["mango"]) == original_mango_keys);
    }

    SECTION("BJData")
    {
        const auto bytes = ordered_json::to_bjdata(original);
        const auto restored = ordered_json::from_bjdata(bytes);
        CHECK(restored == original);
        CHECK(collect_keys(restored) == original_keys);
        CHECK(collect_keys(restored["mango"]) == original_mango_keys);
    }
}

TEST_CASE("alt_json (custom string_t) across binary formats")
{
    const alt_json original = make_rich_alt_json();

    SECTION("CBOR")
    {
        const auto bytes = alt_json::to_cbor(original);
        const auto restored = alt_json::from_cbor(bytes);
        CHECK(restored == original);
    }

    SECTION("MessagePack")
    {
        const auto bytes = alt_json::to_msgpack(original);
        const auto restored = alt_json::from_msgpack(bytes);
        CHECK(restored == original);
    }

    SECTION("UBJSON")
    {
        const auto bytes = alt_json::to_ubjson(original);
        const auto restored = alt_json::from_ubjson(bytes);
        CHECK(restored == original);
    }

    SECTION("BSON")
    {
        const auto bytes = alt_json::to_bson(original);
        const auto restored = alt_json::from_bson(bytes);
        CHECK(restored == original);
    }

    SECTION("BJData")
    {
        const auto bytes = alt_json::to_bjdata(original);
        const auto restored = alt_json::from_bjdata(bytes);
        CHECK(restored == original);
    }
}

TEST_CASE("ordered_json operator== is sensitive to key order")
{
    // Unlike nlohmann::json (whose object_t is a std::map, so equality never
    // depends on insertion order), ordered_json's object_t (ordered_map) is a
    // std::vector<std::pair<Key, T>> under the hood, and does not define its
    // own operator==: it inherits std::vector's element-wise comparison. As a
    // result, two ordered_json objects holding the very same key/value pairs
    // in different insertion order compare *unequal*. This is the property
    // that makes the round-trip `CHECK(restored == original)` checks above a
    // meaningful order-preservation check by themselves (the explicit
    // collect_keys() comparisons make that check explicit/readable, and
    // guard against this operator== behavior ever changing).
    ordered_json a;
    a["x"] = 1;
    a["y"] = 2;

    ordered_json b;
    b["y"] = 2;
    b["x"] = 1;

    CHECK(a.size() == b.size());
    CHECK(a["x"] == b["x"]);
    CHECK(a["y"] == b["y"]);
    CHECK_FALSE(a == b);
}

TEST_CASE("duplicate keys in a binary-encoded object")
{
    // CBOR encoding of a map with two entries under the same key "a": {"a": 1, "a": 2}
    const std::vector<std::uint8_t> cbor_bytes
    {
        0xA2, 0x61, 'a', 0x01, 0x61, 'a', 0x02
    };

    // Both json (std::map, via operator[]) and ordered_json (ordered_map, via
    // operator[]) build binary-decoded objects by looking up/creating the
    // entry for each incoming key and then assigning the value into it. This
    // means a repeated key does *not* produce two entries in either case;
    // instead, the *first* occurrence's position is kept (relevant only for
    // ordered_json) while the *last* occurrence's value wins (for both) --
    // this matches operator[]'s "assign the referenced slot" semantics, and
    // is worth noting because it differs from the initializer-list
    // construction path (`ordered_json{{"a",1},{"a",2}}`), which builds
    // through insert()/emplace() and therefore keeps the *first* value, not
    // the last (see the "There are no dup keys..." case in
    // unit-ordered_json.cpp).
    const auto j = json::from_cbor(cbor_bytes);
    const auto oj = ordered_json::from_cbor(cbor_bytes);

    CHECK(j.size() == 1);
    CHECK(oj.size() == 1);
    CHECK(j["a"] == 2);
    CHECK(oj["a"] == 2);
    CHECK(j == json(oj));
}

TEST_CASE("ordered_json through flatten/unflatten")
{
    const ordered_json original = make_rich_ordered_json();
    const std::vector<std::string> original_keys = collect_keys(original);
    const std::vector<std::string> original_mango_keys = collect_keys(original["mango"]);

    const ordered_json flat = original.flatten();
    const ordered_json unflattened = flat.unflatten();

    CHECK(unflattened == original);
    // flatten() walks the value depth-first in iteration order and
    // unflatten() re-inserts each flattened key via operator[] in the flat
    // object's iteration order, so for ordered_json the original key order
    // (both top-level and nested) is preserved end-to-end.
    CHECK(collect_keys(unflattened) == original_keys);
    CHECK(collect_keys(unflattened["mango"]) == original_mango_keys);
}

TEST_CASE("ordered_json through diff/patch/patch_inplace")
{
    ordered_json original;
    original["one"] = 1;
    original["two"] = 2;
    original["three"] = 3;

    ordered_json target = original;
    target["one"] = 100;      // replace
    target.erase("two");      // remove
    target["four"] = 4;       // add

    const ordered_json patch = ordered_json::diff(original, target);

    SECTION("patch")
    {
        const ordered_json patched = original.patch(patch);
        CHECK(patched == target);
    }

    SECTION("patch_inplace")
    {
        ordered_json copy = original;
        copy.patch_inplace(patch);
        CHECK(copy == target);
    }
}

TEST_CASE("ordered_json through merge_patch")
{
    ordered_json original;
    original["a"] = 1;
    original["b"] = 2;

    const ordered_json patch = {{"b", nullptr}, {"c", 3}};

    original.merge_patch(patch);

    ordered_json expected;
    expected["a"] = 1;
    expected["c"] = 3;

    CHECK(original == expected);
    CHECK(collect_keys(original) == collect_keys(expected));
}
