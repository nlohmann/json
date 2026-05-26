//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
#include <nlohmann/eval.hpp>
using nlohmann::json;

#include <string>

// Tests for null-safe, noexcept accessors:
//   eval_value(j, key | ptr, default)
//   eval_array(j, key | ptr)
//   eval_object(j, key | ptr)
//
// See https://github.com/nlohmann/json/discussions/5129.
//
// NOTE on style: when calling reference-returning helpers (eval_array,
// eval_object), the key (std::string) and json_pointer arguments are kept in
// named local variables on purpose -- this matches the recommended user
// style and avoids GCC's -Wdangling-reference warning that triggers when a
// function returning a reference takes a parameter bound to a temporary
// (the warning is a false positive here, but worth modelling correctly).

TEST_CASE("eval_value with key")
{
    SECTION("happy path: object with matching key and type")
    {
        const json j = {{"a", 42}, {"s", "hello"}};
        CHECK(nlohmann::eval_value(j, "a", 0) == 42);
        CHECK(nlohmann::eval_value(j, "s", std::string{"x"}) == "hello");
    }

    SECTION("missing key returns default")
    {
        const json j = {{"a", 1}};
        CHECK(nlohmann::eval_value(j, "missing", 7) == 7);
        CHECK(nlohmann::eval_value(j, "missing", std::string{"def"}) == "def");
    }

    SECTION("null value at key returns default")
    {
        const json j = {{"a", nullptr}};
        CHECK(nlohmann::eval_value(j, "a", 99) == 99);
    }

    SECTION("wrong type at key returns default")
    {
        const json j = {{"a", "not a number"}};
        CHECK(nlohmann::eval_value(j, "a", 5) == 5);
    }

    SECTION("non-object receiver returns default")
    {
        const json null_j = nullptr;
        const json arr_j  = json::array({1, 2, 3});
        const json str_j  = "hello";
        const json num_j  = 42;
        const json bool_j = true;

        CHECK(nlohmann::eval_value(null_j, "a", 1) == 1);
        CHECK(nlohmann::eval_value(arr_j,  "a", 1) == 1);
        CHECK(nlohmann::eval_value(str_j,  "a", 1) == 1);
        CHECK(nlohmann::eval_value(num_j,  "a", 1) == 1);
        CHECK(nlohmann::eval_value(bool_j, "a", 1) == 1);
    }

    SECTION("noexcept")
    {
        const json j = {{"a", 1}};
        const json::object_t::key_type key = "a";
        const int def = 0;
        // Pre-construct the arguments so noexcept(...) measures eval_value
        // itself, not the (possibly throwing) construction of std::string
        // / int from the literal arguments.
        CHECK(noexcept(nlohmann::eval_value(j, key, def)));
    }
}

TEST_CASE("eval_value with JSON Pointer")
{
    SECTION("happy path: nested object")
    {
        const json j = {{"c", {{"d", "deep"}}}};
        const auto ptr = json::json_pointer("/c/d");
        CHECK(nlohmann::eval_value(j, ptr, std::string{}) == "deep");
    }

    SECTION("unresolvable pointer returns default")
    {
        const json j = {{"c", {{"d", "deep"}}}};
        const auto p1 = json::json_pointer("/c/missing");
        const auto p2 = json::json_pointer("/x/y/z");
        CHECK(nlohmann::eval_value(j, p1, std::string{"def"}) == "def");
        CHECK(nlohmann::eval_value(j, p2, std::string{"def"}) == "def");
    }

    SECTION("null intermediate or null resolved value returns default")
    {
        const json j1 = {{"c", nullptr}};
        const auto pcd = json::json_pointer("/c/d");
        // /c is null -> walking to /c/d is unresolvable -> default
        CHECK(nlohmann::eval_value(j1, pcd, std::string{"def"}) == "def");

        const json j2 = {{"c", {{"d", nullptr}}}};
        CHECK(nlohmann::eval_value(j2, pcd, std::string{"def"}) == "def");
    }

    SECTION("wrong resolved type returns default")
    {
        const json j = {{"a", "not a number"}};
        const auto pa = json::json_pointer("/a");
        CHECK(nlohmann::eval_value(j, pa, 5) == 5);
    }

    SECTION("non-object receiver returns default")
    {
        const json null_j = nullptr;
        const json arr_j  = json::array({1, 2, 3});
        const auto pa = json::json_pointer("/a");
        const auto p0 = json::json_pointer("/0");

        CHECK(nlohmann::eval_value(null_j, pa, 7) == 7);
        CHECK(nlohmann::eval_value(arr_j,  p0, 7) == 7);
    }

    SECTION("noexcept")
    {
        const json j = {{"a", 1}};
        const auto ptr = json::json_pointer("/a");
        CHECK(noexcept(nlohmann::eval_value(j, ptr, 0)));
    }
}

TEST_CASE("eval_array with key")
{
    // Keep the key alive in a named variable: eval_array returns a
    // reference, so binding it to `const auto&` while passing a temporary
    // std::string for the key would otherwise trip GCC's
    // -Wdangling-reference (false positive here, but worth modelling).
    const json::object_t::key_type k_items   = "items";
    const json::object_t::key_type k_missing = "missing";
    const json::object_t::key_type k_x       = "x";
    const json::object_t::key_type k_y       = "y";

    SECTION("happy path: returns const reference to array")
    {
        const json j = {{"items", {1, 2, 3}}};
        const auto& arr = nlohmann::eval_array(j, k_items);
        REQUIRE(arr.is_array());
        CHECK(arr.size() == 3);
        CHECK(arr[0] == 1);
        CHECK(arr[2] == 3);
    }

    SECTION("range-based for loop is safe")
    {
        const json j = {{"items", {10, 20, 30}}};
        int sum = 0;
        const auto& arr = nlohmann::eval_array(j, k_items);
        for (const auto& item : arr)
        {
            sum += item.template get<int>();
        }
        CHECK(sum == 60);
    }

    SECTION("missing key returns empty array")
    {
        const json j = {{"a", 1}};
        const auto& arr = nlohmann::eval_array(j, k_missing);
        REQUIRE(arr.is_array());
        CHECK(arr.empty());
    }

    SECTION("wrong type at key returns empty array")
    {
        const json j = {{"items", "not an array"}};
        const auto& arr = nlohmann::eval_array(j, k_items);
        REQUIRE(arr.is_array());
        CHECK(arr.empty());
    }

    SECTION("non-object receiver returns empty array")
    {
        const json null_j = nullptr;
        const json arr_j  = json::array({1, 2, 3});
        const json num_j  = 42;

        const auto& a1 = nlohmann::eval_array(null_j, k_items);
        const auto& a2 = nlohmann::eval_array(arr_j,  k_items);
        const auto& a3 = nlohmann::eval_array(num_j,  k_items);

        CHECK(a1.is_array());
        CHECK(a1.empty());
        CHECK(a2.is_array());
        CHECK(a2.empty());
        CHECK(a3.is_array());
        CHECK(a3.empty());
    }

    SECTION("static empty array reference is stable")
    {
        const json j = {{"a", 1}};
        const auto& a = nlohmann::eval_array(j, k_x);
        const auto& b = nlohmann::eval_array(j, k_y);
        // Both should reference the same static singleton.
        CHECK(&a == &b);
    }

    SECTION("noexcept")
    {
        const json j = {{"items", json::array()}};
        CHECK(noexcept(nlohmann::eval_array(j, k_items)));
    }
}

TEST_CASE("eval_array with JSON Pointer")
{
    const auto p_entries = json::json_pointer("/response/data/entries");
    const auto p_xyz     = json::json_pointer("/x/y/z");
    const auto p_x       = json::json_pointer("/x");
    const auto p_a       = json::json_pointer("/a");

    SECTION("happy path: nested array")
    {
        const json j = {{"response", {{"data", {{"entries", {1, 2, 3}}}}}}};
        const auto& arr = nlohmann::eval_array(j, p_entries);
        REQUIRE(arr.is_array());
        CHECK(arr.size() == 3);
    }

    SECTION("unresolvable pointer returns empty array")
    {
        const json j = {{"a", 1}};
        const auto& arr = nlohmann::eval_array(j, p_xyz);
        REQUIRE(arr.is_array());
        CHECK(arr.empty());
    }

    SECTION("wrong resolved type returns empty array")
    {
        const json j = {{"x", "not an array"}};
        const auto& arr = nlohmann::eval_array(j, p_x);
        REQUIRE(arr.is_array());
        CHECK(arr.empty());
    }

    SECTION("non-object receiver returns empty array")
    {
        const json null_j = nullptr;
        const auto& arr = nlohmann::eval_array(null_j, p_a);
        CHECK(arr.is_array());
        CHECK(arr.empty());
    }

    SECTION("noexcept")
    {
        const json j = {{"a", json::array()}};
        CHECK(noexcept(nlohmann::eval_array(j, p_a)));
    }
}

TEST_CASE("eval_object with key")
{
    const json::object_t::key_type k_meta    = "meta";
    const json::object_t::key_type k_missing = "missing";
    const json::object_t::key_type k_x       = "x";
    const json::object_t::key_type k_y       = "y";

    SECTION("happy path: returns const reference to object")
    {
        const json j = {{"meta", {{"k", 1}, {"v", 2}}}};
        const auto& obj = nlohmann::eval_object(j, k_meta);
        REQUIRE(obj.is_object());
        CHECK(obj.size() == 2);
        CHECK(obj.at("k") == 1);
    }

    SECTION("range-based for over items() is safe")
    {
        const json j = {{"meta", {{"a", 1}, {"b", 2}}}};
        int count = 0;
        const auto& obj = nlohmann::eval_object(j, k_meta);
        for (const auto& kv : obj.items())
        {
            (void)kv;
            ++count;
        }
        CHECK(count == 2);
    }

    SECTION("missing key returns empty object")
    {
        const json j = {{"a", 1}};
        const auto& obj = nlohmann::eval_object(j, k_missing);
        REQUIRE(obj.is_object());
        CHECK(obj.empty());
    }

    SECTION("wrong type at key returns empty object")
    {
        const json j = {{"meta", "not an object"}};
        const auto& obj = nlohmann::eval_object(j, k_meta);
        REQUIRE(obj.is_object());
        CHECK(obj.empty());
    }

    SECTION("non-object receiver returns empty object")
    {
        const json null_j = nullptr;
        const json arr_j  = json::array({1, 2, 3});

        const auto& o1 = nlohmann::eval_object(null_j, k_meta);
        const auto& o2 = nlohmann::eval_object(arr_j,  k_meta);

        CHECK(o1.is_object());
        CHECK(o1.empty());
        CHECK(o2.is_object());
        CHECK(o2.empty());
    }

    SECTION("static empty object reference is stable")
    {
        const json j = {{"a", 1}};
        const auto& a = nlohmann::eval_object(j, k_x);
        const auto& b = nlohmann::eval_object(j, k_y);
        CHECK(&a == &b);
    }

    SECTION("array vs object empty singletons differ")
    {
        const json j = {{"a", 1}};
        const auto& arr = nlohmann::eval_array(j, k_x);
        const auto& obj = nlohmann::eval_object(j, k_x);
        CHECK(arr.is_array());
        CHECK(obj.is_object());
    }

    SECTION("noexcept")
    {
        const json j = {{"meta", json::object()}};
        CHECK(noexcept(nlohmann::eval_object(j, k_meta)));
    }
}

TEST_CASE("eval_object with JSON Pointer")
{
    const auto p_cd  = json::json_pointer("/c/d");
    const auto p_xyz = json::json_pointer("/x/y/z");
    const auto p_x   = json::json_pointer("/x");
    const auto p_a   = json::json_pointer("/a");

    SECTION("happy path: nested object")
    {
        const json j = {{"c", {{"d", {{"e", 1}}}}}};
        const auto& obj = nlohmann::eval_object(j, p_cd);
        REQUIRE(obj.is_object());
        CHECK(obj.at("e") == 1);
    }

    SECTION("unresolvable pointer returns empty object")
    {
        const json j = {{"a", 1}};
        const auto& obj = nlohmann::eval_object(j, p_xyz);
        REQUIRE(obj.is_object());
        CHECK(obj.empty());
    }

    SECTION("wrong resolved type returns empty object")
    {
        const json j = {{"x", json::array({1, 2})}};
        const auto& obj = nlohmann::eval_object(j, p_x);
        REQUIRE(obj.is_object());
        CHECK(obj.empty());
    }

    SECTION("non-object receiver returns empty object")
    {
        const json null_j = nullptr;
        const auto& obj = nlohmann::eval_object(null_j, p_a);
        CHECK(obj.is_object());
        CHECK(obj.empty());
    }

    SECTION("noexcept")
    {
        const json j = {{"a", json::object()}};
        CHECK(noexcept(nlohmann::eval_object(j, p_a)));
    }
}

TEST_CASE("eval functions end-to-end scenario from discussion 5129")
{
    SECTION("safe access on a possibly-null payload")
    {
        // Simulate `auto received = from_server();` with a null payload.
        const json received = nullptr;

        const auto p_cd = json::json_pointer("/c/d");
        const int  a    = nlohmann::eval_value(received, "a", 0);
        const auto d    = nlohmann::eval_value(received, p_cd, std::string{});

        CHECK(a == 0);
        CHECK(d.empty());

        // Range-based for is still safe on a null receiver.
        const json::object_t::key_type k_items = "items";
        const auto& items = nlohmann::eval_array(received, k_items);
        int count = 0;
        for (const auto& item : items)
        {
            (void)item;
            ++count;
        }
        CHECK(count == 0);
    }

    SECTION("safe access on a partial payload")
    {
        const json received = {{"a", 5}};  // no "c", no "items"
        const auto p_cd = json::json_pointer("/c/d");
        const json::object_t::key_type k_items = "items";

        CHECK(nlohmann::eval_value(received, "a", 0) == 5);
        CHECK(nlohmann::eval_value(received, p_cd, std::string{"fallback"}) == "fallback");
        CHECK(nlohmann::eval_array(received, k_items).empty());
    }

    SECTION("ADL works without explicit namespace qualification")
    {
        const json j = {{"a", 7}};
        // ADL: argument-dependent lookup finds nlohmann::eval_value via `j`.
        CHECK(eval_value(j, "a", 0) == 7);
    }
}
