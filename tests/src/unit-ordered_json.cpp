//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;
using nlohmann::ordered_json;

TEST_CASE("ordered_json")
{
    json j;
    ordered_json oj;

    j["element3"] = 3;
    j["element1"] = 1;
    j["element2"] = 2;

    oj["element3"] = 3;
    oj["element1"] = 1;
    oj["element2"] = 2;

    CHECK(j.dump() == "{\"element1\":1,\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element1\":1,\"element2\":2}");

    CHECK(j == json(oj));
    CHECK(ordered_json(json(oj)) == ordered_json(j));

    j.erase("element1");
    oj.erase("element1");

    CHECK(j.dump() == "{\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element2\":2}");

    // remove again and nothing changes
    j.erase("element1");
    oj.erase("element1");

    CHECK(j.dump() == "{\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element2\":2}");

    // There are no dup keys cause constructor calls emplace...
    json const multi {{"z", 1}, {"m", 2}, {"m", 3}, {"y", 4}, {"m", 5}};
    CHECK(multi.size() == 3);
    CHECK(multi.dump() == "{\"m\":2,\"y\":4,\"z\":1}");

    ordered_json multi_ordered {{"z", 1}, {"m", 2}, {"m", 3}, {"y", 4}, {"m", 5}};
    CHECK(multi_ordered.size() == 3);
    CHECK(multi_ordered.dump() == "{\"z\":1,\"m\":2,\"y\":4}");
    CHECK(multi_ordered.erase("m") == 1);
    CHECK(multi_ordered.dump() == "{\"z\":1,\"y\":4}");

    // Ranged insert test.
    // It seems that values shouldn't be overwritten. Only new values are added
    json j1 {{"c", 1}, {"b", 2}, {"a", 3}};
    const json j2 {{"c", 77}, {"d", 42}, {"a", 4}};
    j1.insert( j2.cbegin(), j2.cend() );
    CHECK(j1.size() == 4);
    CHECK(j1.dump() == "{\"a\":3,\"b\":2,\"c\":1,\"d\":42}");

    ordered_json oj1 {{"c", 1}, {"b", 2}, {"a", 3}};
    const ordered_json oj2 {{"c", 77}, {"d", 42}, {"a", 4}};
    oj1.insert( oj2.cbegin(), oj2.cend() );
    CHECK(oj1.size() == 4);
    CHECK(oj1.dump() == "{\"c\":1,\"b\":2,\"a\":3,\"d\":42}");
}

TEST_CASE("regression test for issue #3732 - iteration_proxy_value<iter_impl<ordered_json>>")
{
    // Naming the proxy type in a function-parameter position forces eager
    // instantiation of basic_json<ordered_map>; previously this hit an
    // incomplete-type error in set_parents().
    auto fn = [](nlohmann::detail::iteration_proxy_value<nlohmann::detail::iter_impl<nlohmann::ordered_json>> const & val)
    {
        return val.value();
    };
    static_cast<void>(fn);
}

TEST_CASE("regression test - diff() must account for ordered_json member order")
{
    SECTION("pure reorder, no value changes")
    {
        ordered_json a = {{"a", 1}, {"b", 2}};
        ordered_json b = {{"b", 2}, {"a", 1}};
        CHECK(a != b); // order-sensitive equality
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("new key must land at the front")
    {
        ordered_json c = {{"b", 2}};
        ordered_json e = {{"a", 1}, {"b", 2}};
        CHECK(c.patch(ordered_json::diff(c, e)) == e);
    }

    SECTION("reorder plus a value change on one of the reordered keys")
    {
        ordered_json a = {{"a", 1}, {"b", 2}};
        ordered_json b = {{"b", 20}, {"a", 1}};
        CHECK(a != b);
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("reorder plus a deleted key")
    {
        ordered_json a = {{"a", 1}, {"b", 2}, {"c", 3}};
        ordered_json b = {{"b", 2}, {"a", 1}};
        CHECK(a != b);
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("reorder plus a nested value that itself needs a recursive diff")
    {
        ordered_json a = {{"a", {{"x", 1}, {"y", 2}}}, {"b", 2}};
        ordered_json b = {{"b", 2}, {"a", {{"x", 1}, {"y", 99}}}};
        CHECK(a != b);
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("three or more keys shuffled into a different order")
    {
        ordered_json a = {{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}};
        ordered_json b = {{"d", 4}, {"b", 2}, {"a", 1}, {"c", 3}};
        CHECK(a != b);
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("matching order still produces a minimal patch (fast path unaffected)")
    {
        ordered_json a = {{"a", 1}, {"b", 2}, {"c", 3}};
        ordered_json b = {{"a", 1}, {"b", 20}, {"c", 3}};
        auto p = ordered_json::diff(a, b);
        // only the changed value should be touched, not a wholesale remove+add
        CHECK(p.size() == 1);
        CHECK(p[0]["op"] == "replace");
        CHECK(p[0]["path"] == "/b");
        CHECK(a.patch(p) == b);
    }

    SECTION("plain json (std::map-backed) is unaffected by same-key-different-insertion-order")
    {
        json a;
        a["b"] = 2;
        a["a"] = 1;

        json b;
        b["a"] = 1;
        b["b"] = 2;

        // std::map iteration is always sorted by key, so a == b regardless of
        // insertion order, and diff() must still produce the same minimal
        // (empty) result as before this fix
        CHECK(a == b);
        auto p = json::diff(a, b);
        CHECK(p.empty());
        CHECK(a.patch(p) == b);
    }
}
