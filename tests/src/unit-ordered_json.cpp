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

TEST_CASE("ordered_json binary formats preserve insertion order")
{
    ordered_json oj;
    oj["z"] = 1;
    oj["a"] = 2;
    oj["m"] = 3;

    SECTION("CBOR")
    {
        const auto packed = ordered_json::to_cbor(oj);
        const auto back = ordered_json::from_cbor(packed);
        CHECK(back.dump() == "{\"z\":1,\"a\":2,\"m\":3}");
    }

    SECTION("MessagePack")
    {
        const auto packed = ordered_json::to_msgpack(oj);
        const auto back = ordered_json::from_msgpack(packed);
        CHECK(back.dump() == "{\"z\":1,\"a\":2,\"m\":3}");
    }

    SECTION("BSON")
    {
        const auto packed = ordered_json::to_bson(oj);
        const auto back = ordered_json::from_bson(packed);
        CHECK(back.dump() == "{\"z\":1,\"a\":2,\"m\":3}");
    }

    SECTION("UBJSON")
    {
        const auto packed = ordered_json::to_ubjson(oj);
        const auto back = ordered_json::from_ubjson(packed);
        CHECK(back.dump() == "{\"z\":1,\"a\":2,\"m\":3}");
    }
}

TEST_CASE("ordered_json flatten, unflatten, and patch")
{
    ordered_json oj;
    oj["z"] = {{"b", 1}};
    oj["a"] = 2;

    SECTION("flatten/unflatten keep object key order")
    {
        const auto flat = oj.flatten();
        CHECK(flat.dump() == "{\"/z/b\":1,\"/a\":2}");
        CHECK(flat.unflatten().dump() == oj.dump());
    }

    SECTION("diff/patch round-trip")
    {
        ordered_json other = oj;
        other["a"] = 9;
        const auto patch = ordered_json::diff(oj, other);
        CHECK(oj.patch(patch) == other);

        ordered_json inplace = oj;
        inplace.patch_inplace(patch);
        CHECK(inplace == other);
    }

    SECTION("update merge_objects=true recurses into objects")
    {
        ordered_json target;
        target["z"] = {{"b", 1}, {"c", 2}};
        target["a"] = 3;
        ordered_json source;
        source["z"] = {{"c", 9}, {"d", 4}};
        target.update(source, true);
        CHECK(target["z"]["b"] == 1);
        CHECK(target["z"]["c"] == 9);
        CHECK(target["z"]["d"] == 4);
        CHECK(target["a"] == 3);
        CHECK(target.dump() == "{\"z\":{\"b\":1,\"c\":9,\"d\":4},\"a\":3}");
    }
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
