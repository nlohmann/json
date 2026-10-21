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

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// split from unit-large_json.cpp so that both run in parallel and stay below
// the ctest timeout under Valgrind

namespace
{
json nested_array(const std::size_t depth, json leaf)
{
    json j = std::move(leaf);
    for (std::size_t i = 0; i < depth; ++i)
    {
        json a = json::array();
        a.push_back(std::move(j));
        j = std::move(a);
    }
    return j;
}

json nested_object(const std::size_t depth, json leaf)
{
    json j = std::move(leaf);
    for (std::size_t i = 0; i < depth; ++i)
    {
        json o = json::object();
        o["k"] = std::move(j);
        j = std::move(o);
    }
    return j;
}
} // namespace

TEST_CASE("issue #5392 - binary writers on deeply nested values")
{
    // 200 is past the point where the writers stop recursing, and still
    // shallow enough that from_* and operator== (which still recurse) are fine.
    const json deep_array = nested_array(200, json(0));
    const json deep_object = nested_object(200, json("x"));
    const json empty_array = nested_array(200, json::array());
    const json empty_object = nested_object(200, json::object());
    const json mixed = nested_object(80, nested_array(80, json(true)));

    SECTION("roundtrip past the recursion bound")
    {
        CHECK(json::from_cbor(json::to_cbor(deep_array)) == deep_array);
        CHECK(json::from_msgpack(json::to_msgpack(deep_array)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array, true, false)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array, true, true)) == deep_array);
        CHECK(json::from_bjdata(json::to_bjdata(deep_array)) == deep_array);
        CHECK(json::from_bon8(json::to_bon8(deep_array)) == deep_array);

        CHECK(json::from_cbor(json::to_cbor(deep_object)) == deep_object);
        CHECK(json::from_msgpack(json::to_msgpack(deep_object)) == deep_object);
        CHECK(json::from_ubjson(json::to_ubjson(deep_object)) == deep_object);
        CHECK(json::from_ubjson(json::to_ubjson(deep_object, true, true)) == deep_object);
        CHECK(json::from_bjdata(json::to_bjdata(deep_object)) == deep_object);
        CHECK(json::from_bon8(json::to_bon8(deep_object)) == deep_object);

        CHECK(json::from_cbor(json::to_cbor(empty_array)) == empty_array);
        CHECK(json::from_msgpack(json::to_msgpack(empty_array)) == empty_array);
        CHECK(json::from_ubjson(json::to_ubjson(empty_array)) == empty_array);
        CHECK(json::from_ubjson(json::to_ubjson(empty_array, true, true)) == empty_array);
        CHECK(json::from_bon8(json::to_bon8(empty_array)) == empty_array);

        CHECK(json::from_cbor(json::to_cbor(empty_object)) == empty_object);
        CHECK(json::from_msgpack(json::to_msgpack(empty_object)) == empty_object);
        CHECK(json::from_ubjson(json::to_ubjson(empty_object)) == empty_object);
        CHECK(json::from_bon8(json::to_bon8(empty_object)) == empty_object);

        CHECK(json::from_cbor(json::to_cbor(mixed)) == mixed);
        CHECK(json::from_msgpack(json::to_msgpack(mixed)) == mixed);
        CHECK(json::from_ubjson(json::to_ubjson(mixed)) == mixed);
        CHECK(json::from_bjdata(json::to_bjdata(mixed)) == mixed);
        CHECK(json::from_bon8(json::to_bon8(mixed)) == mixed);
    }

    SECTION("the two ways of writing a value meet at the bound")
    {
        for (std::size_t depth = 120; depth <= 140; ++depth)
        {
            CAPTURE(depth)

            const json array = nested_array(depth, json(7));
            CHECK(json::from_cbor(json::to_cbor(array)) == array);
            CHECK(json::from_msgpack(json::to_msgpack(array)) == array);
            CHECK(json::from_ubjson(json::to_ubjson(array, true, true)) == array);
            CHECK(json::from_bon8(json::to_bon8(array)) == array);

            const json object = nested_object(depth, json(7));
            CHECK(json::from_cbor(json::to_cbor(object)) == object);
            CHECK(json::from_msgpack(json::to_msgpack(object)) == object);
            CHECK(json::from_bjdata(json::to_bjdata(object)) == object);
            CHECK(json::from_bon8(json::to_bon8(object)) == object);
        }
    }

    SECTION("a BJData ndarray below the bound is still an ndarray")
    {
        const json ndarray = json({{"_ArrayType_", "uint8"}, {"_ArraySize_", {2, 3}}, {"_ArrayData_", {1, 2, 3, 4, 5, 6}}});
        const json invalid = json({{"_ArrayType_", "nope"}, {"_ArraySize_", {1}}, {"_ArrayData_", {1}}});

        const json deep_ndarray = nested_array(140, ndarray);
        const json deep_invalid = nested_array(140, invalid);

        CHECK(json::from_bjdata(json::to_bjdata(deep_ndarray)) == deep_ndarray);
        CHECK(json::from_bjdata(json::to_bjdata(deep_invalid)) == deep_invalid);
        CHECK(json::from_bjdata(json::to_bjdata(ndarray)) == ndarray);
    }

    SECTION("byte-exact across the switch-over")
    {
        // nested one-element arrays around the recursion bound: the exact
        // bytes a writer produces do not depend on whether it stayed on the
        // call stack or moved to the heap one partway through
        for (const std::size_t depth :
                {
                    nlohmann::detail::recursion_depth_limit() - 1, nlohmann::detail::recursion_depth_limit(),
                    nlohmann::detail::recursion_depth_limit() + 1, nlohmann::detail::recursion_depth_limit() + 2
                })
        {
            CAPTURE(depth)
            const json array = nested_array(depth, json(0));

            std::vector<std::uint8_t> expected_cbor(depth, 0x81);
            expected_cbor.push_back(0x00);
            CHECK(json::to_cbor(array) == expected_cbor);

            std::vector<std::uint8_t> expected_msgpack(depth, 0x91);
            expected_msgpack.push_back(0x00);
            CHECK(json::to_msgpack(array) == expected_msgpack);

            std::string expected_ubjson(depth, '[');
            expected_ubjson += "i";
            expected_ubjson += '\0';
            expected_ubjson.append(depth, ']');
            const auto packed_ubjson = json::to_ubjson(array);
            CHECK(std::string(packed_ubjson.begin(), packed_ubjson.end()) == expected_ubjson);

            std::vector<std::uint8_t> expected_bon8(depth, 0x81);
            expected_bon8.push_back(0x90);
            CHECK(json::to_bon8(array) == expected_bon8);
        }
    }

    SECTION("a deep object, and a BJData ndarray, past the recursion bound")
    {
        const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 50;

        const json object = nested_object(depth, json(42));
        CHECK(json::from_cbor(json::to_cbor(object)) == object);
        CHECK(json::from_msgpack(json::to_msgpack(object)) == object);
        CHECK(json::from_ubjson(json::to_ubjson(object, true, true)) == object);
        CHECK(json::from_bjdata(json::to_bjdata(object)) == object);
        CHECK(json::from_bon8(json::to_bon8(object)) == object);

        const json ndarray = json({{"_ArrayType_", "uint8"}, {"_ArraySize_", {2, 3}}, {"_ArrayData_", {1, 2, 3, 4, 5, 6}}});
        const json deep_ndarray = nested_array(depth, ndarray);
        CHECK(json::from_bjdata(json::to_bjdata(deep_ndarray)) == deep_ndarray);
    }

    SECTION("a discarded value past the recursion bound still throws type_error.321")
    {
        const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 50;
        const json discarded_leaf(json::value_t::discarded);
        const json deep_discarded = nested_array(depth, discarded_leaf);

        // with diagnostics, the message names the path to the discarded leaf
#if JSON_DIAGNOSTICS
        std::string path;
        for (std::size_t i = 0; i < depth; ++i)
        {
            path += "/0";
        }
        const std::string prefix = "[json.exception.type_error.321] (" + path + ") ";
#else
        const std::string prefix = "[json.exception.type_error.321] ";
#endif

        CHECK_THROWS_WITH_AS(json::to_cbor(deep_discarded), (prefix + "cannot serialize discarded value to CBOR").c_str(), json::type_error);
        CHECK_THROWS_WITH_AS(json::to_msgpack(deep_discarded), (prefix + "cannot serialize discarded value to MessagePack").c_str(), json::type_error);
        CHECK_THROWS_WITH_AS(json::to_ubjson(deep_discarded), (prefix + "cannot serialize discarded value to UBJSON").c_str(), json::type_error);
        CHECK_THROWS_WITH_AS(json::to_bjdata(deep_discarded), (prefix + "cannot serialize discarded value to BJData").c_str(), json::type_error);
    }

    SECTION("BON8 past the recursion bound: discarded values and errors")
    {
        const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 50;

        // BON8 rejects a discarded value (type_error.321), deep or not
        const json deep_discarded = nested_array(depth, json(json::value_t::discarded));
        CHECK_THROWS_AS(json::to_bon8(deep_discarded), json::type_error);

        // errors are thrown from below the bound as from above it
        const json deep_invalid_string = nested_array(depth, json(std::string("\x80")));
        CHECK_THROWS_AS(json::to_bon8(deep_invalid_string), json::type_error);

        json deep_invalid_key = json::object();
        deep_invalid_key[std::string("\x80")] = 1;
        deep_invalid_key = nested_object(depth, deep_invalid_key);
        CHECK_THROWS_AS(json::to_bon8(deep_invalid_key), json::type_error);

        const json deep_too_large = nested_array(depth, json(9223372036854775808u));
        CHECK_THROWS_AS(json::to_bon8(deep_too_large), json::out_of_range);
    }

    SECTION("does not overflow the C++ stack")
    {
        const std::size_t depth = 100000;
        const json j = json::parse(std::string(depth, '[') + "0" + std::string(depth, ']'));

        std::vector<std::uint8_t> packed;
        CHECK_NOTHROW(packed = json::to_cbor(j));
        CHECK(json::from_cbor(packed) == j);

        CHECK_NOTHROW(packed = json::to_msgpack(j));
        CHECK(json::from_msgpack(packed) == j);

        CHECK_NOTHROW(packed = json::to_ubjson(j));
        CHECK(json::from_ubjson(packed) == j);

        CHECK_NOTHROW(packed = json::to_ubjson(j, true, false));
        CHECK(json::from_ubjson(packed) == j);

        CHECK_NOTHROW(packed = json::to_bjdata(j));
        CHECK(json::from_bjdata(packed) == j);

        CHECK_NOTHROW(packed = json::to_bon8(j));
        CHECK(json::from_bon8(packed) == j);
    }

    SECTION("BON8 containers with more than four elements past the recursion bound")
    {
        // such containers are closed with 0xFE, which the iterative writer
        // must emit when it leaves them; strings next to each other must
        // still be separated with 0xFF
        const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 50;
        json wide_array = json::array({1, "a", "b", json::array(), 5});
        json wide_object = json({{"k1", "v"}, {"k2", 2}, {"k3", ""}, {"k4", json::object()}, {"k5", nullptr}});
        for (std::size_t i = 0; i < depth; ++i)
        {
            wide_array = json::array({"s", wide_array, "t", wide_object, true});
            wide_object = json({{"a", wide_object}, {"b", "x"}, {"c", "y"}, {"d", wide_array.size()}, {"e", "z"}});
        }

        CHECK(json::from_bon8(json::to_bon8(wide_array)) == wide_array);
        CHECK(json::from_bon8(json::to_bon8(wide_object)) == wide_object);
    }

    SECTION("regression test for https://issues.oss-fuzz.com/issues/566583014")
    {
        // 200000 nested one-element CBOR arrays, the innermost holding null;
        // round-tripping this used to recurse once per level on the way back
        // out through to_cbor(), deep enough to overflow the stack
        std::vector<std::uint8_t> v(200000, 0x81);
        v.push_back(0xf6);
        const json j = json::from_cbor(v);
        CHECK(json::to_cbor(j) == v);

        // the MessagePack analogue: fixarray of 1 nesting down to nil
        std::vector<std::uint8_t> v_msgpack(200000, 0x91);
        v_msgpack.push_back(0xc0);
        const json j_msgpack = json::from_msgpack(v_msgpack);
        CHECK(json::to_msgpack(j_msgpack) == v_msgpack);
    }

    SECTION("regression test for https://issues.oss-fuzz.com/issues/572238015")
    {
        // the BON8 analogue: 200000 nested one-element arrays down to null
        std::vector<std::uint8_t> v(200000, 0x81);
        v.push_back(0xFA);
        const json j = json::from_bon8(v);
        CHECK(json::to_bon8(j) == v);
    }
}

