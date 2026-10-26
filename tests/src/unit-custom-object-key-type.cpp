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
#include <string>
#include <utility>

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
