//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-custom-binary-type.cpp (binary types
// whose value type is std::byte). It is kept in a separate translation unit so the (much
// larger) unit-custom-binary-type.cpp is built for C++11 only and not rebuilt for every
// C++ standard.

#include "doctest_compatibility.h"

// capture whether JSON_DISABLE_ENUM_SERIALIZATION was enabled on the command
// line before including json.hpp, which #undefs it; std::byte is an enum, so
// converting std::vector<std::byte> needs enum serialization
#if defined(JSON_DISABLE_ENUM_SERIALIZATION) && (JSON_DISABLE_ENUM_SERIALIZATION == 1)
    #define SKIP_TESTS_FOR_ENUM_SERIALIZATION
#endif

#include <nlohmann/json.hpp>

#ifdef JSON_HAS_CPP_17
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

// a BinaryType whose value type is not an integer type at all
using byte_binary_json = nlohmann::json::with_binary_t<std::vector<std::byte>>;

TEST_CASE("binary type whose value type is not std::uint8_t (C++17)")
{
    SECTION("dumping a value type that is not an integer")
    {
        const std::vector<std::byte> bytes{std::byte{0}, std::byte{1}, std::byte{0xFF}};
        CHECK(byte_binary_json::binary(bytes).dump() == R"({"bytes":[0,1,255],"subtype":null})");
        CHECK(byte_binary_json::binary(bytes, 42).dump() == R"({"bytes":[0,1,255],"subtype":42})");
        CHECK(byte_binary_json::binary({}).dump() == R"({"bytes":[],"subtype":null})");
    }

    SECTION("hashing and the binary formats")
    {
        const std::vector<std::byte> bytes{std::byte{0}, std::byte{1}, std::byte{0xFF}};
        const auto j = byte_binary_json::binary(bytes);

        CHECK(std::hash<byte_binary_json> {}(j) == std::hash<byte_binary_json> {}(j));
        CHECK(byte_binary_json::from_cbor(byte_binary_json::to_cbor(j)) == j);
        CHECK(byte_binary_json::from_msgpack(byte_binary_json::to_msgpack(j)) == j);

        // UBJSON has no binary type, so binary values are written as an array
        CHECK(byte_binary_json::from_ubjson(byte_binary_json::to_ubjson(j)) == byte_binary_json({0, 1, 255}));
        // the same holds for BON8
        CHECK(byte_binary_json::from_bon8(byte_binary_json::to_bon8(j)) == byte_binary_json({0, 1, 255}));
    }
}

// moved from unit-regression3.cpp, so that file does not instantiate a second
// basic_json specialization (MinGW section limit, see windows.yml)
TEST_CASE("std::vector<std::byte> as binary type")
{
    SECTION("issue #4804: from_cbor incompatible with std::vector<std::byte> as binary_t")
    {
        const std::vector<std::uint8_t> data = {0x80};
        const auto decoded = byte_binary_json::from_cbor(data);
        CHECK((decoded == byte_binary_json::array()));
    }

#ifndef SKIP_TESTS_FOR_ENUM_SERIALIZATION
    SECTION("discussion #4209 - custom BinaryType direct assignment and round-tripping")
    {
        // Test that assigning a custom BinaryType directly creates a binary value, not an array
        const std::vector<std::byte> original{std::byte{1}, std::byte{2}, std::byte{3}};
        const byte_binary_json j = original;
        CHECK(j.is_binary());
        CHECK(!j.is_array());

        // Test round-tripping: extracting the binary value back as the custom container type
        const auto extracted = j.get<std::vector<std::byte>>();
        CHECK(extracted == original);

        // Test that the default json alias behavior is unchanged: std::vector<uint8_t> -> array
        const nlohmann::json default_json = std::vector<std::uint8_t> {1, 2, 3};
        CHECK(default_json.is_array());
        CHECK(!default_json.is_binary());
    }

    SECTION("discussion #4209 - custom BinaryType extraction from parsed array")
    {
        // Test that extracting a custom BinaryType from a parsed JSON array still works
        // (not just from a binary-typed node)
        const auto j = byte_binary_json::parse("[1,2,3]");
        CHECK(j.is_array());
        CHECK(!j.is_binary());

        // Extracting as custom BinaryType should work from arrays
        const auto extracted = j.get<std::vector<std::byte>>();
        CHECK(extracted.size() == 3);
        CHECK(extracted[0] == std::byte{1});
        CHECK(extracted[1] == std::byte{2});
        CHECK(extracted[2] == std::byte{3});
    }
#endif
}

#endif
