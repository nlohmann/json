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
using byte_binary_json = nlohmann::basic_json <
                         std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t,
                         double, std::allocator, nlohmann::adl_serializer, std::vector<std::byte>, void >;

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

#endif
