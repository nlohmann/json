//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// capture whether JSON_DISABLE_ENUM_SERIALIZATION was enabled on the command
// line before including json.hpp, which #undefs it; std::byte is an enum, so
// converting std::vector<std::byte> needs enum serialization
#if defined(JSON_DISABLE_ENUM_SERIALIZATION) && (JSON_DISABLE_ENUM_SERIALIZATION == 1)
    #define SKIP_TESTS_FOR_ENUM_SERIALIZATION
#endif

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#ifdef JSON_HAS_CPP_17
    #include <cstddef>
#endif

namespace
{

// a BinaryType whose value type is signed: the elements must still be
// processed as the numbers 0..255
using char_binary_json = nlohmann::json::with_binary_t<std::vector<char>>;

#ifdef JSON_HAS_CPP_17
    // a BinaryType whose value type is not an integer type at all
    using byte_binary_json = nlohmann::json::with_binary_t<std::vector<std::byte>>;
#endif

} // namespace

TEST_CASE("binary type whose value type is not std::uint8_t")
{
    SECTION("a signed value type does not dump negative numbers")
    {
        const std::vector<char> chars{'\0', '\x01', '\xFF'};
        CHECK(char_binary_json::binary(chars).dump() == R"({"bytes":[0,1,255],"subtype":null})");
        CHECK(char_binary_json::binary(chars, 42).dump() == R"({"bytes":[0,1,255],"subtype":42})");
        CHECK(char_binary_json::binary({}).dump() == R"({"bytes":[],"subtype":null})");
    }

    SECTION("a value is converted to the binary type if it is binary or an array")
    {
        const std::vector<char> chars{'\0', '\x01', '\x7F'};
        CHECK(char_binary_json::binary(chars).get<std::vector<char>>() == chars);
        CHECK(char_binary_json({0, 1, 127}).get<std::vector<char>>() == chars);
        CHECK_THROWS_WITH_AS(char_binary_json(1).get<std::vector<char>>(),
                             "[json.exception.type_error.302] type must be binary or array, but is number",
                             char_binary_json::type_error&);
    }

    SECTION("the default binary type is unchanged")
    {
        CHECK(nlohmann::json::binary({0, 1, 255}, 42).dump() == R"({"bytes":[0,1,255],"subtype":42})");
    }

#ifdef JSON_HAS_CPP_17
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
#endif
}

#ifdef JSON_HAS_CPP_17
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
