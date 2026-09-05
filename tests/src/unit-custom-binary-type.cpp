//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

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
using char_binary_json = nlohmann::basic_json <
                         std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t,
                         double, std::allocator, nlohmann::adl_serializer, std::vector<char>, void >;

#ifdef JSON_HAS_CPP_17
    // a BinaryType whose value type is not an integer type at all
    using byte_binary_json = nlohmann::basic_json <
    std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t,
    double, std::allocator, nlohmann::adl_serializer, std::vector<std::byte>, void >;
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
    }
#endif
}
