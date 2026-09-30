//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-msgpack.cpp (std::byte
// input). It is kept in a separate translation unit so the (much larger)
// unit-msgpack.cpp does not need to be compiled and run a second time just
// for this one test case (#5418).

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#ifdef JSON_HAS_CPP_17
#include <cstddef>
#include <vector>

// Test suite for verifying MessagePack handling with std::byte input
TEST_CASE("MessagePack with std::byte")
{

    SECTION("std::byte compatibility")
    {
        SECTION("vector roundtrip")
        {
            json original =
            {
                {"name", "test"},
                {"value", 42},
                {"array", {1, 2, 3}}
            };

            std::vector<uint8_t> temp = json::to_msgpack(original);
            // Convert the uint8_t vector to std::byte vector
            std::vector<std::byte> msgpack_data(temp.size());
            for (size_t i = 0; i < temp.size(); ++i)
            {
                msgpack_data[i] = std::byte(temp[i]);
            }
            // Deserialize from std::byte vector back to JSON
            json from_bytes;
            CHECK_NOTHROW(from_bytes = json::from_msgpack(msgpack_data));

            CHECK(from_bytes == original);
        }

        SECTION("empty vector")
        {
            const std::vector<std::byte> empty_data;
            CHECK_THROWS_WITH_AS([&]()
            {
                [[maybe_unused]] auto result = json::from_msgpack(empty_data);
                return true;
            }
            (),
            "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing MessagePack value: unexpected end of input",
            json::parse_error&);
        }

        SECTION("comparison with workaround")
        {
            json original =
            {
                {"string", "hello"},
                {"integer", 42},
                {"float", 3.14},
                {"boolean", true},
                {"null", nullptr},
                {"array", {1, 2, 3}},
                {"object", {{"key", "value"}}}
            };

            std::vector<uint8_t> temp = json::to_msgpack(original);

            std::vector<std::byte> msgpack_data(temp.size());
            for (size_t i = 0; i < temp.size(); ++i)
            {
                msgpack_data[i] = std::byte(temp[i]);
            }
            // Attempt direct deserialization using std::byte input
            const json direct_result = json::from_msgpack(msgpack_data);

            // Test the workaround approach: reinterpret as unsigned char* and use iterator range
            const auto* const char_start = reinterpret_cast<unsigned char const*>(msgpack_data.data());
            const auto* const char_end = char_start + msgpack_data.size();
            json workaround_result = json::from_msgpack(char_start, char_end);

            // Verify that the final deserialized JSON matches the original JSON
            CHECK(direct_result == workaround_result);
            CHECK(direct_result == original);
        }
    }
}
#endif
