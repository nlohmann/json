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

namespace
{

// a BinaryType whose value type is signed: the elements must still be
// processed as the numbers 0..255
using char_binary_json = nlohmann::basic_json <
                         std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t,
                         double, std::allocator, nlohmann::adl_serializer, std::vector<char>, void >;

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
}
