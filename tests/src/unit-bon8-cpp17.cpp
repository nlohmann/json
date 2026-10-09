//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-bon8.cpp (BON8 with std::byte
// containers). It is kept in a separate translation unit so the (much larger) unit-
// bon8.cpp is built for C++11 only and not rebuilt for every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#ifdef JSON_HAS_CPP_17
#include <cstddef>
#include <cstdint>
#include <vector>

TEST_CASE("BON8 with std::byte")
{
    SECTION("vector roundtrip")
    {
        const json original =
        {
            {"name", "test"},
            {"value", 42},
            {"array", {1, 2, 3}}
        };

        const std::vector<uint8_t> temp = json::to_bon8(original);
        std::vector<std::byte> bon8_data(temp.size());
        for (size_t i = 0; i < temp.size(); ++i)
        {
            bon8_data[i] = std::byte(temp[i]);
        }

        json from_bytes;
        CHECK_NOTHROW(from_bytes = json::from_bon8(bon8_data));
        CHECK(from_bytes == original);
    }

    SECTION("empty vector")
    {
        const std::vector<std::byte> empty_data;
        CHECK_THROWS_WITH_AS([&]()
        {
            [[maybe_unused]] auto result = json::from_bon8(empty_data);
            return true;
        }
        (),
        "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing BON8 value: unexpected end of input",
        json::parse_error&);
    }
}

#endif
