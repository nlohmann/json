//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include "diag.hpp"

TEST_CASE("ABI compatible diagnostics")
{
    SECTION("basic_json size")
    {
        // basic_json with diagnostics is larger because of added data members
        CHECK(json_sizeof_diag_on() == json_sizeof_diag_on_explicit());
        CHECK(json_sizeof_diag_off() == json_sizeof_diag_off_explicit());
        CHECK(json_sizeof_diag_on() > json_sizeof_diag_off());
    }

    SECTION("basic_json at")
    {
        // accessing a nonexistent key throws different exception with diagnostics
        CHECK_THROWS_WITH(json_at_diag_on(), "[json.exception.out_of_range.403] (/foo) key 'bar' not found");
        CHECK_THROWS_WITH(json_at_diag_off(), "[json.exception.out_of_range.403] key 'bar' not found");
    }
}
