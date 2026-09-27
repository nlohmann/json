//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-items.cpp (structured
// bindings support for json::items()). It is kept in a separate
// translation unit so the (much larger) unit-items.cpp does not need to
// be compiled a second time just for this one SECTION.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#ifdef JSON_HAS_CPP_17
#include <map>
#include <string>

TEST_CASE("items()")
{
    SECTION("object")
    {
        SECTION("structured bindings")
        {
            json j = { {"A", 1}, {"B", 2} };

            std::map<std::string, int> m;

            for (auto const&[key, value] : j.items())
            {
                m.emplace(key, value);
            }

            CHECK(j.get<decltype(m)>() == m);
        }
    }
}
#endif
