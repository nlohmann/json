//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-ordered_map.cpp (ordered_map::find with
// std::string_view keys). It is kept in a separate translation unit so the (much larger)
// unit-ordered_map.cpp is built for C++11 only and not rebuilt for every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::ordered_map;

#ifdef JSON_HAS_CPP_17
#include <string>
#include <string_view>

TEST_CASE("ordered_map (C++17)")
{
    SECTION("find")
    {
        ordered_map<std::string, std::string> om;
        om["eins"] = "one";
        om["zwei"] = "two";
        om["drei"] = "three";
        const auto com = om;

        const std::string eins("eins");
        const std::string vier("vier");

        CHECK(om.find(std::string_view("eins")) == om.begin());
        CHECK(com.find(std::string_view("eins")) == com.begin());
    }
}

#endif
