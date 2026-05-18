//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ns
{
enum class Color { red, green, blue, unknown };

NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(Color,
{
    { Color::unknown, "unknown" },
    { Color::red,     "red"     },
    { Color::green,   "green"   },
    { Color::blue,    "blue"    }
})
} // namespace ns

TEST_CASE("NLOHMANN_JSON_SERIALIZE_ENUM_STRICT throws on unknown input string")
{
    json j = "purple"; // not mapped
    ns::Color c;

    CHECK_THROWS_AS((j.get_to(c)), nlohmann::detail::type_error);
}

TEST_CASE("NLOHMANN_JSON_SERIALIZE_ENUM_STRICT still deserializes valid values")
{
    json j = "green";
    auto c = j.get<ns::Color>();
    CHECK(c == ns::Color::green);
}
