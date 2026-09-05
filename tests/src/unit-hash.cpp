//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

#include <set>
#include <unordered_set>

TEST_CASE("hash<nlohmann::json>")
{
    // Collect hashes for different JSON values and make sure that they are distinct
    // We cannot compare against fixed values, because the implementation of
    // std::hash may differ between compilers.
    //
    // numbers that compare equal under operator== (0 == 0U == 0.0) must hash
    // equally, so they are only inserted once below and checked separately.

    std::set<std::size_t> hashes;

    // null
    hashes.insert(std::hash<json> {}(json(nullptr)));

    // boolean
    hashes.insert(std::hash<json> {}(json(true)));
    hashes.insert(std::hash<json> {}(json(false)));

    // string
    hashes.insert(std::hash<json> {}(json("")));
    hashes.insert(std::hash<json> {}(json("foo")));

    // number
    hashes.insert(std::hash<json> {}(json(0)));
    hashes.insert(std::hash<json> {}(json(-1)));
    hashes.insert(std::hash<json> {}(json(42.23)));

    // array
    hashes.insert(std::hash<json> {}(json::array()));
    hashes.insert(std::hash<json> {}(json::array({1, 2, 3})));

    // object
    hashes.insert(std::hash<json> {}(json::object()));
    hashes.insert(std::hash<json> {}(json::object({{"foo", "bar"}})));

    // binary
    hashes.insert(std::hash<json> {}(json::binary({})));
    hashes.insert(std::hash<json> {}(json::binary({}, 0)));
    hashes.insert(std::hash<json> {}(json::binary({}, 42)));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3})));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3}, 0)));
    hashes.insert(std::hash<json> {}(json::binary({1, 2, 3}, 42)));

    // discarded
    hashes.insert(std::hash<json> {}(json(json::value_t::discarded)));

    CHECK(hashes.size() == 19);

    // numbers that compare equal under operator== must hash equally,
    // regardless of which of number_integer, number_unsigned, or
    // number_float actually holds the value
    CHECK(json(0) == json(static_cast<unsigned>(0)));
    CHECK(json(0) == json(0.0));
    CHECK(std::hash<json> {}(json(0)) == std::hash<json> {}(json(static_cast<unsigned>(0))));
    CHECK(std::hash<json> {}(json(0)) == std::hash<json> {}(json(0.0)));
    CHECK(std::hash<json> {}(json(-1)) == std::hash<json> {}(json(-1.0)));

    // a std::unordered_set relies on this same consistency between == and hash
    const std::unordered_set<json> numbers {json(0), json(static_cast<unsigned>(0)), json(0.0)};
    CHECK(numbers.size() == 1);
}

TEST_CASE("hash<nlohmann::ordered_json>")
{
    // Collect hashes for different JSON values and make sure that they are distinct
    // We cannot compare against fixed values, because the implementation of
    // std::hash may differ between compilers.

    std::set<std::size_t> hashes;

    // null
    hashes.insert(std::hash<ordered_json> {}(ordered_json(nullptr)));

    // boolean
    hashes.insert(std::hash<ordered_json> {}(ordered_json(true)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json(false)));

    // string
    hashes.insert(std::hash<ordered_json> {}(ordered_json("")));
    hashes.insert(std::hash<ordered_json> {}(ordered_json("foo")));

    // number
    hashes.insert(std::hash<ordered_json> {}(ordered_json(0)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json(-1)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json(42.23)));

    // array
    hashes.insert(std::hash<ordered_json> {}(ordered_json::array()));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::array({1, 2, 3})));

    // object
    hashes.insert(std::hash<ordered_json> {}(ordered_json::object()));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::object({{"foo", "bar"}})));

    // binary
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({})));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({}, 0)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({}, 42)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({1, 2, 3})));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({1, 2, 3}, 0)));
    hashes.insert(std::hash<ordered_json> {}(ordered_json::binary({1, 2, 3}, 42)));

    // discarded
    hashes.insert(std::hash<ordered_json> {}(ordered_json(ordered_json::value_t::discarded)));

    CHECK(hashes.size() == 19);

    CHECK(std::hash<ordered_json> {}(ordered_json(0)) == std::hash<ordered_json> {}(ordered_json(static_cast<unsigned>(0))));
    CHECK(std::hash<ordered_json> {}(ordered_json(0)) == std::hash<ordered_json> {}(ordered_json(0.0)));
}
