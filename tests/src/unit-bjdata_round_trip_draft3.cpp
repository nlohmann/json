//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include "bjdata_round_trip.hpp"

// split from unit-bjdata.cpp, see bjdata_round_trip.hpp; the other half is in
// unit-bjdata_round_trip_draft2.cpp

TEST_CASE("BJData round-trip invariants (j1 written with Draft 3)")
{
    utils::check_bjdata_round_trip(json::bjdata_version_t::draft3);
}
