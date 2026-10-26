//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // uint8_t
#include <vector> // vector

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include "round_trip_corpus.hpp"

// The BJData round-trip invariants, split by the BJData version that turns a
// corpus value into j1 (unit-bjdata_round_trip_draft2.cpp and
// unit-bjdata_round_trip_draft3.cpp). They were part of unit-bjdata.cpp, but
// took 80 % of its time; as separate tests, both halves run in parallel and
// stay below the ctest timeout under Valgrind.
namespace utils
{

// This checks what the parse_bjdata_fuzzer driver checks (see
// tests/src/fuzzer-parse_bjdata.cpp), so that a regression shows up in CI
// rather than as an OSS-Fuzz report: every value from_bjdata() returns
// (j1) can be serialized with any combination of options, the result can
// be parsed back (j2), and serializing j2 again with the same options
// yields a value-equal result.
//
// Beyond the driver, this also checks that j2 equals j1 and that
// serializing j2 reproduces the exact bytes, both except for values that
// contain a binary value: a binary value is only written as a binary
// value with Draft 3's optimized binary array, and otherwise read back as
// an array of integers, for which the writer may choose different (but
// equally valid) type markers when it is serialized again (see #5494).
//
// Values are compared with dump() rather than operator==, because a NaN
// never compares equal to itself.
//
// Only the corpus values written with @a initial_version become j1; each j1
// is then serialized with every combination of options, both versions
// included.
inline void check_bjdata_round_trip(const nlohmann::json::bjdata_version_t initial_version)
{
    using nlohmann::json;

    struct options
    {
        bool use_size;
        bool use_type;
        json::bjdata_version_t version;
    };
    const std::vector<options> all_options =
    {
        {false, false, json::bjdata_version_t::draft2},
        {true, false, json::bjdata_version_t::draft2},
        {true, true, json::bjdata_version_t::draft2},
        {false, false, json::bjdata_version_t::draft3},
        {true, false, json::bjdata_version_t::draft3},
        {true, true, json::bjdata_version_t::draft3},
    };

    for (const auto& j0 : utils::round_trip_corpus::values())
    {
        // turn the corpus value into a value as from_bjdata() returns it
        for (const auto& initial : all_options)
        {
            if (initial.version != initial_version)
            {
                continue;
            }

            const json j1 = json::from_bjdata(json::to_bjdata(j0, initial.use_size, initial.use_type, initial.version));
            const bool has_binary = utils::round_trip_corpus::contains_binary(j1);

            for (const auto& o : all_options)
            {
                INFO("j1 = " << j1.dump() << ", use_size = " << o.use_size << ", use_type = " << o.use_type
                     << ", draft3 = " << (o.version == json::bjdata_version_t::draft3));

                const std::vector<std::uint8_t> vec = json::to_bjdata(j1, o.use_size, o.use_type, o.version);
                json j2;
                // anything the library writes must be parsable by the library
                REQUIRE_NOTHROW(j2 = json::from_bjdata(vec));
                const std::vector<std::uint8_t> vec2 = json::to_bjdata(j2, o.use_size, o.use_type, o.version);
                CHECK(json::from_bjdata(vec2).dump() == j2.dump());

                if (!has_binary)
                {
                    CHECK(j2.dump() == j1.dump());
                    CHECK(vec2 == vec);
                }
            }
        }
    }
}

} // namespace utils
