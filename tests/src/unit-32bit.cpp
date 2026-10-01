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

#include <climits> // SIZE_MAX

// JSON_32bitTest=ONLY builds only this file, so it must keep its own
// include of the shared trait/TEST_CASE_TEMPLATE_DEFINE rather than relying
// on unit-bjdata.cpp to provide it
#include "value_in_range_of_test.hpp"

TEST_CASE("32bit")
{
    REQUIRE(SIZE_MAX == 0xffffffff);
}

TEST_CASE_TEMPLATE_INVOKE(value_in_range_of_test, \
                          trait_test_arg<std::size_t, std::int32_t, false, true>, \
                          trait_test_arg<std::size_t, std::uint32_t, true, true>, \
                          trait_test_arg<std::size_t, std::int64_t, false, false>, \
                          trait_test_arg<std::size_t, std::uint64_t, true, false>);

TEST_CASE("BJData")
{
    SECTION("parse errors")
    {
        SECTION("array")
        {
            SECTION("optimized array: negative size")
            {
                std::vector<uint8_t> const vM = {'[', '$', 'M', '#', '[', 'I', 0x00, 0x20, 'M', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xFF, ']'};
                std::vector<uint8_t> const vMX = {'[', '$', 'U', '#', '[', 'M', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 'U', 0x01, ']'};

                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vM, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vMX), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vMX, true, false).is_discarded());
            }

            SECTION("optimized array: integer value overflow")
            {
                std::vector<uint8_t> const vL = {'[', '#', 'L', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F};
                std::vector<uint8_t> const vM = {'[', '$', 'M', '#', '[', 'I', 0x00, 0x20, 'M', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xFF, ']'};

                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vL), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vL, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vM, true, false).is_discarded());
            }
        }
    }
}

TEST_CASE("CBOR")
{
    SECTION("parse errors")
    {
        SECTION("array/map size larger than std::size_t")
        {
            // declared lengths do not fit in a 32-bit std::size_t and must not be truncated
            std::vector<uint8_t> const varr = {0x9B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05};
            std::vector<uint8_t> const vmap = {0xBB, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05};

            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_cbor(varr), "[json.exception.out_of_range.408] syntax error while parsing CBOR size: excessive array size", json::out_of_range&);
            CHECK(json::from_cbor(varr, true, false).is_discarded());

            CHECK_THROWS_WITH_AS(_ = json::from_cbor(vmap), "[json.exception.out_of_range.408] syntax error while parsing CBOR size: excessive map size", json::out_of_range&);
            CHECK(json::from_cbor(vmap, true, false).is_discarded());
        }

        SECTION("array/map size equal to the indefinite-length sentinel")
        {
            // on 32-bit platforms a four-byte length of 0xFFFFFFFF aliases unknown_size()
            std::vector<uint8_t> const varr = {0x9A, 0xFF, 0xFF, 0xFF, 0xFF};
            std::vector<uint8_t> const vmap = {0xBA, 0xFF, 0xFF, 0xFF, 0xFF};

            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_cbor(varr), "[json.exception.out_of_range.408] syntax error while parsing CBOR size: excessive array size", json::out_of_range&);
            CHECK(json::from_cbor(varr, true, false).is_discarded());

            CHECK_THROWS_WITH_AS(_ = json::from_cbor(vmap), "[json.exception.out_of_range.408] syntax error while parsing CBOR size: excessive map size", json::out_of_range&);
            CHECK(json::from_cbor(vmap, true, false).is_discarded());
        }
    }
}
