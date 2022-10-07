//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <fstream>
#include "make_test_data_available.hpp"

TEST_CASE("Binary Formats" * doctest::skip())
{
    SECTION("canada.json")
    {
        const auto* filename = TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json";
        const json j = json::parse(std::ifstream(filename));

        const auto json_size = j.dump().size();
        const auto bjdata_1_size = json::to_bjdata(j).size();
        const auto bjdata_2_size = json::to_bjdata(j, true).size();
        const auto bjdata_3_size = json::to_bjdata(j, true, true).size();
        const auto bson_size = json::to_bson(j).size();
        const auto cbor_size = json::to_cbor(j).size();
        const auto msgpack_size = json::to_msgpack(j).size();
        const auto ubjson_1_size = json::to_ubjson(j).size();
        const auto ubjson_2_size = json::to_ubjson(j, true).size();
        const auto ubjson_3_size = json::to_ubjson(j, true, true).size();

        CHECK(json_size == 2090303);
        CHECK(bjdata_1_size == 1112030);
        CHECK(bjdata_2_size == 1224148);
        CHECK(bjdata_3_size == 1224148);
        CHECK(bson_size == 1794522);
        CHECK(cbor_size == 1055552);
        CHECK(msgpack_size == 1056145);
        CHECK(ubjson_1_size == 1112030);
        CHECK(ubjson_2_size == 1224148);
        CHECK(ubjson_3_size == 1169069);

        CHECK((100.0 * double(json_size) / double(json_size)) == Approx(100.0));
        CHECK((100.0 * double(bjdata_1_size) / double(json_size)) == Approx(53.199));
        CHECK((100.0 * double(bjdata_2_size) / double(json_size)) == Approx(58.563));
        CHECK((100.0 * double(bjdata_3_size) / double(json_size)) == Approx(58.563));
        CHECK((100.0 * double(bson_size) / double(json_size)) == Approx(85.849));
        CHECK((100.0 * double(cbor_size) / double(json_size)) == Approx(50.497));
        CHECK((100.0 * double(msgpack_size) / double(json_size)) == Approx(50.526));
        CHECK((100.0 * double(ubjson_1_size) / double(json_size)) == Approx(53.199));
        CHECK((100.0 * double(ubjson_2_size) / double(json_size)) == Approx(58.563));
        CHECK((100.0 * double(ubjson_3_size) / double(json_size)) == Approx(55.928));
    }

    SECTION("twitter.json")
    {
        const auto* filename = TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json";
        const json j = json::parse(std::ifstream(filename));

        const auto json_size = j.dump().size();
        const auto bjdata_1_size = json::to_bjdata(j).size();
        const auto bjdata_2_size = json::to_bjdata(j, true).size();
        const auto bjdata_3_size = json::to_bjdata(j, true, true).size();
        const auto bson_size = json::to_bson(j).size();
        const auto cbor_size = json::to_cbor(j).size();
        const auto msgpack_size = json::to_msgpack(j).size();
        const auto ubjson_1_size = json::to_ubjson(j).size();
        const auto ubjson_2_size = json::to_ubjson(j, true).size();
        const auto ubjson_3_size = json::to_ubjson(j, true, true).size();

        CHECK(json_size == 466906);
        CHECK(bjdata_1_size == 425342);
        CHECK(bjdata_2_size == 429970);
        CHECK(bjdata_3_size == 429970);
        CHECK(bson_size == 444568);
        CHECK(cbor_size == 402814);
        CHECK(msgpack_size == 401510);
        CHECK(ubjson_1_size == 426160);
        CHECK(ubjson_2_size == 430788);
        CHECK(ubjson_3_size == 430798);

        CHECK((100.0 * double(json_size) / double(json_size)) == Approx(100.0));
        CHECK((100.0 * double(bjdata_1_size) / double(json_size)) == Approx(91.097));
        CHECK((100.0 * double(bjdata_2_size) / double(json_size)) == Approx(92.089));
        CHECK((100.0 * double(bjdata_3_size) / double(json_size)) == Approx(92.089));
        CHECK((100.0 * double(bson_size) / double(json_size)) == Approx(95.215));
        CHECK((100.0 * double(cbor_size) / double(json_size)) == Approx(86.273));
        CHECK((100.0 * double(msgpack_size) / double(json_size)) == Approx(85.993));
        CHECK((100.0 * double(ubjson_1_size) / double(json_size)) == Approx(91.273));
        CHECK((100.0 * double(ubjson_2_size) / double(json_size)) == Approx(92.264));
        CHECK((100.0 * double(ubjson_3_size) / double(json_size)) == Approx(92.266));
    }

    SECTION("citm_catalog.json")
    {
        const auto* filename = TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json";
        const json j = json::parse(std::ifstream(filename));

        const auto json_size = j.dump().size();
        const auto bjdata_1_size = json::to_bjdata(j).size();
        const auto bjdata_2_size = json::to_bjdata(j, true).size();
        const auto bjdata_3_size = json::to_bjdata(j, true, true).size();
        const auto bson_size = json::to_bson(j).size();
        const auto cbor_size = json::to_cbor(j).size();
        const auto msgpack_size = json::to_msgpack(j).size();
        const auto ubjson_1_size = json::to_ubjson(j).size();
        const auto ubjson_2_size = json::to_ubjson(j, true).size();
        const auto ubjson_3_size = json::to_ubjson(j, true, true).size();

        CHECK(json_size == 500299);
        CHECK(bjdata_1_size == 390781);
        CHECK(bjdata_2_size == 433557);
        CHECK(bjdata_3_size == 432964);
        CHECK(bson_size == 479430);
        CHECK(cbor_size == 342373);
        CHECK(msgpack_size == 342473);
        CHECK(ubjson_1_size == 391463);
        CHECK(ubjson_2_size == 434239);
        CHECK(ubjson_3_size == 425073);

        CHECK((100.0 * double(json_size) / double(json_size)) == Approx(100.0));
        CHECK((100.0 * double(bjdata_1_size) / double(json_size)) == Approx(78.109));
        CHECK((100.0 * double(bjdata_2_size) / double(json_size)) == Approx(86.659));
        CHECK((100.0 * double(bjdata_3_size) / double(json_size)) == Approx(86.541));
        CHECK((100.0 * double(bson_size) / double(json_size)) == Approx(95.828));
        CHECK((100.0 * double(cbor_size) / double(json_size)) == Approx(68.433));
        CHECK((100.0 * double(msgpack_size) / double(json_size)) == Approx(68.453));
        CHECK((100.0 * double(ubjson_1_size) / double(json_size)) == Approx(78.245));
        CHECK((100.0 * double(ubjson_2_size) / double(json_size)) == Approx(86.795));
        CHECK((100.0 * double(ubjson_3_size) / double(json_size)) == Approx(84.963));
    }

    SECTION("jeopardy.json")
    {
        const auto* filename = TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json";
        json j = json::parse(std::ifstream(filename));

        const auto json_size = j.dump().size();
        const auto bjdata_1_size = json::to_bjdata(j).size();
        const auto bjdata_2_size = json::to_bjdata(j, true).size();
        const auto bjdata_3_size = json::to_bjdata(j, true, true).size();
        const auto bson_size = json::to_bson({{"", j}}).size(); // wrap array in object for BSON
        const auto cbor_size = json::to_cbor(j).size();
        const auto msgpack_size = json::to_msgpack(j).size();
        const auto ubjson_1_size = json::to_ubjson(j).size();
        const auto ubjson_2_size = json::to_ubjson(j, true).size();
        const auto ubjson_3_size = json::to_ubjson(j, true, true).size();

        CHECK(json_size == 52508728);
        CHECK(bjdata_1_size == 50710965);
        CHECK(bjdata_2_size == 51144830);
        CHECK(bjdata_3_size == 51144830);
        CHECK(bson_size == 56008520);
        CHECK(cbor_size == 46187320);
        CHECK(msgpack_size == 46158575);
        CHECK(ubjson_1_size == 50710965);
        CHECK(ubjson_2_size == 51144830);
        CHECK(ubjson_3_size == 49861422);

        CHECK((100.0 * double(json_size) / double(json_size)) == Approx(100.0));
        CHECK((100.0 * double(bjdata_1_size) / double(json_size)) == Approx(96.576));
        CHECK((100.0 * double(bjdata_2_size) / double(json_size)) == Approx(97.402));
        CHECK((100.0 * double(bjdata_3_size) / double(json_size)) == Approx(97.402));
        CHECK((100.0 * double(bson_size) / double(json_size)) == Approx(106.665));
        CHECK((100.0 * double(cbor_size) / double(json_size)) == Approx(87.961));
        CHECK((100.0 * double(msgpack_size) / double(json_size)) == Approx(87.906));
        CHECK((100.0 * double(ubjson_1_size) / double(json_size)) == Approx(96.576));
        CHECK((100.0 * double(ubjson_2_size) / double(json_size)) == Approx(97.402));
        CHECK((100.0 * double(ubjson_3_size) / double(json_size)) == Approx(94.958));
    }

    SECTION("sample.json")
    {
        const auto* filename = TEST_DATA_DIRECTORY "/json_testsuite/sample.json";
        const json j = json::parse(std::ifstream(filename));

        const auto json_size = j.dump().size();
        const auto bjdata_1_size = json::to_bjdata(j).size();
        const auto bjdata_2_size = json::to_bjdata(j, true).size();
        const auto bjdata_3_size = json::to_bjdata(j, true, true).size();
        // BSON cannot process the file as it contains code point  U+0000
        const auto cbor_size = json::to_cbor(j).size();
        const auto msgpack_size = json::to_msgpack(j).size();
        const auto ubjson_1_size = json::to_ubjson(j).size();
        const auto ubjson_2_size = json::to_ubjson(j, true).size();
        const auto ubjson_3_size = json::to_ubjson(j, true, true).size();

        CHECK(json_size == 168677);
        CHECK(bjdata_1_size == 148695);
        CHECK(bjdata_2_size == 150569);
        CHECK(bjdata_3_size == 150569);
        CHECK(cbor_size == 147095);
        CHECK(msgpack_size == 147017);
        CHECK(ubjson_1_size == 148695);
        CHECK(ubjson_2_size == 150569);
        CHECK(ubjson_3_size == 150883);

        CHECK((100.0 * double(json_size) / double(json_size)) == Approx(100.0));
        CHECK((100.0 * double(bjdata_1_size) / double(json_size)) == Approx(88.153));
        CHECK((100.0 * double(bjdata_2_size) / double(json_size)) == Approx(89.264));
        CHECK((100.0 * double(bjdata_3_size) / double(json_size)) == Approx(89.264));
        CHECK((100.0 * double(cbor_size) / double(json_size)) == Approx(87.205));
        CHECK((100.0 * double(msgpack_size) / double(json_size)) == Approx(87.158));
        CHECK((100.0 * double(ubjson_1_size) / double(json_size)) == Approx(88.153));
        CHECK((100.0 * double(ubjson_2_size) / double(json_size)) == Approx(89.264));
        CHECK((100.0 * double(ubjson_3_size) / double(json_size)) == Approx(89.450));
    }
}
