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

#include <cmath>
#include <fstream>
#include <limits>
#include <map>
#include <string>
#include <vector>
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
        const auto bon8_size = json::to_bon8(j).size();
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
        CHECK(bon8_size == 1055792);
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
        CHECK((100.0 * double(bon8_size) / double(json_size)) == Approx(50.509));
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
        const auto bon8_size = json::to_bon8(j).size();
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
        CHECK(bon8_size == 391396);
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
        CHECK((100.0 * double(bon8_size) / double(json_size)) == Approx(83.828));
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
        const auto bon8_size = json::to_bon8(j).size();
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
        CHECK(bon8_size == 317879);
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
        CHECK((100.0 * double(bon8_size) / double(json_size)) == Approx(63.538));
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
        const auto bon8_size = json::to_bon8(j).size();
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
        CHECK(bon8_size == 45942080);
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
        CHECK((100.0 * double(bon8_size) / double(json_size)) == Approx(87.494));
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
        const auto bon8_size = json::to_bon8(j).size();
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
        CHECK(bon8_size == 144477);
        CHECK(cbor_size == 147095);
        CHECK(msgpack_size == 147017);
        CHECK(ubjson_1_size == 148695);
        CHECK(ubjson_2_size == 150569);
        CHECK(ubjson_3_size == 150883);

        CHECK((100.0 * double(json_size) / double(json_size)) == Approx(100.0));
        CHECK((100.0 * double(bjdata_1_size) / double(json_size)) == Approx(88.153));
        CHECK((100.0 * double(bjdata_2_size) / double(json_size)) == Approx(89.264));
        CHECK((100.0 * double(bjdata_3_size) / double(json_size)) == Approx(89.264));
        CHECK((100.0 * double(bon8_size) / double(json_size)) == Approx(85.653));
        CHECK((100.0 * double(cbor_size) / double(json_size)) == Approx(87.205));
        CHECK((100.0 * double(msgpack_size) / double(json_size)) == Approx(87.158));
        CHECK((100.0 * double(ubjson_1_size) / double(json_size)) == Approx(88.153));
        CHECK((100.0 * double(ubjson_2_size) / double(json_size)) == Approx(89.264));
        CHECK((100.0 * double(ubjson_3_size) / double(json_size)) == Approx(89.450));
    }
}

namespace
{
// the binary formats as function pointers for "Binary formats with narrow number types";
// named functions rather than lambdas, because clang 3.5 cannot convert a lambda
// to a function pointer in the braced initializer of the format table
using narrow_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int32_t, std::uint32_t, float>;
using bytes = std::vector<std::uint8_t>;

bytes encode_cbor(const json& j)
{
    return json::to_cbor(j);
}
narrow_json decode_cbor(const bytes& v, bool allow_exceptions)
{
    return narrow_json::from_cbor(v, true, allow_exceptions);
}

bytes encode_msgpack(const json& j)
{
    return json::to_msgpack(j);
}
narrow_json decode_msgpack(const bytes& v, bool allow_exceptions)
{
    return narrow_json::from_msgpack(v, true, allow_exceptions);
}

bytes encode_ubjson(const json& j)
{
    return json::to_ubjson(j);
}
narrow_json decode_ubjson(const bytes& v, bool allow_exceptions)
{
    return narrow_json::from_ubjson(v, true, allow_exceptions);
}

bytes encode_bjdata(const json& j)
{
    return json::to_bjdata(j);
}
narrow_json decode_bjdata(const bytes& v, bool allow_exceptions)
{
    return narrow_json::from_bjdata(v, true, allow_exceptions);
}

// BSON can only store numbers as object members
bytes encode_bson(const json& j)
{
    return json::to_bson(json{{"a", j}});
}
narrow_json decode_bson(const bytes& v, bool allow_exceptions)
{
    const auto result = narrow_json::from_bson(v, true, allow_exceptions);
    return result.is_discarded() ? result : result.at("a");
}

bytes encode_bon8(const json& j)
{
    return json::to_bon8(j);
}
narrow_json decode_bon8(const bytes& v, bool allow_exceptions)
{
    return narrow_json::from_bon8(v, true, allow_exceptions);
}

} // namespace

TEST_CASE("Binary formats with narrow number types")
{
    // Numbers that do not fit the number types are handled like the lexer
    // handles them in JSON text: an integer that fits neither integer type is
    // stored as a floating-point number, and a finite floating-point number
    // that overflows number_float_t is rejected with out_of_range.406.
    struct binary_format
    {
        const char* name;
        bytes (*encode)(const json&);
        narrow_json (*decode)(const bytes&, bool);
    };

    const std::vector<binary_format> formats =
    {
        {"CBOR", encode_cbor, decode_cbor},
        {"MessagePack", encode_msgpack, decode_msgpack},
        {"UBJSON", encode_ubjson, decode_ubjson},
        {"BJData", encode_bjdata, decode_bjdata},
        {"BSON", encode_bson, decode_bson},
        {"BON8", encode_bon8, decode_bon8},
    };

    for (const auto& format : formats)
    {
        const std::string name = format.name;
        INFO("format := ", name);
        const auto roundtrip = [&format](const json & j)
        {
            return format.decode(format.encode(j), true);
        };

        // integers that fit keep their type
        CHECK(roundtrip(json(-5)).is_number_integer());
        CHECK(roundtrip(json(-5)).get<std::int32_t>() == -5);
        CHECK(roundtrip(json(3000000000u)).is_number_unsigned());
        CHECK(roundtrip(json(3000000000u)).get<std::uint32_t>() == 3000000000u);

        // integers that fit neither integer type are stored as float
        CHECK(roundtrip(json(5000000000u)).is_number_float());
        CHECK(roundtrip(json(5000000000u)).get<float>() == 5000000000.0f);
        if (name != "BON8") // BON8 cannot encode integers above INT64_MAX
        {
            CHECK(roundtrip(json(10000000000000000000u)).is_number_float());
            CHECK(roundtrip(json(10000000000000000000u)).get<float>() == 10000000000000000000.0f);
        }
        CHECK(roundtrip(json(-3000000000LL)).is_number_float());
        CHECK(roundtrip(json(-3000000000LL)).get<float>() == -3000000000.0f);
        CHECK(roundtrip(json(-5000000000LL)).is_number_float());
        CHECK(roundtrip(json(-5000000000LL)).get<float>() == -5000000000.0f);

        // floating-point numbers that fit
        CHECK(roundtrip(json(1.5)).get<float>() == 1.5f);
        const auto just_above_max = std::nextafter(static_cast<double>((std::numeric_limits<float>::max)()),
                                    std::numeric_limits<double>::infinity());
        CHECK(roundtrip(json(just_above_max)).get<float>() == (std::numeric_limits<float>::max)());

        // infinity and NaN are passed on
        CHECK(std::isinf(roundtrip(json(std::numeric_limits<double>::infinity())).get<float>()));
        CHECK(std::isnan(roundtrip(json(std::numeric_limits<double>::quiet_NaN())).get<float>()));

        // finite floating-point numbers that overflow number_float_t are rejected
        const std::string message = "[json.exception.out_of_range.406] syntax error while parsing " + name
                                    + " value: number overflow";
        CHECK_THROWS_WITH_AS(roundtrip(json(1e300)), message.c_str(), narrow_json::out_of_range&);
        CHECK_THROWS_WITH_AS(roundtrip(json(-1e300)), message.c_str(), narrow_json::out_of_range&);
        CHECK(format.decode(format.encode(json(1e300)), false).is_discarded());
    }
}
