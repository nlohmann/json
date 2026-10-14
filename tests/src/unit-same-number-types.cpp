//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <vector>

// basic_json with the same type for number_integer_t and number_unsigned_t
// (#2573): every integer is stored as number_integer

namespace
{

template<typename IntegerType>
using same_types_json = nlohmann::json::with_integers_t<IntegerType, IntegerType>;

using json64 = same_types_json<std::int64_t>;
using json32 = same_types_json<std::int32_t>;

} // namespace

TEST_CASE_TEMPLATE("same type for number_integer_t and number_unsigned_t", Json, json64, json32)
{
    using integer_t = typename Json::number_integer_t;
    using limits = std::numeric_limits<integer_t>;

    SECTION("parsing stores integers as number_integer")
    {
        const Json j = Json::parse("[0, 1, -1, 2147483647, -2147483648]");
        for (const auto& element : j)
        {
            CHECK(element.is_number_integer());
            CHECK(!element.is_number_unsigned());
            CHECK(element.type() == nlohmann::detail::value_t::number_integer);
        }
        CHECK(j[1].template get<integer_t>() == 1);
        CHECK(j[2].template get<integer_t>() == -1);
        CHECK(j[3].template get<integer_t>() == 2147483647);
        CHECK(j[4].template get<std::int64_t>() == -2147483648LL);
    }

    SECTION("integers above the maximum are parsed as floats")
    {
        // a positive literal is parsed as unsigned first; it must not wrap
        // around to a negative number_integer_t
        const auto above_max = std::to_string(static_cast<std::uint64_t>(limits::max()) + 1);
        const Json j1 = Json::parse(above_max);
        CHECK(j1.is_number_float());
        CHECK(j1.template get<double>() == static_cast<double>(static_cast<std::uint64_t>(limits::max()) + 1));

        const Json j2 = Json::parse("18446744073709551615");
        CHECK(j2.is_number_float());
        CHECK(j2.template get<double>() == 18446744073709551615.0);

        const Json j3 = Json::parse(std::to_string(limits::max()));
        CHECK(j3.is_number_integer());
        CHECK(j3.template get<integer_t>() == limits::max());
    }

    SECTION("serialization of the extremes")
    {
        CHECK(Json(limits::max()).dump() == std::to_string(limits::max()));
        // the absolute value of the minimum does not fit into number_unsigned_t
        CHECK(Json(limits::min()).dump() == std::to_string(limits::min()));
        CHECK(Json::parse(std::to_string(limits::min())) == Json(limits::min()));
        CHECK(Json(0).dump() == "0");
    }

    SECTION("construction from unsigned types")
    {
        const Json j1 = 5u;
        CHECK(j1.is_number_integer());
        CHECK(!j1.is_number_unsigned());
        CHECK(j1 == 5);

        const Json j2 = static_cast<std::uint8_t>(200);
        CHECK(j2.is_number_integer());
        CHECK(j2.template get<integer_t>() == 200);

        const Json j3 = std::vector<unsigned> {1, 2, 3};
        CHECK(j3.dump() == "[1,2,3]");
        CHECK(j3[0].is_number_integer());

        const Json j4 = true;
        CHECK(j4.is_boolean());
    }

    SECTION("value_t::number_unsigned creates a number_integer")
    {
        const Json j(nlohmann::detail::value_t::number_unsigned);
        CHECK(j.is_number_integer());
        CHECK(!j.is_number_unsigned());
        CHECK(j == 0);
        CHECK(j.dump() == "0");
    }

    SECTION("conversions")
    {
        Json j = 42;
        CHECK(j.template get<unsigned>() == 42u);
        CHECK(j.template get<std::uint64_t>() == 42u);
        CHECK(j.template get<int>() == 42);
        CHECK(j.template get<double>() == 42.0);
        CHECK(j.template get_ptr<integer_t*>() != nullptr);
        CHECK(*j.template get_ptr<integer_t*>() == 42);
        CHECK(j.template get_ref<integer_t&>() == 42);
        j.template get_ref<integer_t&>() = 43;
        CHECK(j == 43);

        integer_t i = 0;
        j.get_to(i);
        CHECK(i == 43);

        const Json object = {{"a", 1}};
        CHECK(object.value("a", 0u) == 1u);
        CHECK(object.value("b", 7u) == 7u);
    }

    SECTION("conversion from a basic_json with distinct types")
    {
        const nlohmann::json j = {1, 2u, -3, 4.5};
        CHECK(j[1].is_number_unsigned());
        const Json converted = j;
        CHECK(converted.dump() == "[1,2,-3,4.5]");
        CHECK(converted[1].is_number_integer());
        CHECK(!converted[1].is_number_unsigned());

        const nlohmann::json back = converted;
        CHECK(back == j);
    }

    SECTION("comparison and hashing")
    {
        const Json j1 = 1;
        const Json j2 = 2u;
        CHECK(j1 < j2);
        CHECK(j1 != j2);
        CHECK(j2 == 2);
        CHECK(j2 == 2u);
        CHECK(j1 < 1.5);
        CHECK(Json(-1) < Json(0u));
        CHECK(std::hash<Json> {}(Json(5u)) == std::hash<Json> {}(Json(5)));
    }

    SECTION("JSON Patch, diff, and flatten")
    {
        const Json source = Json::parse(R"({"a": [1, 2, 3], "b": 4})");
        const Json target = Json::parse(R"({"a": [1, 5], "c": 6})");
        CHECK(source.patch(Json::diff(source, target)) == target);
        CHECK(source.flatten().unflatten() == source);
    }

    SECTION("binary formats")
    {
        const Json j = {{"min", limits::min()}, {"max", limits::max()}, {"zero", 0}, {"small", 100}, {"negative", -100}, {"float", 1.5}};

        CHECK(Json::from_cbor(Json::to_cbor(j)) == j);
        CHECK(Json::from_msgpack(Json::to_msgpack(j)) == j);
        CHECK(Json::from_ubjson(Json::to_ubjson(j)) == j);
        CHECK(Json::from_bjdata(Json::to_bjdata(j)) == j);
        CHECK(Json::from_bson(Json::to_bson(j)) == j);
        CHECK(Json::from_bon8(Json::to_bon8(j)) == j);

        for (const auto& element : Json::from_cbor(Json::to_cbor(j)))
        {
            CHECK(!element.is_number_unsigned());
        }

        // CBOR unsigned integer 2^64-1 does not fit and is read as float
        const std::vector<std::uint8_t> cbor_max = {0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        const Json from_cbor = Json::from_cbor(cbor_max);
        CHECK(from_cbor.is_number_float());
        CHECK(from_cbor.template get<double>() == 18446744073709551615.0);

        // MessagePack uint 8 is read as number_integer
        const std::vector<std::uint8_t> msgpack_uint8 = {0xCC, 0xC8};
        const Json from_msgpack = Json::from_msgpack(msgpack_uint8);
        CHECK(from_msgpack.is_number_integer());
        CHECK(from_msgpack == 200);
    }
}

TEST_CASE("same type for number_integer_t and number_unsigned_t: type traits")
{
    CHECK(std::is_same<nlohmann::detail::number_unsigned_overload_t<json64>, nlohmann::detail::same_as_number_integer_type>::value);
    CHECK(std::is_same<nlohmann::detail::number_unsigned_overload_t<nlohmann::json>, std::uint64_t>::value);
    CHECK(nlohmann::detail::is_compatible_number_integer_type<json64, unsigned>::value);
    CHECK(!nlohmann::detail::is_compatible_number_integer_type<nlohmann::json, unsigned>::value);
    CHECK(!nlohmann::detail::is_compatible_number_integer_type<json64, bool>::value);
}
