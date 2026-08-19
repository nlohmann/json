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

#include <cstdint>
#include <string>
#include <vector>

namespace
{

// a spread of values exercising every writer path: scalars of each width, the
// float paths, strings, binary, and containers big enough to reallocate
std::vector<json> test_values()
{
    json big_array = json::array();
    for (int i = 0; i < 5000; ++i)
    {
        big_array.push_back(i);
    }

    json big_object = json::object();
    for (int i = 0; i < 1000; ++i)
    {
        big_object[std::to_string(i)] = i;
    }

    return
    {
        json(nullptr), json(true), json(false),
        json(0), json(-1), json(255), json(-129), json(65535), json(-32769),
        json(4294967295U), json(-2147483649LL), json(18446744073709551615ULL),
        json(0.0), json(-0.5), json(3.1415926535897932),
        json(""), json("hello"), json(std::string(1000, 'x')),
        json::binary({0x00, 0x01, 0x02}, 42),
        json::array(), json::object(),
        json::array({1, 2, 3}), json({{"a", 1}, {"b", nullptr}}),
        json({{"nested", {{"deep", json::array({1, "two", 3.0, nullptr})}}}}),
        big_array, big_object
    };
}

// values to_bson() accepts: the document must be an object
std::vector<json> bson_values()
{
    json big_object = json::object();
    for (int i = 0; i < 1000; ++i)
    {
        big_object[std::to_string(i)] = i;
    }

    return
    {
        json::object(),
        json({{"a", 1}, {"b", nullptr}, {"c", true}, {"d", 2.5}, {"e", "text"}}),
        json({{"arr", json::array({1, 2, 3})}, {"obj", {{"k", "v"}}}}),
        big_object
    };
}

} // namespace

// The vector-returning to_*(j) overloads write through the non-virtual
// output_vector_sink, while to_*(j, adapter) goes through output_adapter_sink.
// The two are separate code paths that must stay byte-for-byte identical; these
// checks fail if either overload is ever changed without the other.
TEST_CASE("binary writer output sinks")
{
    SECTION("vector sink and adapter sink agree")
    {
        // note: no SUBCASE inside these loops - doctest keys subcases by
        // name/file/line, so a subcase in a loop body would only ever run for
        // the first iteration
        for (const auto& j : test_values())
        {
            CAPTURE(j.dump(-1, ' ', false, json::error_handler_t::replace));

            std::vector<std::uint8_t> cbor;
            json::to_cbor(j, cbor);
            CHECK(json::to_cbor(j) == cbor);

            std::vector<std::uint8_t> msgpack;
            json::to_msgpack(j, msgpack);
            CHECK(json::to_msgpack(j) == msgpack);

            for (const bool use_size :
                    {
                        false, true
                    })
            {
                for (const bool use_type :
                        {
                            false, true
                        })
                {
                    if (use_type && !use_size)
                    {
                        continue; // not a supported combination
                    }
                    CAPTURE(use_size);
                    CAPTURE(use_type);
                    std::vector<std::uint8_t> ubjson;
                    json::to_ubjson(j, ubjson, use_size, use_type);
                    CHECK(json::to_ubjson(j, use_size, use_type) == ubjson);
                }
            }

            for (const auto version :
                    {
                        json::bjdata_version_t::draft2, json::bjdata_version_t::draft3
                    })
            {
                std::vector<std::uint8_t> bjdata;
                json::to_bjdata(j, bjdata, false, false, version);
                CHECK(json::to_bjdata(j, false, false, version) == bjdata);
            }
        }

        for (const auto& j : bson_values())
        {
            CAPTURE(j.dump());
            std::vector<std::uint8_t> bson;
            json::to_bson(j, bson);
            CHECK(json::to_bson(j) == bson);
        }
    }

    SECTION("the char adapter produces the same bytes")
    {
        for (const auto& j : test_values())
        {
            CAPTURE(j.dump(-1, ' ', false, json::error_handler_t::replace));

            const std::vector<std::uint8_t> expected = json::to_cbor(j);
            std::vector<char> as_char;
            json::to_cbor(j, as_char);

            REQUIRE(as_char.size() == expected.size());
            std::vector<std::uint8_t> as_bytes;
            as_bytes.reserve(as_char.size());
            for (const char c : as_char)
            {
                as_bytes.push_back(static_cast<std::uint8_t>(c));
            }
            CHECK(as_bytes == expected);
        }
    }
}

// binary_reserve_hint() is documented as a *lower* bound on the serialized size,
// so that reserving it up front can never leave the returned vector holding
// capacity beyond what the value actually needs.
TEST_CASE("binary_reserve_hint never over-reserves")
{
    for (const auto& j : test_values())
    {
        CAPTURE(j.dump(-1, ' ', false, json::error_handler_t::replace));

        const std::size_t hint = nlohmann::detail::binary_reserve_hint(j);

        CHECK(hint <= json::to_cbor(j).size());
        CHECK(hint <= json::to_msgpack(j).size());
        CHECK(hint <= json::to_ubjson(j).size());
        CHECK(hint <= json::to_ubjson(j, true, true).size());
        CHECK(hint <= json::to_bjdata(j).size());
    }

    for (const auto& j : bson_values())
    {
        CAPTURE(j.dump());
        CHECK(nlohmann::detail::binary_reserve_hint(j) <= json::to_bson(j).size());
    }

    SECTION("scalars get no hint")
    {
        CHECK(nlohmann::detail::binary_reserve_hint(json(nullptr)) == 0);
        CHECK(nlohmann::detail::binary_reserve_hint(json(42)) == 0);
        CHECK(nlohmann::detail::binary_reserve_hint(json("a string")) == 0);
        CHECK(nlohmann::detail::binary_reserve_hint(json::binary({0x01})) == 0);
    }

    SECTION("containers are hinted from their element count")
    {
        CHECK(nlohmann::detail::binary_reserve_hint(json::array()) == 1);
        CHECK(nlohmann::detail::binary_reserve_hint(json::array({1, 2, 3})) == 4);
        CHECK(nlohmann::detail::binary_reserve_hint(json::object()) == 1);
        CHECK(nlohmann::detail::binary_reserve_hint(json({{"a", 1}, {"b", 2}})) == 5);
    }
}
