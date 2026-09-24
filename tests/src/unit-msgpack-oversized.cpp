//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Test for issue #5320: MessagePack serialization of oversized containers
// https://github.com/nlohmann/json/issues/5320

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <cstdint>
#include <limits>

namespace
{
// A binary container that reports a size beyond UINT32_MAX without allocating
// that much memory, so the MessagePack length overflow can be tested cheaply.
class huge_binary_t : public std::vector<std::uint8_t>
{
  public:
    using std::vector<std::uint8_t>::vector;

    size_type size() const noexcept // NOLINT(readability-convert-member-functions-to-static)
    {
        return static_cast<size_type>((std::numeric_limits<std::uint32_t>::max)()) + 1;
    }
};

using huge_binary_json = nlohmann::basic_json <
                         std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t,
                         double, std::allocator, nlohmann::adl_serializer, huge_binary_t, void >;

// A string type that can be made to report a size beyond UINT32_MAX without
// allocating that much memory.
class huge_string_t : public std::string
{
  public:
    using std::string::string;
    huge_string_t(const std::string& s) : std::string(s) {}

    static huge_string_t as_huge(const std::string& s)
    {
        huge_string_t result(s);
        result.pretend_huge = true;
        return result;
    }

    size_type size() const noexcept
    {
        if (pretend_huge)
        {
            return static_cast<size_type>((std::numeric_limits<std::uint32_t>::max)()) + 1;
        }
        return std::string::size();
    }

  private:
    bool pretend_huge = false;
};

using huge_string_json = nlohmann::basic_json <
                         std::map, std::vector, huge_string_t, bool, std::int64_t, std::uint64_t,
                         double, std::allocator, nlohmann::adl_serializer, std::vector<std::uint8_t>, void >;

} // namespace

TEST_CASE("MessagePack oversized containers (#5320)")
{
    SECTION("binary container exceeding UINT32_MAX throws out_of_range.412")
    {
        huge_binary_json j;
        j["b"] = huge_binary_json::binary(huge_binary_t{});

        CHECK_THROWS_WITH_AS(
            huge_binary_json::to_msgpack(j),
            "[json.exception.out_of_range.412] MessagePack length 4294967296 exceeds maximum of 4294967295",
            huge_binary_json::out_of_range&);
    }

    SECTION("string exceeding UINT32_MAX throws out_of_range.412")
    {
        huge_string_json j;
        j["s"] = huge_string_t::as_huge("value");

        CHECK_THROWS_WITH_AS(
            huge_string_json::to_msgpack(j),
            "[json.exception.out_of_range.412] MessagePack length 4294967296 exceeds maximum of 4294967295",
            huge_string_json::out_of_range&);
    }
}
