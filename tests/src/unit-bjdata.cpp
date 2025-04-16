//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <algorithm>
#include <climits>
#include <limits>
#include <iostream>
#include <fstream>
#include <set>
#include "make_test_data_available.hpp"
#include "test_utils.hpp"

namespace
{
class SaxCountdown
{
  public:
    explicit SaxCountdown(const int count) : events_left(count)
    {}

    bool null()
    {
        return events_left-- > 0;
    }

    bool boolean(bool /*unused*/)
    {
        return events_left-- > 0;
    }

    bool number_integer(json::number_integer_t /*unused*/)
    {
        return events_left-- > 0;
    }

    bool number_unsigned(json::number_unsigned_t /*unused*/)
    {
        return events_left-- > 0;
    }

    bool number_float(json::number_float_t /*unused*/, const std::string& /*unused*/)
    {
        return events_left-- > 0;
    }

    bool string(std::string& /*unused*/)
    {
        return events_left-- > 0;
    }

    bool binary(std::vector<std::uint8_t>& /*unused*/)
    {
        return events_left-- > 0;
    }

    bool start_object(std::size_t /*unused*/)
    {
        return events_left-- > 0;
    }

    bool key(std::string& /*unused*/)
    {
        return events_left-- > 0;
    }

    bool end_object()
    {
        return events_left-- > 0;
    }

    bool start_array(std::size_t /*unused*/)
    {
        return events_left-- > 0;
    }

    bool end_array()
    {
        return events_left-- > 0;
    }

    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const json::exception& /*unused*/) // NOLINT(readability-convert-member-functions-to-static)
    {
        return false;
    }

  private:
    int events_left = 0;
};
} // namespace

// at some point in the future, a unit test dedicated to type traits might be a good idea
template <typename OfType, typename T, bool MinInRange, bool MaxInRange>
struct trait_test_arg
{
    using of_type = OfType;
    using type = T;
    static constexpr bool min_in_range = MinInRange;
    static constexpr bool max_in_range = MaxInRange;
};

TEST_CASE_TEMPLATE_DEFINE("value_in_range_of trait", T, value_in_range_of_test) // NOLINT(readability-math-missing-parentheses)
{
    using nlohmann::detail::value_in_range_of;

    using of_type = typename T::of_type;
    using type = typename T::type;
    constexpr bool min_in_range = T::min_in_range;
    constexpr bool max_in_range = T::max_in_range;

    type const val_min = std::numeric_limits<type>::min();
    type const val_min2 = val_min + 1;
    type const val_max = std::numeric_limits<type>::max();
    type const val_max2 = val_max - 1;

    REQUIRE(CHAR_BIT == 8);

    std::string of_type_str;
    if (std::is_unsigned<of_type>::value)
    {
        of_type_str += "u";
    }
    of_type_str += "int";
    of_type_str += std::to_string(sizeof(of_type) * 8);

    INFO("of_type := ", of_type_str);

    std::string type_str;
    if (std::is_unsigned<type>::value)
    {
        type_str += "u";
    }
    type_str += "int";
    type_str += std::to_string(sizeof(type) * 8);

    INFO("type := ", type_str);

    CAPTURE(val_min);
    CAPTURE(min_in_range);
    CAPTURE(val_max);
    CAPTURE(max_in_range);

    if (min_in_range)
    {
        CHECK(value_in_range_of<of_type>(val_min));
        CHECK(value_in_range_of<of_type>(val_min2));
    }
    else
    {
        CHECK_FALSE(value_in_range_of<of_type>(val_min));
        CHECK_FALSE(value_in_range_of<of_type>(val_min2));
    }

    if (max_in_range)
    {
        CHECK(value_in_range_of<of_type>(val_max));
        CHECK(value_in_range_of<of_type>(val_max2));
    }
    else
    {
        CHECK_FALSE(value_in_range_of<of_type>(val_max));
        CHECK_FALSE(value_in_range_of<of_type>(val_max2));
    }
}

TEST_CASE_TEMPLATE_INVOKE(value_in_range_of_test, \
                          trait_test_arg<std::int32_t, std::int32_t, true, true>, \
                          trait_test_arg<std::int32_t, std::uint32_t, true, false>, \
                          trait_test_arg<std::uint32_t, std::int32_t, false, true>, \
                          trait_test_arg<std::uint32_t, std::uint32_t, true, true>, \
                          trait_test_arg<std::int32_t, std::int64_t, false, false>, \
                          trait_test_arg<std::int32_t, std::uint64_t, true, false>, \
                          trait_test_arg<std::uint32_t, std::int64_t, false, false>, \
                          trait_test_arg<std::uint32_t, std::uint64_t, true, false>, \
                          trait_test_arg<std::int64_t, std::int32_t, true, true>, \
                          trait_test_arg<std::int64_t, std::uint32_t, true, true>, \
                          trait_test_arg<std::uint64_t, std::int32_t, false, true>, \
                          trait_test_arg<std::uint64_t, std::uint32_t, true, true>, \
                          trait_test_arg<std::int64_t, std::int64_t, true, true>, \
                          trait_test_arg<std::int64_t, std::uint64_t, true, false>, \
                          trait_test_arg<std::uint64_t, std::int64_t, false, true>, \
                          trait_test_arg<std::uint64_t, std::uint64_t, true, true>);

#if SIZE_MAX == 0xffffffff
TEST_CASE_TEMPLATE_INVOKE(value_in_range_of_test, \
                          trait_test_arg<std::size_t, std::int32_t, false, true>, \
                          trait_test_arg<std::size_t, std::uint32_t, true, true>, \
                          trait_test_arg<std::size_t, std::int64_t, false, false>, \
                          trait_test_arg<std::size_t, std::uint64_t, true, false>);
#else
TEST_CASE_TEMPLATE_INVOKE(value_in_range_of_test, \
                          trait_test_arg<std::size_t, std::int32_t, false, true>, \
                          trait_test_arg<std::size_t, std::uint32_t, true, true>, \
                          trait_test_arg<std::size_t, std::int64_t, false, true>, \
                          trait_test_arg<std::size_t, std::uint64_t, true, true>);
#endif

TEST_CASE("BJData")
{
    SECTION("binary_reader BJData LUT arrays are sorted")
    {
        std::vector<std::uint8_t> const data;
        auto ia = nlohmann::detail::input_adapter(data);
        // NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
        nlohmann::detail::binary_reader<json, decltype(ia)> const br{std::move(ia), json::input_format_t::bjdata};

        CHECK(std::is_sorted(br.bjd_optimized_type_markers.begin(), br.bjd_optimized_type_markers.end()));
        CHECK(std::is_sorted(br.bjd_types_map.begin(), br.bjd_types_map.end()));
    }

    SECTION("individual values")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            json const j = json::value_t::discarded;
            const auto result = json::to_bjdata(j);
            CHECK(result.empty());
        }

        SECTION("null")
        {
            json const j = nullptr;
            std::vector<uint8_t> const expected = {'Z'};
            const auto result = json::to_bjdata(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_bjdata(result) == j);
            CHECK(json::from_bjdata(result, true, false) == j);
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json const j = true;
                std::vector<uint8_t> const expected = {'T'};
                const auto result = json::to_bjdata(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_bjdata(result) == j);
                CHECK(json::from_bjdata(result, true, false) == j);
            }

            SECTION("false")
            {
                json const j = false;
                std::vector<uint8_t> const expected = {'F'};
                const auto result = json::to_bjdata(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_bjdata(result) == j);
                CHECK(json::from_bjdata(result, true, false) == j);
            }
        }

        SECTION("byte")
        {
            SECTION("0..255 (uint8)")
            {
                for (size_t i = 0; i <= 255; ++i)
                {
                    CAPTURE(i)

                    // create JSON value with integer number (no byte type in JSON)
                    json j = -1;
                    j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                    // check type
                    CHECK(j.is_number_integer());

                    // create byte vector
                    std::vector<uint8_t> const value
                    {
                        static_cast<uint8_t>('B'),
                        static_cast<uint8_t>(i),
                    };

                    // compare value
                    CHECK(json::from_bjdata(value) == j);
                }
            }
        }

        SECTION("number")
        {
            SECTION("signed")
            {
                SECTION("-9223372036854775808..-2147483649 (int64)")
                {
                    std::vector<int64_t> const numbers
                    {
                        (std::numeric_limits<int64_t>::min)(),
                        -1000000000000000000LL,
                        -100000000000000000LL,
                        -10000000000000000LL,
                        -1000000000000000LL,
                        -100000000000000LL,
                        -10000000000000LL,
                        -1000000000000LL,
                        -100000000000LL,
                        -10000000000LL,
                        -2147483649LL,
                    };
                    for (const auto i : numbers)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            static_cast<uint8_t>('L'),
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 24) & 0xff),
                            static_cast<uint8_t>((i >> 32) & 0xff),
                            static_cast<uint8_t>((i >> 40) & 0xff),
                            static_cast<uint8_t>((i >> 48) & 0xff),
                            static_cast<uint8_t>((i >> 56) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
                        int64_t const restored = (static_cast<int64_t>(result[8]) << 070) +
                                                 (static_cast<int64_t>(result[7]) << 060) +
                                                 (static_cast<int64_t>(result[6]) << 050) +
                                                 (static_cast<int64_t>(result[5]) << 040) +
                                                 (static_cast<int64_t>(result[4]) << 030) +
                                                 (static_cast<int64_t>(result[3]) << 020) +
                                                 (static_cast<int64_t>(result[2]) << 010) +
                                                 static_cast<int64_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("-2147483648..-32769 (int32)")
                {
                    std::vector<int32_t> const numbers
                    {
                        -32769,
                        -100000,
                        -1000000,
                        -10000000,
                        -100000000,
                        -1000000000,
                        -2147483647 - 1, // https://stackoverflow.com/a/29356002/266378
                    };
                    for (const auto i : numbers)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            static_cast<uint8_t>('l'),
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 24) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        int32_t const restored = (static_cast<int32_t>(result[4]) << 030) +
                                                 (static_cast<int32_t>(result[3]) << 020) +
                                                 (static_cast<int32_t>(result[2]) << 010) +
                                                 static_cast<int32_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("-32768..-129 (int16)")
                {
                    for (int32_t i = -32768; i <= -129; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            static_cast<uint8_t>('I'),
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        auto const restored = static_cast<int16_t>(((result[2] << 8) + result[1]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("-9263 (int16)")
                {
                    json const j = -9263;
                    std::vector<uint8_t> const expected = {'I', 0xd1, 0xdb};

                    // compare result + size
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);
                    CHECK(result.size() == 3);

                    // check individual bytes
                    CHECK(result[0] == 'I');
                    auto const restored = static_cast<int16_t>(((result[2] << 8) + result[1]));
                    CHECK(restored == -9263);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("-128..-1 (int8)")
                {
                    for (auto i = -128; i <= -1; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'i',
                            static_cast<uint8_t>(i),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        CHECK(static_cast<int8_t>(result[1]) == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("0..127 (int8)")
                {
                    for (size_t i = 0; i <= 127; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            static_cast<uint8_t>('i'),
                            static_cast<uint8_t>(i),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        CHECK(result[1] == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("128..255 (uint8)")
                {
                    for (size_t i = 128; i <= 255; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            static_cast<uint8_t>('U'),
                            static_cast<uint8_t>(i),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'U');
                        CHECK(result[1] == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("256..32767 (int16)")
                {
                    for (size_t i = 256; i <= 32767; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            static_cast<uint8_t>('I'),
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        auto const restored = static_cast<uint16_t>((static_cast<uint8_t>(result[2]) * 256) + static_cast<uint8_t>(result[1]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("32768..65535 (uint16)")
                {
                    for (const uint32_t i :
                            {
                                32768u, 55555u, 65535u
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            static_cast<uint8_t>('u'),
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'u');
                        auto const restored = static_cast<uint16_t>((static_cast<uint8_t>(result[2]) * 256) + static_cast<uint8_t>(result[1]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("65536..2147483647 (int32)")
                {
                    for (const uint32_t i :
                            {
                                65536u, 77777u, 2147483647u
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'l',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 24) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        uint32_t const restored = (static_cast<uint32_t>(result[4]) << 030) +
                                                  (static_cast<uint32_t>(result[3]) << 020) +
                                                  (static_cast<uint32_t>(result[2]) << 010) +
                                                  static_cast<uint32_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("2147483648..4294967295 (uint32)")
                {
                    for (const uint32_t i :
                            {
                                2147483648u, 3333333333u, 4294967295u
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'm',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 24) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'm');
                        uint32_t const restored = (static_cast<uint32_t>(result[4]) << 030) +
                                                  (static_cast<uint32_t>(result[3]) << 020) +
                                                  (static_cast<uint32_t>(result[2]) << 010) +
                                                  static_cast<uint32_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("4294967296..9223372036854775807 (int64)")
                {
                    std::vector<uint64_t> const v = {4294967296LU, 9223372036854775807LU};
                    for (const uint64_t i : v)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'L',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 010) & 0xff),
                            static_cast<uint8_t>((i >> 020) & 0xff),
                            static_cast<uint8_t>((i >> 030) & 0xff),
                            static_cast<uint8_t>((i >> 040) & 0xff),
                            static_cast<uint8_t>((i >> 050) & 0xff),
                            static_cast<uint8_t>((i >> 060) & 0xff),
                            static_cast<uint8_t>((i >> 070) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
                        uint64_t const restored = (static_cast<uint64_t>(result[8]) << 070) +
                                                  (static_cast<uint64_t>(result[7]) << 060) +
                                                  (static_cast<uint64_t>(result[6]) << 050) +
                                                  (static_cast<uint64_t>(result[5]) << 040) +
                                                  (static_cast<uint64_t>(result[4]) << 030) +
                                                  (static_cast<uint64_t>(result[3]) << 020) +
                                                  (static_cast<uint64_t>(result[2]) << 010) +
                                                  static_cast<uint64_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("9223372036854775808..18446744073709551615 (uint64)")
                {
                    std::vector<uint64_t> const v = {9223372036854775808ull, 18446744073709551615ull};
                    for (const uint64_t i : v)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'M',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 010) & 0xff),
                            static_cast<uint8_t>((i >> 020) & 0xff),
                            static_cast<uint8_t>((i >> 030) & 0xff),
                            static_cast<uint8_t>((i >> 040) & 0xff),
                            static_cast<uint8_t>((i >> 050) & 0xff),
                            static_cast<uint8_t>((i >> 060) & 0xff),
                            static_cast<uint8_t>((i >> 070) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'M');
                        uint64_t const restored = (static_cast<uint64_t>(result[8]) << 070) +
                                                  (static_cast<uint64_t>(result[7]) << 060) +
                                                  (static_cast<uint64_t>(result[6]) << 050) +
                                                  (static_cast<uint64_t>(result[5]) << 040) +
                                                  (static_cast<uint64_t>(result[4]) << 030) +
                                                  (static_cast<uint64_t>(result[3]) << 020) +
                                                  (static_cast<uint64_t>(result[2]) << 010) +
                                                  static_cast<uint64_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }
            }

            SECTION("unsigned")
            {
                SECTION("0..127 (int8)")
                {
                    for (size_t i = 0; i <= 127; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected{'i', static_cast<uint8_t>(i)};

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        auto const restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("128..255 (uint8)")
                {
                    for (size_t i = 128; i <= 255; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected{'U', static_cast<uint8_t>(i)};

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'U');
                        auto const restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("256..32767 (int16)")
                {
                    for (size_t i = 256; i <= 32767; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'I',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        auto const restored = static_cast<uint16_t>((static_cast<uint8_t>(result[2]) * 256) + static_cast<uint8_t>(result[1]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("32768..65535 (uint16)")
                {
                    for (const uint32_t i :
                            {
                                32768u, 55555u, 65535u
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'u',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'u');
                        auto const restored = static_cast<uint16_t>((static_cast<uint8_t>(result[2]) * 256) + static_cast<uint8_t>(result[1]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }
                SECTION("65536..2147483647 (int32)")
                {
                    for (const uint32_t i :
                            {
                                65536u, 77777u, 2147483647u
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'l',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 24) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        uint32_t const restored = (static_cast<uint32_t>(result[4]) << 030) +
                                                  (static_cast<uint32_t>(result[3]) << 020) +
                                                  (static_cast<uint32_t>(result[2]) << 010) +
                                                  static_cast<uint32_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("2147483648..4294967295 (uint32)")
                {
                    for (const uint32_t i :
                            {
                                2147483648u, 3333333333u, 4294967295u
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'm',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 24) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'm');
                        uint32_t const restored = (static_cast<uint32_t>(result[4]) << 030) +
                                                  (static_cast<uint32_t>(result[3]) << 020) +
                                                  (static_cast<uint32_t>(result[2]) << 010) +
                                                  static_cast<uint32_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("4294967296..9223372036854775807 (int64)")
                {
                    std::vector<uint64_t> const v = {4294967296ul, 9223372036854775807ul};
                    for (const uint64_t i : v)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'L',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 010) & 0xff),
                            static_cast<uint8_t>((i >> 020) & 0xff),
                            static_cast<uint8_t>((i >> 030) & 0xff),
                            static_cast<uint8_t>((i >> 040) & 0xff),
                            static_cast<uint8_t>((i >> 050) & 0xff),
                            static_cast<uint8_t>((i >> 060) & 0xff),
                            static_cast<uint8_t>((i >> 070) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
                        uint64_t const restored = (static_cast<uint64_t>(result[8]) << 070) +
                                                  (static_cast<uint64_t>(result[7]) << 060) +
                                                  (static_cast<uint64_t>(result[6]) << 050) +
                                                  (static_cast<uint64_t>(result[5]) << 040) +
                                                  (static_cast<uint64_t>(result[4]) << 030) +
                                                  (static_cast<uint64_t>(result[3]) << 020) +
                                                  (static_cast<uint64_t>(result[2]) << 010) +
                                                  static_cast<uint64_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }

                SECTION("9223372036854775808..18446744073709551615 (uint64)")
                {
                    std::vector<uint64_t> const v = {9223372036854775808ull, 18446744073709551615ull};
                    for (const uint64_t i : v)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            'M',
                            static_cast<uint8_t>(i & 0xff),
                            static_cast<uint8_t>((i >> 010) & 0xff),
                            static_cast<uint8_t>((i >> 020) & 0xff),
                            static_cast<uint8_t>((i >> 030) & 0xff),
                            static_cast<uint8_t>((i >> 040) & 0xff),
                            static_cast<uint8_t>((i >> 050) & 0xff),
                            static_cast<uint8_t>((i >> 060) & 0xff),
                            static_cast<uint8_t>((i >> 070) & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_bjdata(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'M');
                        uint64_t const restored = (static_cast<uint64_t>(result[8]) << 070) +
                                                  (static_cast<uint64_t>(result[7]) << 060) +
                                                  (static_cast<uint64_t>(result[6]) << 050) +
                                                  (static_cast<uint64_t>(result[5]) << 040) +
                                                  (static_cast<uint64_t>(result[4]) << 030) +
                                                  (static_cast<uint64_t>(result[3]) << 020) +
                                                  (static_cast<uint64_t>(result[2]) << 010) +
                                                  static_cast<uint64_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_bjdata(result) == j);
                        CHECK(json::from_bjdata(result, true, false) == j);
                    }
                }
            }
            SECTION("float64")
            {
                SECTION("3.1415925")
                {
                    double v = 3.1415925;
                    json const j = v;
                    std::vector<uint8_t> const expected =
                    {
                        'D', 0xfc, 0xde, 0xa6, 0x3f, 0xfb, 0x21, 0x09, 0x40
                    };
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result) == v);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("half-precision float")
            {
                SECTION("simple half floats")
                {
                    CHECK(json::parse("0.0") == json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x00})));
                    CHECK(json::parse("-0.0") == json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x80})));
                    CHECK(json::parse("1.0") == json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x3c})));
                    CHECK(json::parse("1.5") == json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x3e})));
                    CHECK(json::parse("65504.0") == json::from_bjdata(std::vector<uint8_t>({'h', 0xff, 0x7b})));
                }

                SECTION("errors")
                {
                    SECTION("no byte follows")
                    {
                        json _;
                        std::vector<uint8_t> const vec0 = {'h'};
                        CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vec0), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
                        CHECK(json::from_bjdata(vec0, true, false).is_discarded());
                    }

                    SECTION("only one byte follows")
                    {
                        json _;
                        std::vector<uint8_t> const vec1 = {'h', 0x00};
                        CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vec1), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
                        CHECK(json::from_bjdata(vec1, true, false).is_discarded());
                    }
                }
            }

            SECTION("half-precision float (edge cases)")
            {
                SECTION("exp = 0b00000")
                {
                    SECTION("0 (0 00000 0000000000)")
                    {
                        json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x00}));
                        json::number_float_t d{j};
                        CHECK(d == 0.0);
                    }

                    SECTION("-0 (1 00000 0000000000)")
                    {
                        json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x80}));
                        json::number_float_t d{j};
                        CHECK(d == -0.0);
                    }

                    SECTION("2**-24 (0 00000 0000000001)")
                    {
                        json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x01, 0x00}));
                        json::number_float_t d{j};
                        CHECK(d == std::pow(2.0, -24.0));
                    }
                }

                SECTION("exp = 0b11111")
                {
                    SECTION("infinity (0 11111 0000000000)")
                    {
                        json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x7c}));
                        json::number_float_t d{j};
                        CHECK(d == std::numeric_limits<json::number_float_t>::infinity());
                        CHECK(j.dump() == "null");
                    }

                    SECTION("-infinity (1 11111 0000000000)")
                    {
                        json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0xfc}));
                        json::number_float_t d{j};
                        CHECK(d == -std::numeric_limits<json::number_float_t>::infinity());
                        CHECK(j.dump() == "null");
                    }
                }

                SECTION("other values from https://en.wikipedia.org/wiki/Half-precision_floating-point_format")
                {
                    SECTION("1 (0 01111 0000000000)")
                    {
                        json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x3c}));
                        json::number_float_t d{j};
                        CHECK(d == 1);
                    }

                    SECTION("-2 (1 10000 0000000000)")
                    {
                        json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0xc0}));
                        json::number_float_t d{j};
                        CHECK(d == -2);
                    }

                    SECTION("65504 (0 11110 1111111111)")
                    {
                        json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0xff, 0x7b}));
                        json::number_float_t d{j};
                        CHECK(d == 65504);
                    }
                }

                SECTION("infinity")
                {
                    json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x7c}));
                    json::number_float_t const d{j};
                    CHECK_FALSE(std::isfinite(d));
                    CHECK(j.dump() == "null");
                }

                SECTION("NaN")
                {
                    json const j = json::from_bjdata(std::vector<uint8_t>({'h', 0x00, 0x7e }));
                    json::number_float_t const d{j};
                    CHECK(std::isnan(d));
                    CHECK(j.dump() == "null");
                }
            }

            SECTION("high-precision number")
            {
                SECTION("unsigned integer number")
                {
                    std::vector<uint8_t> const vec = {'H', 'i', 0x14, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
                    const auto j = json::from_bjdata(vec);
                    CHECK(j.is_number_unsigned());
                    CHECK(j.dump() == "12345678901234567890");
                }

                SECTION("signed integer number")
                {
                    std::vector<uint8_t> const vec = {'H', 'i', 0x13, '-', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8'};
                    const auto j = json::from_bjdata(vec);
                    CHECK(j.is_number_integer());
                    CHECK(j.dump() == "-123456789012345678");
                }

                SECTION("floating-point number")
                {
                    std::vector<uint8_t> const vec = {'H', 'i', 0x16, '3', '.', '1', '4', '1', '5', '9',  '2', '6', '5', '3', '5', '8', '9',  '7', '9', '3', '2', '3', '8', '4',  '6'};
                    const auto j = json::from_bjdata(vec);
                    CHECK(j.is_number_float());
                    CHECK(j.dump() == "3.141592653589793");
                }

                SECTION("errors")
                {
                    // error while parsing length
                    std::vector<uint8_t> const vec0 = {'H', 'i'};
                    CHECK(json::from_bjdata(vec0, true, false).is_discarded());
                    // error while parsing string
                    std::vector<uint8_t> const vec1 = {'H', 'i', '1'};
                    CHECK(json::from_bjdata(vec1, true, false).is_discarded());

                    json _;
                    std::vector<uint8_t> const vec2 = {'H', 'i', 2, '1', 'A', '3'};
                    CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vec2), "[json.exception.parse_error.115] parse error at byte 5: syntax error while parsing BJData high-precision number: invalid number text: 1A", json::parse_error);
                    std::vector<uint8_t> const vec3 = {'H', 'i', 2, '1', '.'};
                    CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vec3), "[json.exception.parse_error.115] parse error at byte 5: syntax error while parsing BJData high-precision number: invalid number text: 1.", json::parse_error);
                    std::vector<uint8_t> const vec4 = {'H', 2, '1', '0'};
                    CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vec4), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing BJData size: expected length type specification (U, i, u, I, m, l, M, L) after '#'; last byte: 0x02", json::parse_error);
                }
            }
        }

        SECTION("string")
        {
            SECTION("N = 0..127")
            {
                for (size_t N = 0; N <= 127; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json const j = s;

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    expected.push_back('S');
                    expected.push_back('i');
                    expected.push_back(static_cast<uint8_t>(N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back('x');
                    }

                    // compare result + size
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 3);
                    // check that no null byte is appended
                    if (N > 0)
                    {
                        CHECK(result.back() != '\x00');
                    }

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("N = 128..255")
            {
                for (size_t N = 128; N <= 255; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json const j = s;

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    expected.push_back('S');
                    expected.push_back('U');
                    expected.push_back(static_cast<uint8_t>(N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back('x');
                    }

                    // compare result + size
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 3);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("N = 256..32767")
            {
                for (const size_t N :
                        {
                            256u, 999u, 1025u, 3333u, 2048u, 32767u
                        })
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json const j = s;

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), 'I');
                    expected.insert(expected.begin(), 'S');

                    // compare result + size
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 4);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("N = 32768..65535")
            {
                for (const size_t N :
                        {
                            32768u, 55555u, 65535u
                        })
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json const j = s;

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), 'u');
                    expected.insert(expected.begin(), 'S');

                    // compare result + size
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 4);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("N = 65536..2147483647")
            {
                for (const size_t N :
                        {
                            65536u, 77777u, 1048576u
                        })
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json const j = s;

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 24) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 16) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), 'l');
                    expected.insert(expected.begin(), 'S');

                    // compare result + size
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 6);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }
        }

        SECTION("binary")
        {
            for (json::bjdata_version_t bjdata_version :
                    {
                        json::bjdata_version_t::draft2, json::bjdata_version_t::draft3
                    })
            {
                CAPTURE(bjdata_version)
                const bool draft3 = (bjdata_version == json::bjdata_version_t::draft3);

                SECTION("N = 0..127")
                {
                    for (std::size_t N = 0; N <= 127; ++N)
                    {
                        CAPTURE(N)

                        // create JSON value with byte array containing of N * 'x'
                        const auto s = std::vector<std::uint8_t>(N, 'x');
                        json const j = json::binary(s);

                        // create expected byte vector
                        std::vector<std::uint8_t> expected;
                        expected.push_back(static_cast<std::uint8_t>('['));
                        if (draft3 || N != 0)
                        {
                            expected.push_back(static_cast<std::uint8_t>('$'));
                            expected.push_back(static_cast<std::uint8_t>(draft3 ? 'B' : 'U'));
                        }
                        expected.push_back(static_cast<std::uint8_t>('#'));
                        expected.push_back(static_cast<std::uint8_t>('i'));
                        expected.push_back(static_cast<std::uint8_t>(N));
                        for (size_t i = 0; i < N; ++i)
                        {
                            expected.push_back(0x78);
                        }

                        // compare result + size
                        const auto result = json::to_bjdata(j, true, true, bjdata_version);
                        CHECK(result == expected);
                        if (!draft3 && N == 0)
                        {
                            CHECK(result.size() == N + 4);
                        }
                        else
                        {
                            CHECK(result.size() == N + 6);
                        }

                        // check that no null byte is appended
                        if (N > 0)
                        {
                            CHECK(result.back() != '\x00');
                        }

                        if (draft3)
                        {
                            // roundtrip
                            CHECK(json::from_bjdata(result) == j);
                            CHECK(json::from_bjdata(result, true, false) == j);
                        }
                        else
                        {
                            // roundtrip only works to an array of numbers
                            json j_out = s;
                            CHECK(json::from_bjdata(result) == j_out);
                            CHECK(json::from_bjdata(result, true, false) == j_out);
                        }
                    }
                }

                SECTION("N = 128..255")
                {
                    for (std::size_t N = 128; N <= 255; ++N)
                    {
                        CAPTURE(N)

                        // create JSON value with byte array containing of N * 'x'
                        const auto s = std::vector<std::uint8_t>(N, 'x');
                        json const j = json::binary(s);

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<std::uint8_t>('['));
                        expected.push_back(static_cast<std::uint8_t>('$'));
                        expected.push_back(static_cast<std::uint8_t>(draft3 ? 'B' : 'U'));
                        expected.push_back(static_cast<std::uint8_t>('#'));
                        expected.push_back(static_cast<std::uint8_t>('U'));
                        expected.push_back(static_cast<std::uint8_t>(N));
                        for (size_t i = 0; i < N; ++i)
                        {
                            expected.push_back(0x78);
                        }

                        // compare result + size
                        const auto result = json::to_bjdata(j, true, true, bjdata_version);
                        CHECK(result == expected);
                        CHECK(result.size() == N + 6);
                        // check that no null byte is appended
                        CHECK(result.back() != '\x00');

                        if (draft3)
                        {
                            // roundtrip
                            CHECK(json::from_bjdata(result) == j);
                            CHECK(json::from_bjdata(result, true, false) == j);
                        }
                        else
                        {
                            // roundtrip only works to an array of numbers
                            json j_out = s;
                            CHECK(json::from_bjdata(result) == j_out);
                            CHECK(json::from_bjdata(result, true, false) == j_out);
                        }
                    }
                }

                SECTION("N = 256..32767")
                {
                    for (const std::size_t N :
                            {
                                256u, 999u, 1025u, 3333u, 2048u, 32767u
                            })
                    {
                        CAPTURE(N)

                        // create JSON value with byte array containing of N * 'x'
                        const auto s = std::vector<std::uint8_t>(N, 'x');
                        json const j = json::binary(s);

                        // create expected byte vector
                        std::vector<std::uint8_t> expected(N + 7, 'x');
                        expected[0] = '[';
                        expected[1] = '$';
                        expected[2] = draft3 ? 'B' : 'U';
                        expected[3] = '#';
                        expected[4] = 'I';
                        expected[5] = static_cast<std::uint8_t>(N & 0xFF);
                        expected[6] = static_cast<std::uint8_t>((N >> 8) & 0xFF);

                        // compare result + size
                        const auto result = json::to_bjdata(j, true, true, bjdata_version);
                        CHECK(result == expected);
                        CHECK(result.size() == N + 7);
                        // check that no null byte is appended
                        CHECK(result.back() != '\x00');

                        if (draft3)
                        {
                            // roundtrip
                            CHECK(json::from_bjdata(result) == j);
                            CHECK(json::from_bjdata(result, true, false) == j);
                        }
                        else
                        {
                            // roundtrip only works to an array of numbers
                            json j_out = s;
                            CHECK(json::from_bjdata(result) == j_out);
                            CHECK(json::from_bjdata(result, true, false) == j_out);
                        }
                    }
                }

                SECTION("N = 32768..65535")
                {
                    for (const std::size_t N :
                            {
                                32768u, 55555u, 65535u
                            })
                    {
                        CAPTURE(N)

                        // create JSON value with byte array containing of N * 'x'
                        const auto s = std::vector<std::uint8_t>(N, 'x');
                        json const j = json::binary(s);

                        // create expected byte vector
                        std::vector<std::uint8_t> expected(N + 7, 'x');
                        expected[0] = '[';
                        expected[1] = '$';
                        expected[2] = draft3 ? 'B' : 'U';
                        expected[3] = '#';
                        expected[4] = 'u';
                        expected[5] = static_cast<std::uint8_t>(N & 0xFF);
                        expected[6] = static_cast<std::uint8_t>((N >> 8) & 0xFF);

                        // compare result + size
                        const auto result = json::to_bjdata(j, true, true, bjdata_version);
                        CHECK(result == expected);
                        CHECK(result.size() == N + 7);
                        // check that no null byte is appended
                        CHECK(result.back() != '\x00');

                        if (draft3)
                        {
                            // roundtrip
                            CHECK(json::from_bjdata(result) == j);
                            CHECK(json::from_bjdata(result, true, false) == j);
                        }
                        else
                        {
                            // roundtrip only works to an array of numbers
                            json j_out = s;
                            CHECK(json::from_bjdata(result) == j_out);
                            CHECK(json::from_bjdata(result, true, false) == j_out);
                        }
                    }
                }

                SECTION("N = 65536..2147483647")
                {
                    for (const std::size_t N :
                            {
                                65536u, 77777u, 1048576u
                            })
                    {
                        CAPTURE(N)

                        // create JSON value with byte array containing of N * 'x'
                        const auto s = std::vector<std::uint8_t>(N, 'x');
                        json const j = json::binary(s);

                        // create expected byte vector
                        std::vector<std::uint8_t> expected(N + 9, 'x');
                        expected[0] = '[';
                        expected[1] = '$';
                        expected[2] = draft3 ? 'B' : 'U';
                        expected[3] = '#';
                        expected[4] = 'l';
                        expected[5] = static_cast<std::uint8_t>(N & 0xFF);
                        expected[6] = static_cast<std::uint8_t>((N >> 8) & 0xFF);
                        expected[7] = static_cast<std::uint8_t>((N >> 16) & 0xFF);
                        expected[8] = static_cast<std::uint8_t>((N >> 24) & 0xFF);

                        // compare result + size
                        const auto result = json::to_bjdata(j, true, true, bjdata_version);
                        CHECK(result == expected);
                        CHECK(result.size() == N + 9);
                        // check that no null byte is appended
                        CHECK(result.back() != '\x00');

                        if (draft3)
                        {
                            // roundtrip
                            CHECK(json::from_bjdata(result) == j);
                            CHECK(json::from_bjdata(result, true, false) == j);
                        }
                        else
                        {
                            // roundtrip only works to an array of numbers
                            json j_out = s;
                            CHECK(json::from_bjdata(result) == j_out);
                            CHECK(json::from_bjdata(result, true, false) == j_out);
                        }
                    }
                }

                SECTION("Other Serializations")
                {
                    const std::size_t N = 10;
                    const auto s = std::vector<std::uint8_t>(N, 'x');
                    json const j = json::binary(s);

                    SECTION("No Count No Type")
                    {
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<std::uint8_t>('['));
                        for (std::size_t i = 0; i < N; ++i)
                        {
                            expected.push_back(static_cast<std::uint8_t>(draft3 ? 'B' : 'U'));
                            expected.push_back(static_cast<std::uint8_t>(0x78));
                        }
                        expected.push_back(static_cast<std::uint8_t>(']'));

                        // compare result + size
                        const auto result = json::to_bjdata(j, false, false, bjdata_version);
                        CHECK(result == expected);
                        CHECK(result.size() == N + 12);
                        // check that no null byte is appended
                        CHECK(result.back() != '\x00');

                        // roundtrip only works to an array of numbers
                        json j_out = s;
                        CHECK(json::from_bjdata(result) == j_out);
                        CHECK(json::from_bjdata(result, true, false) == j_out);
                    }

                    SECTION("Yes Count No Type")
                    {
                        std::vector<std::uint8_t> expected;
                        expected.push_back(static_cast<std::uint8_t>('['));
                        expected.push_back(static_cast<std::uint8_t>('#'));
                        expected.push_back(static_cast<std::uint8_t>('i'));
                        expected.push_back(static_cast<std::uint8_t>(N));

                        for (size_t i = 0; i < N; ++i)
                        {
                            expected.push_back(static_cast<std::uint8_t>(draft3 ? 'B' : 'U'));
                            expected.push_back(static_cast<std::uint8_t>(0x78));
                        }

                        // compare result + size
                        const auto result = json::to_bjdata(j, true, false, bjdata_version);
                        CHECK(result == expected);
                        CHECK(result.size() == N + 14);
                        // check that no null byte is appended
                        CHECK(result.back() != '\x00');

                        // roundtrip only works to an array of numbers
                        json j_out = s;
                        CHECK(json::from_bjdata(result) == j_out);
                        CHECK(json::from_bjdata(result, true, false) == j_out);
                    }
                }
            }
        }
        SECTION("array")
        {
            SECTION("empty")
            {
                SECTION("size=false type=false")
                {
                    json const j = json::array();
                    std::vector<uint8_t> const expected = {'[', ']'};
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::array();
                    std::vector<uint8_t> const expected = {'[', '#', 'i', 0};
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::array();
                    std::vector<uint8_t> const expected = {'[', '#', 'i', 0};
                    const auto result = json::to_bjdata(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("[null]")
            {
                SECTION("size=false type=false")
                {
                    json const j = {nullptr};
                    std::vector<uint8_t> const expected = {'[', 'Z', ']'};
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = {nullptr};
                    std::vector<uint8_t> const expected = {'[', '#', 'i', 1, 'Z'};
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = {nullptr};
                    std::vector<uint8_t> const expected = {'[', '#', 'i', 1, 'Z'};
                    const auto result = json::to_bjdata(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("[1,2,3,4,5]")
            {
                SECTION("size=false type=false")
                {
                    json const j = json::parse("[1,2,3,4,5]");
                    std::vector<uint8_t> const expected = {'[', 'i', 1, 'i', 2, 'i', 3, 'i', 4, 'i', 5, ']'};
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::parse("[1,2,3,4,5]");
                    std::vector<uint8_t> const expected = {'[', '#', 'i', 5, 'i', 1, 'i', 2, 'i', 3, 'i', 4, 'i', 5};
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::parse("[1,2,3,4,5]");
                    std::vector<uint8_t> const expected = {'[', '$', 'i', '#', 'i', 5, 1, 2, 3, 4, 5};
                    const auto result = json::to_bjdata(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("[[[[]]]]")
            {
                SECTION("size=false type=false")
                {
                    json const j = json::parse("[[[[]]]]");
                    std::vector<uint8_t> const expected = {'[', '[', '[', '[', ']', ']', ']', ']'};
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::parse("[[[[]]]]");
                    std::vector<uint8_t> const expected = {'[', '#', 'i', 1, '[', '#', 'i', 1, '[', '#', 'i', 1, '[', '#', 'i', 0};
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::parse("[[[[]]]]");
                    std::vector<uint8_t> const expected = {'[', '#', 'i', 1, '[', '#', 'i', 1, '[', '#', 'i', 1, '[', '#', 'i', 0};
                    const auto result = json::to_bjdata(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("array with int16_t elements")
            {
                SECTION("size=false type=false")
                {
                    json j(257, nullptr);
                    std::vector<uint8_t> expected(j.size() + 2, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[258] = ']'; // closing array
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json j(257, nullptr);
                    std::vector<uint8_t> expected(j.size() + 5, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[1] = '#'; // array size
                    expected[2] = 'I'; // int16
                    expected[3] = 0x01; // 0x0101, first byte
                    expected[4] = 0x01; // 0x0101, second byte
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("array with uint16_t elements")
            {
                SECTION("size=false type=false")
                {
                    json j(32768, nullptr);
                    std::vector<uint8_t> expected(j.size() + 2, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[32769] = ']'; // closing array
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json j(32768, nullptr);
                    std::vector<uint8_t> expected(j.size() + 5, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[1] = '#'; // array size
                    expected[2] = 'u'; // int16
                    expected[3] = 0x00; // 0x0101, first byte
                    expected[4] = 0x80; // 0x0101, second byte
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("array with int32_t elements")
            {
                SECTION("size=false type=false")
                {
                    json j(65793, nullptr);
                    std::vector<uint8_t> expected(j.size() + 2, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[65794] = ']'; // closing array
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json j(65793, nullptr);
                    std::vector<uint8_t> expected(j.size() + 7, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[1] = '#'; // array size
                    expected[2] = 'l'; // int32
                    expected[3] = 0x01; // 0x00010101, fourth byte
                    expected[4] = 0x01; // 0x00010101, third byte
                    expected[5] = 0x01; // 0x00010101, second byte
                    expected[6] = 0x00; // 0x00010101, first byte
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty")
            {
                SECTION("size=false type=false")
                {
                    json const j = json::object();
                    std::vector<uint8_t> const expected = {'{', '}'};
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::object();
                    std::vector<uint8_t> const expected = {'{', '#', 'i', 0};
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::object();
                    std::vector<uint8_t> const expected = {'{', '#', 'i', 0};
                    const auto result = json::to_bjdata(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("{\"\":null}")
            {
                SECTION("size=false type=false")
                {
                    json const j = {{"", nullptr}};
                    std::vector<uint8_t> const expected = {'{', 'i', 0, 'Z', '}'};
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = {{"", nullptr}};
                    std::vector<uint8_t> const expected = {'{', '#', 'i', 1, 'i', 0, 'Z'};
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }

            SECTION("{\"a\": {\"b\": {\"c\": {}}}}")
            {
                SECTION("size=false type=false")
                {
                    json const j = json::parse(R"({"a": {"b": {"c": {}}}})");
                    std::vector<uint8_t> const expected =
                    {
                        '{', 'i', 1, 'a', '{', 'i', 1, 'b', '{', 'i', 1, 'c', '{', '}', '}', '}', '}'
                    };
                    const auto result = json::to_bjdata(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::parse(R"({"a": {"b": {"c": {}}}})");
                    std::vector<uint8_t> const expected =
                    {
                        '{', '#', 'i', 1, 'i', 1, 'a', '{', '#', 'i', 1, 'i', 1, 'b', '{', '#', 'i', 1, 'i', 1, 'c', '{', '#', 'i', 0
                    };
                    const auto result = json::to_bjdata(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }

                SECTION("size=true type=true ignore object type marker")
                {
                    json const j = json::parse(R"({"a": {"b": {"c": {}}}})");
                    std::vector<uint8_t> const expected =
                    {
                        '{', '#', 'i', 1, 'i', 1, 'a', '{', '#', 'i', 1, 'i', 1, 'b', '{', '#', 'i', 1, 'i', 1, 'c', '{', '#', 'i', 0
                    };
                    const auto result = json::to_bjdata(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_bjdata(result) == j);
                    CHECK(json::from_bjdata(result, true, false) == j);
                }
            }
        }
    }

    SECTION("errors")
    {
        SECTION("strict mode")
        {
            std::vector<uint8_t> const vec = {'Z', 'Z'};
            SECTION("non-strict mode")
            {
                const auto result = json::from_bjdata(vec, false);
                CHECK(result == json());
            }

            SECTION("strict mode")
            {
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vec),
                                     "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BJData value: expected end of input; last byte: 0x5A", json::parse_error&);
            }
        }
    }

    SECTION("SAX aborts")
    {
        SECTION("start_array()")
        {
            std::vector<uint8_t> const v = {'[', 'T', 'F', ']'};
            SaxCountdown scp(0);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("start_object()")
        {
            std::vector<uint8_t> const v = {'{', 'i', 3, 'f', 'o', 'o', 'F', '}'};
            SaxCountdown scp(0);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("key() in object")
        {
            std::vector<uint8_t> const v = {'{', 'i', 3, 'f', 'o', 'o', 'F', '}'};
            SaxCountdown scp(1);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("start_array(len)")
        {
            std::vector<uint8_t> const v = {'[', '#', 'i', '2', 'T', 'F'};
            SaxCountdown scp(0);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("start_object(len)")
        {
            std::vector<uint8_t> const v = {'{', '#', 'i', '1', 3, 'f', 'o', 'o', 'F'};
            SaxCountdown scp(0);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("key() in object with length")
        {
            std::vector<uint8_t> const v = {'{', 'i', 3, 'f', 'o', 'o', 'F', '}'};
            SaxCountdown scp(1);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("start_array() in ndarray _ArraySize_")
        {
            std::vector<uint8_t> const v = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 2, 2, 1, 1, 2};
            SaxCountdown scp(2);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("number_integer() in ndarray _ArraySize_")
        {
            std::vector<uint8_t> const v = {'[', '$', 'U', '#', '[', '$', 'i', '#', 'i', 2, 2, 1, 1, 2};
            SaxCountdown scp(3);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("key() in ndarray _ArrayType_")
        {
            std::vector<uint8_t> const v = {'[', '$', 'U', '#', '[', '$', 'U', '#', 'i', 2, 2, 2, 1, 2, 3, 4};
            SaxCountdown scp(6);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("string() in ndarray _ArrayType_")
        {
            std::vector<uint8_t> const v = {'[', '$', 'U', '#', '[', '$', 'U', '#', 'i', 2, 2, 2, 1, 2, 3, 4};
            SaxCountdown scp(7);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("key() in ndarray _ArrayData_")
        {
            std::vector<uint8_t> const v = {'[', '$', 'U', '#', '[', '$', 'U', '#', 'i', 2, 2, 2, 1, 2, 3, 4};
            SaxCountdown scp(8);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("string() in ndarray _ArrayData_")
        {
            std::vector<uint8_t> const v = {'[', '$', 'U', '#', '[', '$', 'U', '#', 'i', 2, 2, 2, 1, 2, 3, 4};
            SaxCountdown scp(9);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("string() in ndarray _ArrayType_")
        {
            std::vector<uint8_t> const v = {'[', '$', 'U', '#', '[', '$', 'i', '#', 'i', 2, 3, 2, 6, 5, 4, 3, 2, 1};
            SaxCountdown scp(11);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }

        SECTION("start_array() in ndarray _ArrayData_")
        {
            std::vector<uint8_t> const v = {'[', '$', 'U', '#', '[', 'i', 2, 'i', 3, ']', 6, 5, 4, 3, 2, 1};
            SaxCountdown scp(13);
            CHECK_FALSE(json::sax_parse(v, &scp, json::input_format_t::bjdata));
        }
    }

    SECTION("parsing values")
    {
        SECTION("strings")
        {
            // create a single-character string for all number types
            std::vector<uint8_t> s_i = {'S', 'i', 1, 'a'};
            std::vector<uint8_t> const s_U = {'S', 'U', 1, 'a'};
            std::vector<uint8_t> const s_I = {'S', 'I', 1, 0, 'a'};
            std::vector<uint8_t> const s_u = {'S', 'u', 1, 0, 'a'};
            std::vector<uint8_t> const s_l = {'S', 'l', 1, 0, 0, 0, 'a'};
            std::vector<uint8_t> const s_m = {'S', 'm', 1, 0, 0, 0, 'a'};
            std::vector<uint8_t> const s_L = {'S', 'L', 1, 0, 0, 0, 0, 0, 0, 0, 'a'};
            std::vector<uint8_t> const s_M = {'S', 'M', 1, 0, 0, 0, 0, 0, 0, 0, 'a'};

            // check if string is parsed correctly to "a"
            CHECK(json::from_bjdata(s_i) == "a");
            CHECK(json::from_bjdata(s_U) == "a");
            CHECK(json::from_bjdata(s_I) == "a");
            CHECK(json::from_bjdata(s_u) == "a");
            CHECK(json::from_bjdata(s_l) == "a");
            CHECK(json::from_bjdata(s_m) == "a");
            CHECK(json::from_bjdata(s_L) == "a");
            CHECK(json::from_bjdata(s_M) == "a");

            // roundtrip: output should be optimized
            CHECK(json::to_bjdata(json::from_bjdata(s_i)) == s_i);
            CHECK(json::to_bjdata(json::from_bjdata(s_U)) == s_i);
            CHECK(json::to_bjdata(json::from_bjdata(s_I)) == s_i);
            CHECK(json::to_bjdata(json::from_bjdata(s_u)) == s_i);
            CHECK(json::to_bjdata(json::from_bjdata(s_l)) == s_i);
            CHECK(json::to_bjdata(json::from_bjdata(s_m)) == s_i);
            CHECK(json::to_bjdata(json::from_bjdata(s_L)) == s_i);
            CHECK(json::to_bjdata(json::from_bjdata(s_M)) == s_i);
        }

        SECTION("number")
        {
            SECTION("float")
            {
                // float32
                std::vector<uint8_t> const v_d = {'d', 0xd0, 0x0f, 0x49, 0x40};
                CHECK(json::from_bjdata(v_d) == 3.14159f);

                // float64
                std::vector<uint8_t> const v_D = {'D', 0x6e, 0x86, 0x1b, 0xf0, 0xf9, 0x21, 0x09, 0x40};
                CHECK(json::from_bjdata(v_D) == 3.14159);

                // float32 is serialized as float64 as the library does not support float32
                CHECK(json::to_bjdata(json::from_bjdata(v_d)) == json::to_bjdata(3.14159f));
            }
        }

        SECTION("array")
        {
            SECTION("optimized version (length only)")
            {
                // create vector with two elements of the same type
                std::vector<uint8_t> const v_TU = {'[', '#', 'U', 2, 'T', 'T'};
                std::vector<uint8_t> const v_T = {'[', '#', 'i', 2, 'T', 'T'};
                std::vector<uint8_t> const v_F = {'[', '#', 'i', 2, 'F', 'F'};
                std::vector<uint8_t> const v_Z = {'[', '#', 'i', 2, 'Z', 'Z'};
                std::vector<uint8_t> const v_i = {'[', '#', 'i', 2, 'i', 0x7F, 'i', 0x7F};
                std::vector<uint8_t> const v_U = {'[', '#', 'i', 2, 'U', 0xFF, 'U', 0xFF};
                std::vector<uint8_t> const v_I = {'[', '#', 'i', 2, 'I', 0xFF, 0x7F, 'I', 0xFF, 0x7F};
                std::vector<uint8_t> const v_u = {'[', '#', 'i', 2, 'u', 0x0F, 0xA7, 'u', 0x0F, 0xA7};
                std::vector<uint8_t> const v_l = {'[', '#', 'i', 2, 'l', 0xFF, 0xFF, 0xFF, 0x7F, 'l', 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_m = {'[', '#', 'i', 2, 'm', 0xFF, 0xC9, 0x9A, 0xBB, 'm', 0xFF, 0xC9, 0x9A, 0xBB};
                std::vector<uint8_t> const v_L = {'[', '#', 'i', 2, 'L', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 'L', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_M = {'[', '#', 'i', 2, 'M', 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D, 'M', 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D};
                std::vector<uint8_t> const v_D = {'[', '#', 'i', 2, 'D', 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40, 'D', 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40};
                std::vector<uint8_t> const v_S = {'[', '#', 'i', 2, 'S', 'i', 1, 'a', 'S', 'i', 1, 'a'};
                std::vector<uint8_t> const v_C = {'[', '#', 'i', 2, 'C', 'a', 'C', 'a'};
                std::vector<uint8_t> const v_B = {'[', '#', 'i', 2, 'B', 0xFF, 'B', 0xFF};

                // check if vector is parsed correctly
                CHECK(json::from_bjdata(v_TU) == json({true, true}));
                CHECK(json::from_bjdata(v_T) == json({true, true}));
                CHECK(json::from_bjdata(v_F) == json({false, false}));
                CHECK(json::from_bjdata(v_Z) == json({nullptr, nullptr}));
                CHECK(json::from_bjdata(v_i) == json({127, 127}));
                CHECK(json::from_bjdata(v_U) == json({255, 255}));
                CHECK(json::from_bjdata(v_I) == json({32767, 32767}));
                CHECK(json::from_bjdata(v_u) == json({42767, 42767}));
                CHECK(json::from_bjdata(v_l) == json({2147483647, 2147483647}));
                CHECK(json::from_bjdata(v_m) == json({3147483647, 3147483647}));
                CHECK(json::from_bjdata(v_L) == json({9223372036854775807, 9223372036854775807}));
                CHECK(json::from_bjdata(v_M) == json({10223372036854775807ull, 10223372036854775807ull}));
                CHECK(json::from_bjdata(v_D) == json({3.1415926, 3.1415926}));
                CHECK(json::from_bjdata(v_S) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_C) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_B) == json({255, 255}));

                // roundtrip: output should be optimized
                CHECK(json::to_bjdata(json::from_bjdata(v_T), true) == v_T);
                CHECK(json::to_bjdata(json::from_bjdata(v_F), true) == v_F);
                CHECK(json::to_bjdata(json::from_bjdata(v_Z), true) == v_Z);
                CHECK(json::to_bjdata(json::from_bjdata(v_i), true) == v_i);
                CHECK(json::to_bjdata(json::from_bjdata(v_U), true) == v_U);
                CHECK(json::to_bjdata(json::from_bjdata(v_I), true) == v_I);
                CHECK(json::to_bjdata(json::from_bjdata(v_u), true) == v_u);
                CHECK(json::to_bjdata(json::from_bjdata(v_l), true) == v_l);
                CHECK(json::to_bjdata(json::from_bjdata(v_m), true) == v_m);
                CHECK(json::to_bjdata(json::from_bjdata(v_L), true) == v_L);
                CHECK(json::to_bjdata(json::from_bjdata(v_M), true) == v_M);
                CHECK(json::to_bjdata(json::from_bjdata(v_D), true) == v_D);
                CHECK(json::to_bjdata(json::from_bjdata(v_S), true) == v_S);
                CHECK(json::to_bjdata(json::from_bjdata(v_C), true) == v_S); // char is serialized to string
                CHECK(json::to_bjdata(json::from_bjdata(v_B), true) == v_U); // byte is serialized to uint8
            }

            SECTION("optimized version (type and length)")
            {
                // create vector with two elements of the same type
                std::vector<uint8_t> const v_i = {'[', '$', 'i', '#', 'i', 2, 0x7F, 0x7F};
                std::vector<uint8_t> const v_U = {'[', '$', 'U', '#', 'i', 2, 0xFF, 0xFF};
                std::vector<uint8_t> const v_I = {'[', '$', 'I', '#', 'i', 2, 0xFF, 0x7F, 0xFF, 0x7F};
                std::vector<uint8_t> const v_u = {'[', '$', 'u', '#', 'i', 2, 0x0F, 0xA7, 0x0F, 0xA7};
                std::vector<uint8_t> const v_l = {'[', '$', 'l', '#', 'i', 2, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_m = {'[', '$', 'm', '#', 'i', 2, 0xFF, 0xC9, 0x9A, 0xBB, 0xFF, 0xC9, 0x9A, 0xBB};
                std::vector<uint8_t> const v_L = {'[', '$', 'L', '#', 'i', 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_M = {'[', '$', 'M', '#', 'i', 2, 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D, 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D};
                std::vector<uint8_t> const v_D = {'[', '$', 'D', '#', 'i', 2, 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40, 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40};
                std::vector<uint8_t> const v_S = {'[', '#', 'i', 2, 'S', 'i', 1, 'a', 'S', 'i', 1, 'a'};
                std::vector<uint8_t> const v_C = {'[', '$', 'C', '#', 'i', 2, 'a', 'a'};
                std::vector<uint8_t> const v_B = {'[', '$', 'B', '#', 'i', 2, 0xFF, 0xFF};

                // check if vector is parsed correctly
                CHECK(json::from_bjdata(v_i) == json({127, 127}));
                CHECK(json::from_bjdata(v_U) == json({255, 255}));
                CHECK(json::from_bjdata(v_I) == json({32767, 32767}));
                CHECK(json::from_bjdata(v_u) == json({42767, 42767}));
                CHECK(json::from_bjdata(v_l) == json({2147483647, 2147483647}));
                CHECK(json::from_bjdata(v_m) == json({3147483647, 3147483647}));
                CHECK(json::from_bjdata(v_L) == json({9223372036854775807, 9223372036854775807}));
                CHECK(json::from_bjdata(v_M) == json({10223372036854775807ull, 10223372036854775807ull}));
                CHECK(json::from_bjdata(v_D) == json({3.1415926, 3.1415926}));
                CHECK(json::from_bjdata(v_S) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_C) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_B) == json::binary(std::vector<uint8_t>({static_cast<uint8_t>(255), static_cast<uint8_t>(255)})));

                // roundtrip: output should be optimized
                std::vector<uint8_t> const v_empty = {'[', '#', 'i', 0};
                CHECK(json::to_bjdata(json::from_bjdata(v_i), true, true) == v_i);
                CHECK(json::to_bjdata(json::from_bjdata(v_U), true, true) == v_U);
                CHECK(json::to_bjdata(json::from_bjdata(v_I), true, true) == v_I);
                CHECK(json::to_bjdata(json::from_bjdata(v_u), true, true) == v_u);
                CHECK(json::to_bjdata(json::from_bjdata(v_l), true, true) == v_l);
                CHECK(json::to_bjdata(json::from_bjdata(v_m), true, true) == v_m);
                CHECK(json::to_bjdata(json::from_bjdata(v_L), true, true) == v_L);
                CHECK(json::to_bjdata(json::from_bjdata(v_M), true, true) == v_M);
                CHECK(json::to_bjdata(json::from_bjdata(v_D), true, true) == v_D);
                CHECK(json::to_bjdata(json::from_bjdata(v_S), true, true) == v_S);
                CHECK(json::to_bjdata(json::from_bjdata(v_C), true, true) == v_S); // char is serialized to string
                CHECK(json::to_bjdata(json::from_bjdata(v_B), true, true, json::bjdata_version_t::draft2) == v_U);
                CHECK(json::to_bjdata(json::from_bjdata(v_B), true, true, json::bjdata_version_t::draft3) == v_B);
            }

            SECTION("optimized ndarray (type and vector-size as optimized 1D array)")
            {
                // create vector with two elements of the same type
                std::vector<uint8_t> const v_0 = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 1, 0};
                std::vector<uint8_t> const v_1 = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 1, 2, 0x7F, 0x7F};
                std::vector<uint8_t> const v_i = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0x7F, 0x7F};
                std::vector<uint8_t> const v_U = {'[', '$', 'U', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0xFF, 0xFF};
                std::vector<uint8_t> const v_I = {'[', '$', 'I', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0xFF, 0x7F, 0xFF, 0x7F};
                std::vector<uint8_t> const v_u = {'[', '$', 'u', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0x0F, 0xA7, 0x0F, 0xA7};
                std::vector<uint8_t> const v_l = {'[', '$', 'l', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_m = {'[', '$', 'm', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0xFF, 0xC9, 0x9A, 0xBB, 0xFF, 0xC9, 0x9A, 0xBB};
                std::vector<uint8_t> const v_L = {'[', '$', 'L', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_M = {'[', '$', 'M', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D, 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D};
                std::vector<uint8_t> const v_D = {'[', '$', 'D', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40, 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40};
                std::vector<uint8_t> const v_S = {'[', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 'S', 'i', 1, 'a', 'S', 'i', 1, 'a'};
                std::vector<uint8_t> const v_C = {'[', '$', 'C', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 'a', 'a'};
                std::vector<uint8_t> const v_B = {'[', '$', 'B', '#', '[', '$', 'i', '#', 'i', 2, 1, 2, 0xFF, 0xFF};

                // check if vector is parsed correctly
                CHECK(json::from_bjdata(v_0) == json::array());
                CHECK(json::from_bjdata(v_1) == json({127, 127}));
                CHECK(json::from_bjdata(v_i) == json({127, 127}));
                CHECK(json::from_bjdata(v_U) == json({255, 255}));
                CHECK(json::from_bjdata(v_I) == json({32767, 32767}));
                CHECK(json::from_bjdata(v_u) == json({42767, 42767}));
                CHECK(json::from_bjdata(v_l) == json({2147483647, 2147483647}));
                CHECK(json::from_bjdata(v_m) == json({3147483647, 3147483647}));
                CHECK(json::from_bjdata(v_L) == json({9223372036854775807, 9223372036854775807}));
                CHECK(json::from_bjdata(v_M) == json({10223372036854775807ull, 10223372036854775807ull}));
                CHECK(json::from_bjdata(v_D) == json({3.1415926, 3.1415926}));
                CHECK(json::from_bjdata(v_S) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_C) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_B) == json::binary(std::vector<uint8_t>({static_cast<uint8_t>(255), static_cast<uint8_t>(255)})));
            }

            SECTION("optimized ndarray (type and vector-size ndarray with JData annotations)")
            {
                // create vector with 0, 1, 2 elements of the same type
                std::vector<uint8_t> const v_e = {'[', '$', 'U', '#', '[', '$', 'i', '#', 'i', 2, 2, 1, 0xFE, 0xFF};
                std::vector<uint8_t> const v_U = {'[', '$', 'U', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
                std::vector<uint8_t> const v_i = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
                std::vector<uint8_t> const v_u = {'[', '$', 'u', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00};
                std::vector<uint8_t> const v_I = {'[', '$', 'I', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00};
                std::vector<uint8_t> const v_m = {'[', '$', 'm', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00};
                std::vector<uint8_t> const v_l = {'[', '$', 'l', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00};
                std::vector<uint8_t> const v_M = {'[', '$', 'M', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                std::vector<uint8_t> const v_L = {'[', '$', 'L', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                std::vector<uint8_t> const v_d = {'[', '$', 'd', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00, 0x80, 0x40, 0x00, 0x00, 0xA0, 0x40, 0x00, 0x00, 0xC0, 0x40};
                std::vector<uint8_t> const v_D = {'[', '$', 'D', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x40};
                std::vector<uint8_t> const v_C = {'[', '$', 'C', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 'a', 'b', 'c', 'd', 'e', 'f'};
                std::vector<uint8_t> const v_B = {'[', '$', 'B', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

                // check if vector is parsed correctly
                CHECK(json::from_bjdata(v_e) == json({{"_ArrayData_", {254, 255}}, {"_ArraySize_", {2, 1}}, {"_ArrayType_", "uint8"}}));
                CHECK(json::from_bjdata(v_U) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "uint8"}}));
                CHECK(json::from_bjdata(v_i) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "int8"}}));
                CHECK(json::from_bjdata(v_i) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "int8"}}));
                CHECK(json::from_bjdata(v_u) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "uint16"}}));
                CHECK(json::from_bjdata(v_I) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "int16"}}));
                CHECK(json::from_bjdata(v_m) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "uint32"}}));
                CHECK(json::from_bjdata(v_l) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "int32"}}));
                CHECK(json::from_bjdata(v_M) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "uint64"}}));
                CHECK(json::from_bjdata(v_L) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "int64"}}));
                CHECK(json::from_bjdata(v_d) == json({{"_ArrayData_", {1.f, 2.f, 3.f, 4.f, 5.f, 6.f}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "single"}}));
                CHECK(json::from_bjdata(v_D) == json({{"_ArrayData_", {1., 2., 3., 4., 5., 6.}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "double"}}));
                CHECK(json::from_bjdata(v_C) == json({{"_ArrayData_", {'a', 'b', 'c', 'd', 'e', 'f'}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "char"}}));
                CHECK(json::from_bjdata(v_B) == json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "byte"}}));

                // roundtrip: output should be optimized
                CHECK(json::to_bjdata(json::from_bjdata(v_e), true, true) == v_e);
                CHECK(json::to_bjdata(json::from_bjdata(v_U), true, true) == v_U);
                CHECK(json::to_bjdata(json::from_bjdata(v_i), true, true) == v_i);
                CHECK(json::to_bjdata(json::from_bjdata(v_u), true, true) == v_u);
                CHECK(json::to_bjdata(json::from_bjdata(v_I), true, true) == v_I);
                CHECK(json::to_bjdata(json::from_bjdata(v_m), true, true) == v_m);
                CHECK(json::to_bjdata(json::from_bjdata(v_l), true, true) == v_l);
                CHECK(json::to_bjdata(json::from_bjdata(v_M), true, true) == v_M);
                CHECK(json::to_bjdata(json::from_bjdata(v_L), true, true) == v_L);
                CHECK(json::to_bjdata(json::from_bjdata(v_d), true, true) == v_d);
                CHECK(json::to_bjdata(json::from_bjdata(v_D), true, true) == v_D);
                CHECK(json::to_bjdata(json::from_bjdata(v_C), true, true) == v_C);
                CHECK(json::to_bjdata(json::from_bjdata(v_B), true, true) == v_B);
            }

            SECTION("optimized ndarray (type and vector-size as 1D array)")
            {
                // create vector with two elements of the same type
                std::vector<uint8_t> const v_0 = {'[', '$', 'i', '#', '[', ']'};
                std::vector<uint8_t> const v_E = {'[', '$', 'i', '#', '[', 'i', 2, 'i', 0, ']'};
                std::vector<uint8_t> const v_i = {'[', '$', 'i', '#', '[', 'i', 1, 'i', 2, ']', 0x7F, 0x7F};
                std::vector<uint8_t> const v_U = {'[', '$', 'U', '#', '[', 'i', 1, 'i', 2, ']', 0xFF, 0xFF};
                std::vector<uint8_t> const v_I = {'[', '$', 'I', '#', '[', 'i', 1, 'i', 2, ']', 0xFF, 0x7F, 0xFF, 0x7F};
                std::vector<uint8_t> const v_u = {'[', '$', 'u', '#', '[', 'i', 1, 'i', 2, ']', 0x0F, 0xA7, 0x0F, 0xA7};
                std::vector<uint8_t> const v_l = {'[', '$', 'l', '#', '[', 'i', 1, 'i', 2, ']', 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_m = {'[', '$', 'm', '#', '[', 'i', 1, 'i', 2, ']', 0xFF, 0xC9, 0x9A, 0xBB, 0xFF, 0xC9, 0x9A, 0xBB};
                std::vector<uint8_t> const v_L = {'[', '$', 'L', '#', '[', 'i', 1, 'i', 2, ']', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_M = {'[', '$', 'M', '#', '[', 'i', 1, 'i', 2, ']', 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D, 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D};
                std::vector<uint8_t> const v_D = {'[', '$', 'D', '#', '[', 'i', 1, 'i', 2, ']', 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40, 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40};
                std::vector<uint8_t> const v_S = {'[', '#', '[', 'i', 1, 'i', 2, ']', 'S', 'i', 1, 'a', 'S', 'i', 1, 'a'};
                std::vector<uint8_t> const v_C = {'[', '$', 'C', '#', '[', 'i', 1, 'i', 2, ']', 'a', 'a'};
                std::vector<uint8_t> const v_B = {'[', '$', 'B', '#', '[', 'i', 1, 'i', 2, ']', 0xFF, 0xFF};
                std::vector<uint8_t> const v_R = {'[', '#', '[', 'i', 2, ']', 'i', 6, 'U', 7};

                // check if vector is parsed correctly
                CHECK(json::from_bjdata(v_0) == json::array());
                CHECK(json::from_bjdata(v_E) == json::array());
                CHECK(json::from_bjdata(v_i) == json({127, 127}));
                CHECK(json::from_bjdata(v_U) == json({255, 255}));
                CHECK(json::from_bjdata(v_I) == json({32767, 32767}));
                CHECK(json::from_bjdata(v_u) == json({42767, 42767}));
                CHECK(json::from_bjdata(v_l) == json({2147483647, 2147483647}));
                CHECK(json::from_bjdata(v_m) == json({3147483647, 3147483647}));
                CHECK(json::from_bjdata(v_L) == json({9223372036854775807, 9223372036854775807}));
                CHECK(json::from_bjdata(v_M) == json({10223372036854775807ull, 10223372036854775807ull}));
                CHECK(json::from_bjdata(v_D) == json({3.1415926, 3.1415926}));
                CHECK(json::from_bjdata(v_S) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_C) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_B) == json::binary(std::vector<uint8_t>({static_cast<uint8_t>(255), static_cast<uint8_t>(255)})));
                CHECK(json::from_bjdata(v_R) == json({6, 7}));
            }

            SECTION("optimized ndarray (type and vector-size as size-optimized array)")
            {
                // create vector with two elements of the same type
                std::vector<uint8_t> const v_i = {'[', '$', 'i', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0x7F, 0x7F};
                std::vector<uint8_t> const v_U = {'[', '$', 'U', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0xFF, 0xFF};
                std::vector<uint8_t> const v_I = {'[', '$', 'I', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0xFF, 0x7F, 0xFF, 0x7F};
                std::vector<uint8_t> const v_u = {'[', '$', 'u', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0x0F, 0xA7, 0x0F, 0xA7};
                std::vector<uint8_t> const v_l = {'[', '$', 'l', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_m = {'[', '$', 'm', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0xFF, 0xC9, 0x9A, 0xBB, 0xFF, 0xC9, 0x9A, 0xBB};
                std::vector<uint8_t> const v_L = {'[', '$', 'L', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
                std::vector<uint8_t> const v_M = {'[', '$', 'M', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D, 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D};
                std::vector<uint8_t> const v_D = {'[', '$', 'D', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40, 0x4a, 0xd8, 0x12, 0x4d, 0xfb, 0x21, 0x09, 0x40};
                std::vector<uint8_t> const v_S = {'[', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 'S', 'i', 1, 'a', 'S', 'i', 1, 'a'};
                std::vector<uint8_t> const v_C = {'[', '$', 'C', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 'a', 'a'};
                std::vector<uint8_t> const v_B = {'[', '$', 'B', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2, 0xFF, 0xFF};

                // check if vector is parsed correctly
                CHECK(json::from_bjdata(v_i) == json({127, 127}));
                CHECK(json::from_bjdata(v_U) == json({255, 255}));
                CHECK(json::from_bjdata(v_I) == json({32767, 32767}));
                CHECK(json::from_bjdata(v_u) == json({42767, 42767}));
                CHECK(json::from_bjdata(v_l) == json({2147483647, 2147483647}));
                CHECK(json::from_bjdata(v_m) == json({3147483647, 3147483647}));
                CHECK(json::from_bjdata(v_L) == json({9223372036854775807, 9223372036854775807}));
                CHECK(json::from_bjdata(v_M) == json({10223372036854775807ull, 10223372036854775807ull}));
                CHECK(json::from_bjdata(v_D) == json({3.1415926, 3.1415926}));
                CHECK(json::from_bjdata(v_S) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_C) == json({"a", "a"}));
                CHECK(json::from_bjdata(v_B) == json::binary(std::vector<uint8_t>({static_cast<uint8_t>(255), static_cast<uint8_t>(255)})));
            }

            SECTION("invalid ndarray annotations remains as object")
            {
                // check if invalid ND array annotations stay as object
                json j_type = json({{"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "invalidtype"}});
                json j_size = json({{"_ArrayData_", {1, 2, 3, 4, 5}}, {"_ArraySize_", {2, 3}}, {"_ArrayType_", "uint8"}});

                // roundtrip: output should stay as object
                CHECK(json::from_bjdata(json::to_bjdata(j_type), true, true) == j_type);
                CHECK(json::from_bjdata(json::to_bjdata(j_size), true, true) == j_size);
            }
        }
    }

    SECTION("parse errors")
    {
        SECTION("empty byte vector")
        {
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(std::vector<uint8_t>()),
                                 "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
        }

        SECTION("char")
        {
            SECTION("eof after C byte")
            {
                std::vector<uint8_t> const v = {'C'};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BJData char: unexpected end of input", json::parse_error&);
            }

            SECTION("byte out of range")
            {
                std::vector<uint8_t> const v = {'C', 130};
                json _;
                CHECK_THROWS_WITH(_ = json::from_bjdata(v), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing BJData char: byte after 'C' must be in range 0x00..0x7F; last byte: 0x82");
            }
        }

        SECTION("byte")
        {
            SECTION("parse bjdata markers in ubjson")
            {
                std::vector<uint8_t> const v = {'B', 1};

                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.112] parse error at byte 1: syntax error while parsing UBJSON value: invalid byte: 0x42", json::parse_error&);
            }
        }

        SECTION("strings")
        {
            SECTION("eof after S byte")
            {
                std::vector<uint8_t> const v = {'S'};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            }

            SECTION("invalid byte")
            {
                std::vector<uint8_t> const v = {'S', '1', 'a'};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing BJData string: expected length type specification (U, i, u, I, m, l, M, L); last byte: 0x31", json::parse_error&);
            }

            SECTION("parse bjdata markers in ubjson")
            {
                // create a single-character string for all number types
                std::vector<uint8_t> const s_u = {'S', 'u', 1, 0, 'a'};
                std::vector<uint8_t> const s_m = {'S', 'm', 1, 0, 0, 0, 'a'};
                std::vector<uint8_t> const s_M = {'S', 'M', 1, 0, 0, 0, 0, 0, 0, 0, 'a'};

                json _;
                // check if string is parsed correctly to "a"
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(s_u), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing UBJSON string: expected length type specification (U, i, I, l, L); last byte: 0x75", json::parse_error&);
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(s_m), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing UBJSON string: expected length type specification (U, i, I, l, L); last byte: 0x6D", json::parse_error&);
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(s_M), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing UBJSON string: expected length type specification (U, i, I, l, L); last byte: 0x4D", json::parse_error&);
            }
        }

        SECTION("array")
        {
            SECTION("optimized array: no size following type")
            {
                std::vector<uint8_t> const v = {'[', '$', 'i', 2};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.112] parse error at byte 4: syntax error while parsing BJData size: expected '#' after type information; last byte: 0x02", json::parse_error&);
            }

            SECTION("optimized array: negative size")
            {
                std::vector<uint8_t> const v1 = {'[', '#', 'i', 0xF1};
                std::vector<uint8_t> const v2 = {'[', '$', 'I', '#', 'i', 0xF2};
                std::vector<uint8_t> const v3 = {'[', '$', 'I', '#', '[', 'i', 0xF4, 'i', 0x02, ']'};
                std::vector<uint8_t> const v4 = {'[', '$', 0xF6, '#', 'i', 0xF7};
                std::vector<uint8_t> const v5 = {'[', '$', 'I', '#', '[', 'i', 0xF5, 'i', 0xF1, ']'};
                std::vector<uint8_t> const v6 = {'[', '#', '[', 'i', 0xF3, 'i', 0x02, ']'};

                std::vector<uint8_t> const vI = {'[', '#', 'I', 0x00, 0xF1};
                std::vector<uint8_t> const vl = {'[', '#', 'l', 0x00, 0x00, 0x00, 0xF2};
                std::vector<uint8_t> const vL = {'[', '#', 'L', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF3};
                std::vector<uint8_t> const vM = {'[', '$', 'M', '#', '[', 'I', 0x00, 0x20, 'M', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xFF, ']'};
                std::vector<uint8_t> const vMX = {'[', '$', 'U', '#', '[', 'M', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 'U', 0x01, ']'};

                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v1), "[json.exception.parse_error.113] parse error at byte 4: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(v1, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v2), "[json.exception.parse_error.113] parse error at byte 6: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(v2, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v3), "[json.exception.parse_error.113] parse error at byte 7: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(v3, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v4), "[json.exception.parse_error.113] parse error at byte 6: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(v4, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v5), "[json.exception.parse_error.113] parse error at byte 7: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(v5, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v6), "[json.exception.parse_error.113] parse error at byte 5: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(v6, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vI), "[json.exception.parse_error.113] parse error at byte 5: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(vI, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vl), "[json.exception.parse_error.113] parse error at byte 7: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(vl, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vL), "[json.exception.parse_error.113] parse error at byte 11: syntax error while parsing BJData size: count in an optimized container must be positive", json::parse_error&);
                CHECK(json::from_bjdata(vL, true, false).is_discarded());

#if SIZE_MAX != 0xffffffff
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.out_of_range.408] syntax error while parsing BJData size: excessive ndarray size caused overflow", json::out_of_range&);
#else
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
#endif
                CHECK(json::from_bjdata(vM, true, false).is_discarded());

#if SIZE_MAX != 0xffffffff
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vMX), "[json.exception.out_of_range.408] syntax error while parsing BJData size: excessive ndarray size caused overflow", json::out_of_range&);
#else
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vMX), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
#endif
                CHECK(json::from_bjdata(vMX, true, false).is_discarded());
            }

            SECTION("optimized array: integer value overflow")
            {
#if SIZE_MAX == 0xffffffff
                std::vector<uint8_t> const vL = {'[', '#', 'L', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F};
                std::vector<uint8_t> const vM = {'[', '$', 'M', '#', '[', 'I', 0x00, 0x20, 'M', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xFF, ']'};

                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vL), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vL, true, false).is_discarded());
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vM, true, false).is_discarded());
#endif
            }

            SECTION("do not accept NTFZ markers in ndarray optimized type (with count)")
            {
                json _;
                std::vector<uint8_t> const v_N = {'[', '$', 'N', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2};
                std::vector<uint8_t> const v_T = {'[', '$', 'T', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2};
                std::vector<uint8_t> const v_F = {'[', '$', 'F', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2};
                std::vector<uint8_t> const v_Z = {'[', '$', 'Z', '#', '[', '#', 'i', 2, 'i', 1, 'i', 2};

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v_N), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x4E is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v_N, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v_T), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x54 is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v_T, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v_F), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x46 is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v_F, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v_Z), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x5A is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v_Z, true, false).is_discarded());
            }

            SECTION("do not accept NTFZ markers in ndarray optimized type (without count)")
            {
                json _;
                std::vector<uint8_t> const v_N = {'[', '$', 'N', '#', '[', 'i', 1, 'i', 2, ']'};
                std::vector<uint8_t> const v_T = {'[', '$', 'T', '#', '[', 'i', 1, 'i', 2, ']'};
                std::vector<uint8_t> const v_F = {'[', '$', 'F', '#', '[', 'i', 1, 'i', 2, ']'};
                std::vector<uint8_t> const v_Z = {'[', '$', 'Z', '#', '[', 'i', 1, 'i', 2, ']'};

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v_N), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x4E is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v_N, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v_T), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x54 is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v_T, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v_F), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x46 is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v_F, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v_Z), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x5A is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v_Z, true, false).is_discarded());
            }
        }

        SECTION("strings")
        {
            std::vector<uint8_t> const vS = {'S'};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vS), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vS, true, false).is_discarded());

            std::vector<uint8_t> const v = {'S', 'i', '2', 'a'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing BJData string: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(v, true, false).is_discarded());

            std::vector<uint8_t> const vC = {'C'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vC), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BJData char: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vC, true, false).is_discarded());
        }

        SECTION("sizes")
        {
            std::vector<uint8_t> const vU = {'[', '#', 'U'};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vU), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vU, true, false).is_discarded());

            std::vector<uint8_t> const vi = {'[', '#', 'i'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vi), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vi, true, false).is_discarded());

            std::vector<uint8_t> const vI = {'[', '#', 'I'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vI), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vI, true, false).is_discarded());

            std::vector<uint8_t> const vu = {'[', '#', 'u'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vu), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vu, true, false).is_discarded());

            std::vector<uint8_t> const vl = {'[', '#', 'l'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vl), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vl, true, false).is_discarded());

            std::vector<uint8_t> const vm = {'[', '#', 'm'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vm), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vm, true, false).is_discarded());

            std::vector<uint8_t> const vL = {'[', '#', 'L'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vL), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vL, true, false).is_discarded());

            std::vector<uint8_t> const vM = {'[', '#', 'M'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vM, true, false).is_discarded());

            std::vector<uint8_t> const v0 = {'[', '#', 'T', ']'};
            CHECK_THROWS_WITH(_ = json::from_bjdata(v0), "[json.exception.parse_error.113] parse error at byte 3: syntax error while parsing BJData size: expected length type specification (U, i, u, I, m, l, M, L) after '#'; last byte: 0x54");
            CHECK(json::from_bjdata(v0, true, false).is_discarded());

            std::vector<uint8_t> const vB = {'[', '#', 'B', ']'};
            CHECK_THROWS_WITH(_ = json::from_bjdata(vB), "[json.exception.parse_error.113] parse error at byte 3: syntax error while parsing BJData size: expected length type specification (U, i, u, I, m, l, M, L) after '#'; last byte: 0x42");
            CHECK(json::from_bjdata(v0, true, false).is_discarded());
        }

        SECTION("parse bjdata markers as array size in ubjson")
        {
            json _;
            std::vector<uint8_t> const vu = {'[', '#', 'u'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vu), "[json.exception.parse_error.113] parse error at byte 3: syntax error while parsing UBJSON size: expected length type specification (U, i, I, l, L) after '#'; last byte: 0x75", json::parse_error&);
            CHECK(json::from_ubjson(vu, true, false).is_discarded());

            std::vector<uint8_t> const vm = {'[', '#', 'm'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vm), "[json.exception.parse_error.113] parse error at byte 3: syntax error while parsing UBJSON size: expected length type specification (U, i, I, l, L) after '#'; last byte: 0x6D", json::parse_error&);
            CHECK(json::from_ubjson(vm, true, false).is_discarded());

            std::vector<uint8_t> const vM = {'[', '#', 'M'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vM), "[json.exception.parse_error.113] parse error at byte 3: syntax error while parsing UBJSON size: expected length type specification (U, i, I, l, L) after '#'; last byte: 0x4D", json::parse_error&);
            CHECK(json::from_ubjson(vM, true, false).is_discarded());

            std::vector<uint8_t> const v0 = {'[', '#', '['};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v0), "[json.exception.parse_error.113] parse error at byte 3: syntax error while parsing UBJSON size: expected length type specification (U, i, I, l, L) after '#'; last byte: 0x5B", json::parse_error&);
            CHECK(json::from_ubjson(v0, true, false).is_discarded());
        }

        SECTION("types")
        {
            std::vector<uint8_t> const v0 = {'[', '$'};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v0), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BJData type: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(v0, true, false).is_discarded());

            std::vector<uint8_t> const vi = {'[', '$', '#'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vi), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vi, true, false).is_discarded());

            std::vector<uint8_t> const vU = {'[', '$', 'U'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vU), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vU, true, false).is_discarded());

            std::vector<uint8_t> const v1 = {'[', '$', '['};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v1), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x5B is not a permitted optimized array type", json::parse_error&);
            CHECK(json::from_bjdata(v1, true, false).is_discarded());
        }

        SECTION("arrays")
        {
            std::vector<uint8_t> const vST = {'[', '$', 'i', '#', 'i', 2, 1};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vST), "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vST, true, false).is_discarded());

            std::vector<uint8_t> const vS = {'[', '#', 'i', 2, 'i', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vS), "[json.exception.parse_error.110] parse error at byte 7: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vS, true, false).is_discarded());

            std::vector<uint8_t> const v = {'[', 'i', 2, 'i', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.110] parse error at byte 6: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(v, true, false).is_discarded());
        }

        SECTION("ndarrays")
        {
            std::vector<uint8_t> const vST = {'[', '$', 'i', '#', '[', '$', 'i', '#'};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vST), "[json.exception.parse_error.113] parse error at byte 9: syntax error while parsing BJData size: expected length type specification (U, i, u, I, m, l, M, L) after '#'; last byte: 0xFF", json::parse_error&);
            CHECK(json::from_bjdata(vST, true, false).is_discarded());

            std::vector<uint8_t> const v = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 2, 1, 2};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.110] parse error at byte 13: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(v, true, false).is_discarded());

            std::vector<uint8_t> const vS0 = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 2, 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vS0), "[json.exception.parse_error.110] parse error at byte 12: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vS0, true, false).is_discarded());

            std::vector<uint8_t> const vS = {'[', '$', 'i', '#', '[', '#', 'i', 2, 1, 2, 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vS), "[json.exception.parse_error.113] parse error at byte 9: syntax error while parsing BJData size: expected length type specification (U, i, u, I, m, l, M, L) after '#'; last byte: 0x01", json::parse_error&);
            CHECK(json::from_bjdata(vS, true, false).is_discarded());

            std::vector<uint8_t> const vT = {'[', '$', 'i', '#', '[', 'i', 2, 'i'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vT), "[json.exception.parse_error.110] parse error at byte 9: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vT, true, false).is_discarded());

            std::vector<uint8_t> const vT0 = {'[', '$', 'i', '#', '[', 'i'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vT0), "[json.exception.parse_error.110] parse error at byte 7: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vT0, true, false).is_discarded());

            std::vector<uint8_t> const vu = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'u', 1, 0};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vu), "[json.exception.parse_error.110] parse error at byte 12: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vu, true, false).is_discarded());

            std::vector<uint8_t> const vm = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'm', 1, 0, 0, 0};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vm), "[json.exception.parse_error.110] parse error at byte 14: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vm, true, false).is_discarded());

            std::vector<uint8_t> const vM = {'[', '$', 'i', '#', '[', '$', 'i', '#', 'M', 1, 0, 0, 0, 0, 0, 0, 0};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.parse_error.110] parse error at byte 18: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vM, true, false).is_discarded());

            std::vector<uint8_t> const vU = {'[', '$', 'U', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 1, 2, 3, 4, 5};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vU), "[json.exception.parse_error.110] parse error at byte 18: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vU, true, false).is_discarded());

            std::vector<uint8_t> const vB = {'[', '$', 'B', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 1, 2, 3, 4, 5};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vU), "[json.exception.parse_error.110] parse error at byte 18: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vU, true, false).is_discarded());

            std::vector<uint8_t> const vT1 = {'[', '$', 'T', '#', '[', '$', 'i', '#', 'i', 2, 2, 3};
            CHECK(json::from_bjdata(vT1, true, false).is_discarded());

            std::vector<uint8_t> const vh = {'[', '$', 'h', '#', '[', '$', 'i', '#', 'i', 2, 2, 3};
            CHECK(json::from_bjdata(vh, true, false).is_discarded());

            std::vector<uint8_t> const vR = {'[', '$', 'i', '#', '[', 'i', 1, '[', ']', ']', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vR), "[json.exception.parse_error.113] parse error at byte 8: syntax error while parsing BJData size: ndarray dimensional vector is not allowed", json::parse_error&);
            CHECK(json::from_bjdata(vR, true, false).is_discarded());

            std::vector<uint8_t> const vRo = {'[', '$', 'i', '#', '[', 'i', 0, '{', '}', ']', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vRo), "[json.exception.parse_error.113] parse error at byte 8: syntax error while parsing BJData size: expected length type specification (U, i, u, I, m, l, M, L) after '#'; last byte: 0x7B", json::parse_error&);
            CHECK(json::from_bjdata(vRo, true, false).is_discarded());

            std::vector<uint8_t> const vR1 = {'[', '$', 'i', '#', '[', '[', 'i', 1, ']', ']', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vR1), "[json.exception.parse_error.113] parse error at byte 6: syntax error while parsing BJData size: ndarray dimensional vector is not allowed", json::parse_error&);
            CHECK(json::from_bjdata(vR1, true, false).is_discarded());

            std::vector<uint8_t> const vR2 = {'[', '$', 'i', '#', '[', '#', '[', 'i', 1, ']', ']', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vR2), "[json.exception.parse_error.113] parse error at byte 11: syntax error while parsing BJData size: expected length type specification (U, i, u, I, m, l, M, L) after '#'; last byte: 0x5D", json::parse_error&);
            CHECK(json::from_bjdata(vR2, true, false).is_discarded());

            std::vector<uint8_t> const vR3 = {'[', '#', '[', 'i', '2', 'i', 2, ']'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vR3), "[json.exception.parse_error.112] parse error at byte 8: syntax error while parsing BJData size: ndarray requires both type and size", json::parse_error&);
            CHECK(json::from_bjdata(vR3, true, false).is_discarded());

            std::vector<uint8_t> const vR4 = {'[', '$', 'i', '#', '[', '$', 'i', '#', '[', 'i', 1, ']', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vR4), "[json.exception.parse_error.110] parse error at byte 14: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vR4, true, false).is_discarded());

            std::vector<uint8_t> const vR5 = {'[', '$', 'i', '#', '[', '[', '[', ']', ']', ']'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vR5), "[json.exception.parse_error.113] parse error at byte 6: syntax error while parsing BJData size: ndarray dimensional vector is not allowed", json::parse_error&);
            CHECK(json::from_bjdata(vR5, true, false).is_discarded());

            std::vector<uint8_t> const vR6 = {'[', '$', 'i', '#', '[', '$', 'i', '#', '[', 'i', '2', 'i', 2, ']'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vR6), "[json.exception.parse_error.112] parse error at byte 14: syntax error while parsing BJData size: ndarray can not be recursive", json::parse_error&);
            CHECK(json::from_bjdata(vR6, true, false).is_discarded());

            std::vector<uint8_t> const vH = {'[', 'H', '[', '#', '[', '$', 'i', '#', '[', 'i', '2', 'i', 2, ']'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vH), "[json.exception.parse_error.113] parse error at byte 3: syntax error while parsing BJData size: ndarray dimensional vector is not allowed", json::parse_error&);
            CHECK(json::from_bjdata(vH, true, false).is_discarded());
        }

        SECTION("objects")
        {
            std::vector<uint8_t> const vST = {'{', '$', 'i', '#', 'i', 2, 'i', 1, 'a', 1};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vST), "[json.exception.parse_error.110] parse error at byte 11: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vST, true, false).is_discarded());

            std::vector<uint8_t> const vT = {'{', '$', 'i', 'i', 1, 'a', 1};
            CHECK_THROWS_WITH(_ = json::from_bjdata(vT), "[json.exception.parse_error.112] parse error at byte 4: syntax error while parsing BJData size: expected '#' after type information; last byte: 0x69");
            CHECK(json::from_bjdata(vT, true, false).is_discarded());

            std::vector<uint8_t> const vS = {'{', '#', 'i', 2, 'i', 1, 'a', 'i', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vS), "[json.exception.parse_error.110] parse error at byte 10: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vS, true, false).is_discarded());

            std::vector<uint8_t> const v = {'{', 'i', 1, 'a', 'i', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.110] parse error at byte 7: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(v, true, false).is_discarded());

            std::vector<uint8_t> const v2 = {'{', 'i', 1, 'a', 'i', 1, 'i'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v2), "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(v2, true, false).is_discarded());

            std::vector<uint8_t> const v3 = {'{', 'i', 1, 'a'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v3), "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(v3, true, false).is_discarded());

            std::vector<uint8_t> const vST1 = {'{', '$', 'd', '#', 'i', 2, 'i', 1, 'a'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vST1), "[json.exception.parse_error.110] parse error at byte 10: syntax error while parsing BJData number: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vST1, true, false).is_discarded());

            std::vector<uint8_t> const vST2 = {'{', '#', 'i', 2, 'i', 1, 'a'};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vST2), "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing BJData value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bjdata(vST2, true, false).is_discarded());

            std::vector<uint8_t> const vO = {'{', '#', '[', 'i', 2, 'i', 1, ']', 'i', 1, 'a', 'i', 1, 'i', 1, 'b', 'i', 2};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vO), "[json.exception.parse_error.112] parse error at byte 8: syntax error while parsing BJData size: ndarray requires both type and size", json::parse_error&);
            CHECK(json::from_bjdata(vO, true, false).is_discarded());

            std::vector<uint8_t> const vO2 = {'{', '$', 'i', '#', '[', 'i', 2, 'i', 1, ']', 'i', 1, 'a', 1, 'i', 1, 'b', 2};
            CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vO2), "[json.exception.parse_error.112] parse error at byte 10: syntax error while parsing BJData object: BJData object does not support ND-array size in optimized format", json::parse_error&);
            CHECK(json::from_bjdata(vO2, true, false).is_discarded());
        }
    }

    SECTION("writing optimized values")
    {
        SECTION("integer")
        {
            SECTION("array of i")
            {
                json const j = {1, -1};
                std::vector<uint8_t> const expected = {'[', '$', 'i', '#', 'i', 2, 1, 0xff};
                CHECK(json::to_bjdata(j, true, true) == expected);
            }

            SECTION("array of U")
            {
                json const j = {200, 201};
                std::vector<uint8_t> const expected = {'[', '$', 'U', '#', 'i', 2, 0xC8, 0xC9};
                CHECK(json::to_bjdata(j, true, true) == expected);
            }

            SECTION("array of I")
            {
                json const j = {30000, -30000};
                std::vector<uint8_t> const expected = {'[', '$', 'I', '#', 'i', 2, 0x30, 0x75, 0xd0, 0x8a};
                CHECK(json::to_bjdata(j, true, true) == expected);
            }

            SECTION("array of u")
            {
                json const j = {50000, 50001};
                std::vector<uint8_t> const expected = {'[', '$', 'u', '#', 'i', 2, 0x50, 0xC3, 0x51, 0xC3};
                CHECK(json::to_bjdata(j, true, true) == expected);
            }

            SECTION("array of l")
            {
                json const j = {70000, -70000};
                std::vector<uint8_t> const expected = {'[', '$', 'l', '#', 'i', 2, 0x70, 0x11, 0x01, 0x00, 0x90, 0xEE, 0xFE, 0xFF};
                CHECK(json::to_bjdata(j, true, true) == expected);
            }

            SECTION("array of m")
            {
                json const j = {3147483647, 3147483648};
                std::vector<uint8_t> const expected = {'[', '$', 'm', '#', 'i', 2, 0xFF, 0xC9, 0x9A, 0xBB, 0x00, 0xCA, 0x9A, 0xBB};
                CHECK(json::to_bjdata(j, true, true) == expected);
            }

            SECTION("array of L")
            {
                json const j = {5000000000, -5000000000};
                std::vector<uint8_t> const expected = {'[', '$', 'L', '#', 'i', 2, 0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0E, 0xFA, 0xD5, 0xFE, 0xFF, 0xFF, 0xFF};
                CHECK(json::to_bjdata(j, true, true) == expected);
            }
        }

        SECTION("unsigned integer")
        {
            SECTION("array of i")
            {
                json const j = {1u, 2u};
                std::vector<uint8_t> const expected = {'[', '$', 'i', '#', 'i', 2, 1, 2};
                std::vector<uint8_t> const expected_size = {'[', '#', 'i', 2, 'i', 1, 'i', 2};
                CHECK(json::to_bjdata(j, true, true) == expected);
                CHECK(json::to_bjdata(j, true) == expected_size);
            }

            SECTION("array of U")
            {
                json const j = {200u, 201u};
                std::vector<uint8_t> const expected = {'[', '$', 'U', '#', 'i', 2, 0xC8, 0xC9};
                std::vector<uint8_t> const expected_size = {'[', '#', 'i', 2, 'U', 0xC8, 'U', 0xC9};
                CHECK(json::to_bjdata(j, true, true) == expected);
                CHECK(json::to_bjdata(j, true) == expected_size);
            }

            SECTION("array of I")
            {
                json const j = {30000u, 30001u};
                std::vector<uint8_t> const expected = {'[', '$', 'I', '#', 'i', 2, 0x30, 0x75, 0x31, 0x75};
                std::vector<uint8_t> const expected_size = {'[', '#', 'i', 2, 'I', 0x30, 0x75, 'I', 0x31, 0x75};
                CHECK(json::to_bjdata(j, true, true) == expected);
                CHECK(json::to_bjdata(j, true) == expected_size);
            }

            SECTION("array of u")
            {
                json const j = {50000u, 50001u};
                std::vector<uint8_t> const expected = {'[', '$', 'u', '#', 'i', 2, 0x50, 0xC3, 0x51, 0xC3};
                std::vector<uint8_t> const expected_size = {'[', '#', 'i', 2, 'u', 0x50, 0xC3, 'u', 0x51, 0xC3};
                CHECK(json::to_bjdata(j, true, true) == expected);
                CHECK(json::to_bjdata(j, true) == expected_size);
            }

            SECTION("array of l")
            {
                json const j = {70000u, 70001u};
                std::vector<uint8_t> const expected = {'[', '$', 'l', '#', 'i', 2, 0x70, 0x11, 0x01, 0x00, 0x71, 0x11, 0x01, 0x00};
                std::vector<uint8_t> const expected_size = {'[', '#', 'i', 2, 'l', 0x70, 0x11, 0x01, 0x00, 'l', 0x71, 0x11, 0x01, 0x00};
                CHECK(json::to_bjdata(j, true, true) == expected);
                CHECK(json::to_bjdata(j, true) == expected_size);
            }

            SECTION("array of m")
            {
                json const j = {3147483647u, 3147483648u};
                std::vector<uint8_t> const expected = {'[', '$', 'm', '#', 'i', 2, 0xFF, 0xC9, 0x9A, 0xBB, 0x00, 0xCA, 0x9A, 0xBB};
                std::vector<uint8_t> const expected_size = {'[', '#', 'i', 2, 'm', 0xFF, 0xC9, 0x9A, 0xBB, 'm', 0x00, 0xCA, 0x9A, 0xBB};
                CHECK(json::to_bjdata(j, true, true) == expected);
                CHECK(json::to_bjdata(j, true) == expected_size);
            }

            SECTION("array of L")
            {
                json const j = {5000000000u, 5000000001u};
                std::vector<uint8_t> const expected = {'[', '$', 'L', '#', 'i', 2, 0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, 0x01, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00};
                std::vector<uint8_t> const expected_size = {'[', '#', 'i', 2, 'L', 0x00, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00, 'L', 0x01, 0xF2, 0x05, 0x2A, 0x01, 0x00, 0x00, 0x00};
                CHECK(json::to_bjdata(j, true, true) == expected);
                CHECK(json::to_bjdata(j, true) == expected_size);
            }

            SECTION("array of M")
            {
                json const j = {10223372036854775807ull, 10223372036854775808ull};
                std::vector<uint8_t> const expected = {'[', '$', 'M', '#', 'i', 2, 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D, 0x00, 0x00, 0x64, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D};
                std::vector<uint8_t> const expected_size = {'[', '#', 'i', 2, 'M', 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D, 'M', 0x00, 0x00, 0x64, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D};
                CHECK(json::to_bjdata(j, true, true) == expected);
                CHECK(json::to_bjdata(j, true) == expected_size);
            }
        }
    }
}

TEST_CASE("Universal Binary JSON Specification Examples 1")
{
    SECTION("Null Value")
    {
        json const j = {{"passcode", nullptr}};
        std::vector<uint8_t> v = {'{', 'i', 8, 'p', 'a', 's', 's', 'c', 'o', 'd', 'e', 'Z', '}'};
        CHECK(json::to_bjdata(j) == v);
        CHECK(json::from_bjdata(v) == j);
    }

    SECTION("No-Op Value")
    {
        json const j = {"foo", "bar", "baz"};
        std::vector<uint8_t> v = {'[', 'S', 'i', 3, 'f', 'o', 'o',
                                  'S', 'i', 3, 'b', 'a', 'r',
                                  'S', 'i', 3, 'b', 'a', 'z', ']'
                                 };
        std::vector<uint8_t> const v2 = {'[', 'S', 'i', 3, 'f', 'o', 'o', 'N',
                                         'S', 'i', 3, 'b', 'a', 'r', 'N', 'N', 'N',
                                         'S', 'i', 3, 'b', 'a', 'z', 'N', 'N', ']'
                                        };
        CHECK(json::to_bjdata(j) == v);
        CHECK(json::from_bjdata(v) == j);
        CHECK(json::from_bjdata(v2) == j);
    }

    SECTION("Boolean Types")
    {
        json const j = {{"authorized", true}, {"verified", false}};
        std::vector<uint8_t> v = {'{', 'i', 10, 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'e', 'd', 'T',
                                  'i', 8, 'v', 'e', 'r', 'i', 'f', 'i', 'e', 'd', 'F', '}'
                                 };
        CHECK(json::to_bjdata(j) == v);
        CHECK(json::from_bjdata(v) == j);
    }

    SECTION("Numeric Types")
    {
        json j =
        {
            {"int8", 16},
            {"uint8", 255},
            {"int16", 32767},
            {"uint16", 42767},
            {"int32", 2147483647},
            {"uint32", 3147483647},
            {"int64", 9223372036854775807},
            {"uint64", 10223372036854775807ull},
            {"float64", 113243.7863123}
        };
        std::vector<uint8_t> v = {'{',
                                  'i', 7, 'f', 'l', 'o', 'a', 't', '6', '4', 'D', 0xcf, 0x34, 0xbc, 0x94, 0xbc, 0xa5, 0xfb, 0x40,
                                  'i', 5, 'i', 'n', 't', '1', '6', 'I', 0xff, 0x7f,
                                  'i', 5, 'i', 'n', 't', '3', '2', 'l', 0xff, 0xff, 0xff, 0x7f,
                                  'i', 5, 'i', 'n', 't', '6', '4', 'L', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
                                  'i', 4, 'i', 'n', 't', '8', 'i', 16,
                                  'i', 6, 'u', 'i', 'n', 't', '1', '6', 'u', 0x0F, 0xA7,
                                  'i', 6, 'u', 'i', 'n', 't', '3', '2', 'm', 0xFF, 0xC9, 0x9A, 0xBB,
                                  'i', 6, 'u', 'i', 'n', 't', '6', '4', 'M', 0xFF, 0xFF, 0x63, 0xA7, 0xB3, 0xB6, 0xE0, 0x8D,
                                  'i', 5, 'u', 'i', 'n', 't', '8', 'U', 0xff,
                                  '}'
                                 };
        CHECK(json::to_bjdata(j) == v);
        CHECK(json::from_bjdata(v) == j);
    }

    SECTION("Char Type")
    {
        json const j = {{"rolecode", "a"}, {"delim", ";"}};
        std::vector<uint8_t> const v = {'{', 'i', 5, 'd', 'e', 'l', 'i', 'm', 'C', ';', 'i', 8, 'r', 'o', 'l', 'e', 'c', 'o', 'd', 'e', 'C', 'a', '}'};
        //CHECK(json::to_bjdata(j) == v);
        CHECK(json::from_bjdata(v) == j);
    }

    SECTION("Byte Type")
    {
        const auto s = std::vector<std::uint8_t>(
        {
            static_cast<std::uint8_t>(222),
            static_cast<std::uint8_t>(173),
            static_cast<std::uint8_t>(190),
            static_cast<std::uint8_t>(239)
        });
        json const j = {{"binary", json::binary(s)}, {"val", 123}};
        std::vector<uint8_t> const v = {'{', 'i', 6, 'b', 'i', 'n', 'a', 'r', 'y', '[', '$', 'B', '#', 'i', 4, 222, 173, 190, 239, 'i', 3, 'v', 'a', 'l', 'i', 123, '}'};
        //CHECK(json::to_bjdata(j) == v); // 123 value gets encoded as uint8
        CHECK(json::from_bjdata(v) == j);
    }

    SECTION("String Type")
    {
        SECTION("English")
        {
            json const j = "hello";
            std::vector<uint8_t> v = {'S', 'i', 5, 'h', 'e', 'l', 'l', 'o'};
            CHECK(json::to_bjdata(j) == v);
            CHECK(json::from_bjdata(v) == j);
        }

        SECTION("Russian")
        {
            json const j = "привет";
            std::vector<uint8_t> v = {'S', 'i', 12, 0xD0, 0xBF, 0xD1, 0x80, 0xD0, 0xB8, 0xD0, 0xB2, 0xD0, 0xB5, 0xD1, 0x82};
            CHECK(json::to_bjdata(j) == v);
            CHECK(json::from_bjdata(v) == j);
        }

        SECTION("Russian")
        {
            json const j = "مرحبا";
            std::vector<uint8_t> v = {'S', 'i', 10, 0xD9, 0x85, 0xD8, 0xB1, 0xD8, 0xAD, 0xD8, 0xA8, 0xD8, 0xA7};
            CHECK(json::to_bjdata(j) == v);
            CHECK(json::from_bjdata(v) == j);
        }
    }

    SECTION("Array Type")
    {
        SECTION("size=false type=false")
        {
            // note the float has been replaced by a double
            json const j = {nullptr, true, false, 4782345193, 153.132, "ham"};
            std::vector<uint8_t> v = {'[', 'Z', 'T', 'F', 'L', 0xE9, 0xCB, 0x0C, 0x1D, 0x01, 0x00, 0x00, 0x00, 'D', 0x4e, 0x62, 0x10, 0x58, 0x39, 0x24, 0x63, 0x40, 'S', 'i', 3, 'h', 'a', 'm', ']'};
            CHECK(json::to_bjdata(j) == v);
            CHECK(json::from_bjdata(v) == j);
        }

        SECTION("size=true type=false")
        {
            // note the float has been replaced by a double
            json const j = {nullptr, true, false, 4782345193, 153.132, "ham"};
            std::vector<uint8_t> v = {'[', '#', 'i', 6, 'Z', 'T', 'F', 'L', 0xE9, 0xCB, 0x0C, 0x1D, 0x01, 0x00, 0x00, 0x00, 'D', 0x4e, 0x62, 0x10, 0x58, 0x39, 0x24, 0x63, 0x40, 'S', 'i', 3, 'h', 'a', 'm'};
            CHECK(json::to_bjdata(j, true) == v);
            CHECK(json::from_bjdata(v) == j);
        }

        SECTION("size=true type=true")
        {
            // note the float has been replaced by a double
            json const j = {nullptr, true, false, 4782345193, 153.132, "ham"};
            std::vector<uint8_t> v = {'[', '#', 'i', 6, 'Z', 'T', 'F', 'L', 0xE9, 0xCB, 0x0C, 0x1D, 0x01, 0x00, 0x00, 0x00, 'D', 0x4e, 0x62, 0x10, 0x58, 0x39, 0x24, 0x63, 0x40, 'S', 'i', 3, 'h', 'a', 'm'};
            CHECK(json::to_bjdata(j, true, true) == v);
            CHECK(json::from_bjdata(v) == j);
        }
    }

    SECTION("Object Type")
    {
        SECTION("size=false type=false")
        {
            json j =
            {
                {
                    "post", {
                        {"id", 1137},
                        {"author", "rkalla"},
                        {"timestamp", 1364482090592},
                        {"body", "I totally agree!"}
                    }
                }
            };
            std::vector<uint8_t> v = {'{', 'i', 4, 'p', 'o', 's', 't', '{',
                                      'i', 6, 'a', 'u', 't', 'h', 'o', 'r', 'S', 'i', 6, 'r', 'k', 'a', 'l', 'l', 'a',
                                      'i', 4, 'b', 'o', 'd', 'y', 'S', 'i', 16, 'I', ' ', 't', 'o', 't', 'a', 'l', 'l', 'y', ' ', 'a', 'g', 'r', 'e', 'e', '!',
                                      'i', 2, 'i', 'd', 'I', 0x71, 0x04,
                                      'i', 9, 't', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p', 'L', 0x60, 0x66, 0x78, 0xB1, 0x3D, 0x01, 0x00, 0x00,
                                      '}', '}'
                                     };
            CHECK(json::to_bjdata(j) == v);
            CHECK(json::from_bjdata(v) == j);
        }

        SECTION("size=true type=false")
        {
            json j =
            {
                {
                    "post", {
                        {"id", 1137},
                        {"author", "rkalla"},
                        {"timestamp", 1364482090592},
                        {"body", "I totally agree!"}
                    }
                }
            };
            std::vector<uint8_t> v = {'{', '#', 'i', 1, 'i', 4, 'p', 'o', 's', 't', '{', '#', 'i', 4,
                                      'i', 6, 'a', 'u', 't', 'h', 'o', 'r', 'S', 'i', 6, 'r', 'k', 'a', 'l', 'l', 'a',
                                      'i', 4, 'b', 'o', 'd', 'y', 'S', 'i', 16, 'I', ' ', 't', 'o', 't', 'a', 'l', 'l', 'y', ' ', 'a', 'g', 'r', 'e', 'e', '!',
                                      'i', 2, 'i', 'd', 'I', 0x71, 0x04,
                                      'i', 9, 't', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p', 'L', 0x60, 0x66, 0x78, 0xB1, 0x3D, 0x01, 0x00, 0x00,
                                     };
            CHECK(json::to_bjdata(j, true) == v);
            CHECK(json::from_bjdata(v) == j);
        }

        SECTION("size=true type=true")
        {
            json j =
            {
                {
                    "post", {
                        {"id", 1137},
                        {"author", "rkalla"},
                        {"timestamp", 1364482090592},
                        {"body", "I totally agree!"}
                    }
                }
            };
            std::vector<uint8_t> v = {'{', '#', 'i', 1, 'i', 4, 'p', 'o', 's', 't', '{', '#', 'i', 4,
                                      'i', 6, 'a', 'u', 't', 'h', 'o', 'r', 'S', 'i', 6, 'r', 'k', 'a', 'l', 'l', 'a',
                                      'i', 4, 'b', 'o', 'd', 'y', 'S', 'i', 16, 'I', ' ', 't', 'o', 't', 'a', 'l', 'l', 'y', ' ', 'a', 'g', 'r', 'e', 'e', '!',
                                      'i', 2, 'i', 'd', 'I', 0x71, 0x04,
                                      'i', 9, 't', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p', 'L', 0x60, 0x66, 0x78, 0xB1, 0x3D, 0x01, 0x00, 0x00,
                                     };
            CHECK(json::to_bjdata(j, true, true) == v);
            CHECK(json::from_bjdata(v) == j);
        }
    }

    SECTION("Optimized Format")
    {
        SECTION("Array Example")
        {
            SECTION("No Optimization")
            {
                // note the floats have been replaced by doubles
                json const j = {29.97, 31.13, 67.0, 2.113, 23.888};
                std::vector<uint8_t> v = {'[',
                                          'D', 0xb8, 0x1e, 0x85, 0xeb, 0x51, 0xf8, 0x3d, 0x40,
                                          'D', 0xe1, 0x7a, 0x14, 0xae, 0x47, 0x21, 0x3f, 0x40,
                                          'D', 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x50, 0x40,
                                          'D', 0x81, 0x95, 0x43, 0x8b, 0x6c, 0xe7, 0x00, 0x40,
                                          'D', 0x17, 0xd9, 0xce, 0xf7, 0x53, 0xe3, 0x37, 0x40,
                                          ']'
                                         };
                CHECK(json::to_bjdata(j) == v);
                CHECK(json::from_bjdata(v) == j);
            }

            SECTION("Optimized with count")
            {
                // note the floats have been replaced by doubles
                json const j = {29.97, 31.13, 67.0, 2.113, 23.888};
                std::vector<uint8_t> v = {'[', '#', 'i', 5,
                                          'D', 0xb8, 0x1e, 0x85, 0xeb, 0x51, 0xf8, 0x3d, 0x40,
                                          'D', 0xe1, 0x7a, 0x14, 0xae, 0x47, 0x21, 0x3f, 0x40,
                                          'D', 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x50, 0x40,
                                          'D', 0x81, 0x95, 0x43, 0x8b, 0x6c, 0xe7, 0x00, 0x40,
                                          'D', 0x17, 0xd9, 0xce, 0xf7, 0x53, 0xe3, 0x37, 0x40,
                                         };
                CHECK(json::to_bjdata(j, true) == v);
                CHECK(json::from_bjdata(v) == j);
            }

            SECTION("Optimized with type & count")
            {
                // note the floats have been replaced by doubles
                json const j = {29.97, 31.13, 67.0, 2.113, 23.888};
                std::vector<uint8_t> v = {'[', '$', 'D', '#', 'i', 5,
                                          0xb8, 0x1e, 0x85, 0xeb, 0x51, 0xf8, 0x3d, 0x40,
                                          0xe1, 0x7a, 0x14, 0xae, 0x47, 0x21, 0x3f, 0x40,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x50, 0x40,
                                          0x81, 0x95, 0x43, 0x8b, 0x6c, 0xe7, 0x00, 0x40,
                                          0x17, 0xd9, 0xce, 0xf7, 0x53, 0xe3, 0x37, 0x40,
                                         };
                CHECK(json::to_bjdata(j, true, true) == v);
                CHECK(json::from_bjdata(v) == j);
            }
        }

        SECTION("Object Example")
        {
            SECTION("No Optimization")
            {
                // note the floats have been replaced by doubles
                json const j = { {"lat", 29.976}, {"long", 31.131}, {"alt", 67.0} };
                std::vector<uint8_t> v = {'{',
                                          'i', 3, 'a', 'l', 't', 'D',      0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x50, 0x40,
                                          'i', 3, 'l', 'a', 't', 'D',      0x60, 0xe5, 0xd0, 0x22, 0xdb, 0xf9, 0x3d, 0x40,
                                          'i', 4, 'l', 'o', 'n', 'g', 'D', 0xa8, 0xc6, 0x4b, 0x37, 0x89, 0x21, 0x3f, 0x40,
                                          '}'
                                         };
                CHECK(json::to_bjdata(j) == v);
                CHECK(json::from_bjdata(v) == j);
            }

            SECTION("Optimized with count")
            {
                // note the floats have been replaced by doubles
                json const j = { {"lat", 29.976}, {"long", 31.131}, {"alt", 67.0} };
                std::vector<uint8_t> v = {'{', '#', 'i', 3,
                                          'i', 3, 'a', 'l', 't', 'D',      0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x50, 0x40,
                                          'i', 3, 'l', 'a', 't', 'D',      0x60, 0xe5, 0xd0, 0x22, 0xdb, 0xf9, 0x3d, 0x40,
                                          'i', 4, 'l', 'o', 'n', 'g', 'D', 0xa8, 0xc6, 0x4b, 0x37, 0x89, 0x21, 0x3f, 0x40,
                                         };
                CHECK(json::to_bjdata(j, true) == v);
                CHECK(json::from_bjdata(v) == j);
            }

            SECTION("Optimized with type & count")
            {
                // note the floats have been replaced by doubles
                json const j = { {"lat", 29.976}, {"long", 31.131}, {"alt", 67.0} };
                std::vector<uint8_t> v = {'{', '$', 'D', '#', 'i', 3,
                                          'i', 3, 'a', 'l', 't',      0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x50, 0x40,
                                          'i', 3, 'l', 'a', 't',      0x60, 0xe5, 0xd0, 0x22, 0xdb, 0xf9, 0x3d, 0x40,
                                          'i', 4, 'l', 'o', 'n', 'g', 0xa8, 0xc6, 0x4b, 0x37, 0x89, 0x21, 0x3f, 0x40,
                                         };
                CHECK(json::to_bjdata(j, true, true) == v);
                CHECK(json::from_bjdata(v) == j);
            }
        }

        SECTION("Special Cases (Null, No-Op and Boolean)")
        {
            SECTION("Array")
            {
                json _;
                std::vector<uint8_t> const v = {'[', '$', 'N', '#', 'I', 0x00, 0x02};
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x4E is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v, true, false).is_discarded());
            }

            SECTION("Object")
            {
                json _;
                std::vector<uint8_t> const v = {'{', '$', 'Z', '#', 'i', 3, 'i', 4, 'n', 'a', 'm', 'e', 'i', 8, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 'i', 5, 'e', 'm', 'a', 'i', 'l'};
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(v), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BJData type: marker 0x5A is not a permitted optimized array type", json::parse_error&);
                CHECK(json::from_bjdata(v, true, false).is_discarded());
            }
        }
    }
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("all BJData first bytes")
{
    // these bytes will fail immediately with exception parse_error.112
    std::set<uint8_t> supported =
    {
        'T', 'F', 'Z', 'B', 'U', 'i', 'I', 'l', 'L', 'd', 'D', 'C', 'S', '[', '{', 'N', 'H', 'u', 'm', 'M', 'h'
    };

    for (auto i = 0; i < 256; ++i)
    {
        const auto byte = static_cast<uint8_t>(i);
        CAPTURE(byte)

        try
        {
            auto res = json::from_bjdata(std::vector<uint8_t>(1, byte));
        }
        catch (const json::parse_error& e)
        {
            // check that parse_error.112 is only thrown if the
            // first byte is not in the supported set
            INFO_WITH_TEMP(e.what());
            if (supported.find(byte) == supported.end())
            {
                CHECK(e.id == 112);
            }
            else
            {
                CHECK(e.id != 112);
            }
        }
    }
}
#endif

TEST_CASE("BJData roundtrips" * doctest::skip())
{
    SECTION("input from self-generated BJData files")
    {
        for (const std::string filename :
                {
                    TEST_DATA_DIRECTORY "/json_nlohmann_tests/all_unicode.json",
                    TEST_DATA_DIRECTORY "/json.org/1.json",
                    TEST_DATA_DIRECTORY "/json.org/2.json",
                    TEST_DATA_DIRECTORY "/json.org/3.json",
                    TEST_DATA_DIRECTORY "/json.org/4.json",
                    TEST_DATA_DIRECTORY "/json.org/5.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip01.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip02.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip03.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip04.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip05.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip06.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip07.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip08.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip09.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip10.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip11.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip12.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip13.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip14.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip15.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip16.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip17.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip18.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip19.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip20.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip21.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip22.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip23.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip24.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip25.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip26.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip27.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip28.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip29.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip30.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip31.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip32.json",
                    TEST_DATA_DIRECTORY "/json_testsuite/sample.json",
                    TEST_DATA_DIRECTORY "/json_tests/pass1.json",
                    TEST_DATA_DIRECTORY "/json_tests/pass2.json",
                    TEST_DATA_DIRECTORY "/json_tests/pass3.json"
                })
        {
            CAPTURE(filename)

            {
                INFO_WITH_TEMP(filename + ": std::vector<uint8_t>");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse BJData file
                auto packed = utils::read_binary_file(filename + ".bjdata");
                json j2;
                CHECK_NOTHROW(j2 = json::from_bjdata(packed));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": std::ifstream");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse BJData file
                std::ifstream f_bjdata(filename + ".bjdata", std::ios::binary);
                json j2;
                CHECK_NOTHROW(j2 = json::from_bjdata(f_bjdata));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": output to output adapters");
                // parse JSON file
                std::ifstream f_json(filename);
                json const j1 = json::parse(f_json);

                // parse BJData file
                auto packed = utils::read_binary_file(filename + ".bjdata");

                {
                    INFO_WITH_TEMP(filename + ": output adapters: std::vector<uint8_t>");
                    std::vector<uint8_t> vec;
                    json::to_bjdata(j1, vec);
                    CHECK(vec == packed);
                }
            }
        }
    }
}
