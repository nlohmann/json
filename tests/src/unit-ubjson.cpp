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

TEST_CASE("UBJSON")
{
    SECTION("individual values")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            json const j = json::value_t::discarded;
            const auto result = json::to_ubjson(j);
            CHECK(result.empty());
        }

        SECTION("null")
        {
            json const j = nullptr;
            std::vector<uint8_t> expected = {'Z'};
            const auto result = json::to_ubjson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_ubjson(result) == j);
            CHECK(json::from_ubjson(result, true, false) == j);
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json const j = true;
                std::vector<uint8_t> const expected = {'T'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
                CHECK(json::from_ubjson(result, true, false) == j);
            }

            SECTION("false")
            {
                json const j = false;
                std::vector<uint8_t> const expected = {'F'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
                CHECK(json::from_ubjson(result, true, false) == j);
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
                    for (auto i : numbers)
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
                            static_cast<uint8_t>((i >> 56) & 0xff),
                            static_cast<uint8_t>((i >> 48) & 0xff),
                            static_cast<uint8_t>((i >> 40) & 0xff),
                            static_cast<uint8_t>((i >> 32) & 0xff),
                            static_cast<uint8_t>((i >> 24) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
                        int64_t const restored = (static_cast<int64_t>(result[1]) << 070) +
                                                 (static_cast<int64_t>(result[2]) << 060) +
                                                 (static_cast<int64_t>(result[3]) << 050) +
                                                 (static_cast<int64_t>(result[4]) << 040) +
                                                 (static_cast<int64_t>(result[5]) << 030) +
                                                 (static_cast<int64_t>(result[6]) << 020) +
                                                 (static_cast<int64_t>(result[7]) << 010) +
                                                 static_cast<int64_t>(result[8]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
                    }
                }

                SECTION("-2147483648..-32769 (int32)")
                {
                    std::vector<int32_t> numbers;
                    numbers.push_back(-32769);
                    numbers.push_back(-100000);
                    numbers.push_back(-1000000);
                    numbers.push_back(-10000000);
                    numbers.push_back(-100000000);
                    numbers.push_back(-1000000000);
                    numbers.push_back(-2147483647 - 1); // https://stackoverflow.com/a/29356002/266378
                    for (auto i : numbers)
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
                            static_cast<uint8_t>((i >> 24) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        int32_t const restored = (static_cast<int32_t>(result[1]) << 030) +
                                                 (static_cast<int32_t>(result[2]) << 020) +
                                                 (static_cast<int32_t>(result[3]) << 010) +
                                                 static_cast<int32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
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
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        auto const restored = static_cast<int16_t>(((result[1] << 8) + result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
                    }
                }

                SECTION("-9263 (int16)")
                {
                    json const j = -9263;
                    std::vector<uint8_t> expected = {'I', 0xdb, 0xd1};

                    // compare result + size
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);
                    CHECK(result.size() == 3);

                    // check individual bytes
                    CHECK(result[0] == 'I');
                    auto const restored = static_cast<int16_t>(((result[1] << 8) + result[2]));
                    CHECK(restored == -9263);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
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
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        CHECK(static_cast<int8_t>(result[1]) == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
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
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        CHECK(result[1] == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
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
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'U');
                        CHECK(result[1] == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
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
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        auto const restored = static_cast<uint16_t>((static_cast<uint8_t>(result[1]) * 256) + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
                    }
                }

                SECTION("65536..2147483647 (int32)")
                {
                    for (uint32_t i :
                            {
                                65536u, 77777u, 1048576u
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
                            static_cast<uint8_t>((i >> 24) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        uint32_t const restored = (static_cast<uint32_t>(result[1]) << 030) +
                                                  (static_cast<uint32_t>(result[2]) << 020) +
                                                  (static_cast<uint32_t>(result[3]) << 010) +
                                                  static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
                    }
                }

                SECTION("2147483648..9223372036854775807 (int64)")
                {
                    std::vector<uint64_t> const v = {2147483648ul, 9223372036854775807ul};
                    for (uint64_t i : v)
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
                            static_cast<uint8_t>((i >> 070) & 0xff),
                            static_cast<uint8_t>((i >> 060) & 0xff),
                            static_cast<uint8_t>((i >> 050) & 0xff),
                            static_cast<uint8_t>((i >> 040) & 0xff),
                            static_cast<uint8_t>((i >> 030) & 0xff),
                            static_cast<uint8_t>((i >> 020) & 0xff),
                            static_cast<uint8_t>((i >> 010) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
                        uint64_t const restored = (static_cast<uint64_t>(result[1]) << 070) +
                                                  (static_cast<uint64_t>(result[2]) << 060) +
                                                  (static_cast<uint64_t>(result[3]) << 050) +
                                                  (static_cast<uint64_t>(result[4]) << 040) +
                                                  (static_cast<uint64_t>(result[5]) << 030) +
                                                  (static_cast<uint64_t>(result[6]) << 020) +
                                                  (static_cast<uint64_t>(result[7]) << 010) +
                                                  static_cast<uint64_t>(result[8]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
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
                        std::vector<uint8_t> const expected
                        {
                            'i',
                            static_cast<uint8_t>(i),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        auto const restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
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
                        std::vector<uint8_t> const expected
                        {
                            'U',
                            static_cast<uint8_t>(i),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'U');
                        auto const restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
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
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        auto const restored = static_cast<uint16_t>((static_cast<uint8_t>(result[1]) * 256) + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
                    }
                }

                SECTION("65536..2147483647 (int32)")
                {
                    for (uint32_t i :
                            {
                                65536u, 77777u, 1048576u
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
                            static_cast<uint8_t>((i >> 24) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        uint32_t const restored = (static_cast<uint32_t>(result[1]) << 030) +
                                                  (static_cast<uint32_t>(result[2]) << 020) +
                                                  (static_cast<uint32_t>(result[3]) << 010) +
                                                  static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
                    }
                }

                SECTION("2147483648..9223372036854775807 (int64)")
                {
                    std::vector<uint64_t> const v = {2147483648ul, 9223372036854775807ul};
                    for (uint64_t i : v)
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
                            static_cast<uint8_t>((i >> 070) & 0xff),
                            static_cast<uint8_t>((i >> 060) & 0xff),
                            static_cast<uint8_t>((i >> 050) & 0xff),
                            static_cast<uint8_t>((i >> 040) & 0xff),
                            static_cast<uint8_t>((i >> 030) & 0xff),
                            static_cast<uint8_t>((i >> 020) & 0xff),
                            static_cast<uint8_t>((i >> 010) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
                        uint64_t const restored = (static_cast<uint64_t>(result[1]) << 070) +
                                                  (static_cast<uint64_t>(result[2]) << 060) +
                                                  (static_cast<uint64_t>(result[3]) << 050) +
                                                  (static_cast<uint64_t>(result[4]) << 040) +
                                                  (static_cast<uint64_t>(result[5]) << 030) +
                                                  (static_cast<uint64_t>(result[6]) << 020) +
                                                  (static_cast<uint64_t>(result[7]) << 010) +
                                                  static_cast<uint64_t>(result[8]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                        CHECK(json::from_ubjson(result, true, false) == j);
                    }
                }
            }

            SECTION("float64")
            {
                SECTION("3.1415925")
                {
                    double v = 3.1415925;
                    json const j = v;
                    std::vector<uint8_t> expected =
                    {
                        'D', 0x40, 0x09, 0x21, 0xfb, 0x3f, 0xa6, 0xde, 0xfc
                    };
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result) == v);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("high-precision number")
            {
                SECTION("unsigned integer number")
                {
                    std::vector<uint8_t> const vec = {'H', 'i', 0x14, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
                    const auto j = json::from_ubjson(vec);
                    CHECK(j.is_number_unsigned());
                    CHECK(j.dump() == "12345678901234567890");
                }

                SECTION("signed integer number")
                {
                    std::vector<uint8_t> const vec = {'H', 'i', 0x13, '-', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8'};
                    const auto j = json::from_ubjson(vec);
                    CHECK(j.is_number_integer());
                    CHECK(j.dump() == "-123456789012345678");
                }

                SECTION("floating-point number")
                {
                    std::vector<uint8_t> const vec = {'H', 'i', 0x16, '3', '.', '1', '4', '1', '5', '9',  '2', '6', '5', '3', '5', '8', '9',  '7', '9', '3', '2', '3', '8', '4',  '6'};
                    const auto j = json::from_ubjson(vec);
                    CHECK(j.is_number_float());
                    CHECK(j.dump() == "3.141592653589793");
                }

                SECTION("errors")
                {
                    // error while parsing length
                    std::vector<uint8_t> const vec0 = {'H', 'i'};
                    CHECK(json::from_ubjson(vec0, true, false).is_discarded());
                    // error while parsing string
                    std::vector<uint8_t> const vec1 = {'H', 'i', '1'};
                    CHECK(json::from_ubjson(vec1, true, false).is_discarded());

                    json _;
                    std::vector<uint8_t> const vec2 = {'H', 'i', 2, '1', 'A', '3'};
                    CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vec2), "[json.exception.parse_error.115] parse error at byte 5: syntax error while parsing UBJSON high-precision number: invalid number text: 1A", json::parse_error);
                    std::vector<uint8_t> const vec3 = {'H', 'i', 2, '1', '.'};
                    CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vec3), "[json.exception.parse_error.115] parse error at byte 5: syntax error while parsing UBJSON high-precision number: invalid number text: 1.", json::parse_error);
                    std::vector<uint8_t> const vec4 = {'H', 2, '1', '0'};
                    CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vec4), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing UBJSON size: expected length type specification (U, i, I, l, L) after '#'; last byte: 0x02", json::parse_error);
                }

                SECTION("serialization")
                {
                    // number that does not fit int64
                    json const j = 11111111111111111111ULL;
                    CHECK(j.is_number_unsigned());

                    // number will be serialized to high-precision number
                    const auto vec = json::to_ubjson(j);
                    std::vector<uint8_t> expected = {'H', 'i', 0x14, '1',  '1',  '1',  '1',  '1', '1',  '1',  '1',  '1',  '1', '1',  '1',  '1',  '1',  '1', '1',  '1',  '1',  '1',  '1'};
                    CHECK(vec == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(vec) == j);
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
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 3);
                    // check that no null byte is appended
                    if (N > 0)
                    {
                        CHECK(result.back() != '\x00');
                    }

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
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
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 3);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("N = 256..32767")
            {
                for (size_t N :
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
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), 'I');
                    expected.insert(expected.begin(), 'S');

                    // compare result + size
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 4);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("N = 65536..2147483647")
            {
                for (size_t N :
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
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 16) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 24) & 0xff));
                    expected.insert(expected.begin(), 'l');
                    expected.insert(expected.begin(), 'S');

                    // compare result + size
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 6);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }
        }

        SECTION("binary")
        {
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
                    if (N != 0)
                    {
                        expected.push_back(static_cast<std::uint8_t>('$'));
                        expected.push_back(static_cast<std::uint8_t>('U'));
                    }
                    expected.push_back(static_cast<std::uint8_t>('#'));
                    expected.push_back(static_cast<std::uint8_t>('i'));
                    expected.push_back(static_cast<std::uint8_t>(N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back(0x78);
                    }

                    // compare result + size
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);
                    if (N == 0)
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

                    // roundtrip only works to an array of numbers
                    json j_out = s;
                    CHECK(json::from_ubjson(result) == j_out);
                    CHECK(json::from_ubjson(result, true, false) == j_out);
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
                    expected.push_back(static_cast<std::uint8_t>('U'));
                    expected.push_back(static_cast<std::uint8_t>('#'));
                    expected.push_back(static_cast<std::uint8_t>('U'));
                    expected.push_back(static_cast<std::uint8_t>(N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back(0x78);
                    }

                    // compare result + size
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 6);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip only works to an array of numbers
                    json j_out = s;
                    CHECK(json::from_ubjson(result) == j_out);
                    CHECK(json::from_ubjson(result, true, false) == j_out);
                }
            }

            SECTION("N = 256..32767")
            {
                for (std::size_t N :
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
                    expected[2] = 'U';
                    expected[3] = '#';
                    expected[4] = 'I';
                    expected[5] = static_cast<std::uint8_t>((N >> 8) & 0xFF);
                    expected[6] = static_cast<std::uint8_t>(N & 0xFF);

                    // compare result + size
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 7);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip only works to an array of numbers
                    json j_out = s;
                    CHECK(json::from_ubjson(result) == j_out);
                    CHECK(json::from_ubjson(result, true, false) == j_out);
                }
            }

            SECTION("N = 32768..2147483647")
            {
                for (std::size_t N :
                        {
                            32768u, 77777u, 1048576u
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
                    expected[2] = 'U';
                    expected[3] = '#';
                    expected[4] = 'l';
                    expected[5] = static_cast<std::uint8_t>((N >> 24) & 0xFF);
                    expected[6] = static_cast<std::uint8_t>((N >> 16) & 0xFF);
                    expected[7] = static_cast<std::uint8_t>((N >> 8) & 0xFF);
                    expected[8] = static_cast<std::uint8_t>(N & 0xFF);

                    // compare result + size
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 9);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip only works to an array of numbers
                    json j_out = s;
                    CHECK(json::from_ubjson(result) == j_out);
                    CHECK(json::from_ubjson(result, true, false) == j_out);
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
                        expected.push_back(static_cast<std::uint8_t>('U'));
                        expected.push_back(static_cast<std::uint8_t>(0x78));
                    }
                    expected.push_back(static_cast<std::uint8_t>(']'));

                    // compare result + size
                    const auto result = json::to_ubjson(j, false, false);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 12);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip only works to an array of numbers
                    json j_out = s;
                    CHECK(json::from_ubjson(result) == j_out);
                    CHECK(json::from_ubjson(result, true, false) == j_out);
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
                        expected.push_back(static_cast<std::uint8_t>('U'));
                        expected.push_back(static_cast<std::uint8_t>(0x78));
                    }

                    // compare result + size
                    const auto result = json::to_ubjson(j, true, false);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 14);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip only works to an array of numbers
                    json j_out = s;
                    CHECK(json::from_ubjson(result) == j_out);
                    CHECK(json::from_ubjson(result, true, false) == j_out);
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
                    std::vector<uint8_t> expected = {'[', ']'};
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::array();
                    std::vector<uint8_t> expected = {'[', '#', 'i', 0};
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::array();
                    std::vector<uint8_t> expected = {'[', '#', 'i', 0};
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("[null]")
            {
                SECTION("size=false type=false")
                {
                    json const j = {nullptr};
                    std::vector<uint8_t> expected = {'[', 'Z', ']'};
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = {nullptr};
                    std::vector<uint8_t> expected = {'[', '#', 'i', 1, 'Z'};
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = {nullptr};
                    std::vector<uint8_t> expected = {'[', '$', 'Z', '#', 'i', 1};
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("[1,2,3,4,5]")
            {
                SECTION("size=false type=false")
                {
                    json const j = json::parse("[1,2,3,4,5]");
                    std::vector<uint8_t> expected = {'[', 'i', 1, 'i', 2, 'i', 3, 'i', 4, 'i', 5, ']'};
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::parse("[1,2,3,4,5]");
                    std::vector<uint8_t> expected = {'[', '#', 'i', 5, 'i', 1, 'i', 2, 'i', 3, 'i', 4, 'i', 5};
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::parse("[1,2,3,4,5]");
                    std::vector<uint8_t> expected = {'[', '$', 'i', '#', 'i', 5, 1, 2, 3, 4, 5};
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("[[[[]]]]")
            {
                SECTION("size=false type=false")
                {
                    json const j = json::parse("[[[[]]]]");
                    std::vector<uint8_t> expected = {'[', '[', '[', '[', ']', ']', ']', ']'};
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::parse("[[[[]]]]");
                    std::vector<uint8_t> expected = {'[', '#', 'i', 1, '[', '#', 'i', 1, '[', '#', 'i', 1, '[', '#', 'i', 0};
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::parse("[[[[]]]]");
                    std::vector<uint8_t> expected = {'[', '$', '[', '#', 'i', 1, '$', '[', '#', 'i', 1, '$', '[', '#', 'i', 1, '#', 'i', 0};
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("array with uint16_t elements")
            {
                SECTION("size=false type=false")
                {
                    json j(257, nullptr);
                    std::vector<uint8_t> expected(j.size() + 2, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[258] = ']'; // closing array
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
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
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json j(257, nullptr);
                    std::vector<uint8_t> expected = {'[', '$', 'Z', '#', 'I', 0x01, 0x01};
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("array with uint32_t elements")
            {
                SECTION("size=false type=false")
                {
                    json j(65793, nullptr);
                    std::vector<uint8_t> expected(j.size() + 2, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[65794] = ']'; // closing array
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json j(65793, nullptr);
                    std::vector<uint8_t> expected(j.size() + 7, 'Z'); // all null
                    expected[0] = '['; // opening array
                    expected[1] = '#'; // array size
                    expected[2] = 'l'; // int32
                    expected[3] = 0x00; // 0x00010101, first byte
                    expected[4] = 0x01; // 0x00010101, second byte
                    expected[5] = 0x01; // 0x00010101, third byte
                    expected[6] = 0x01; // 0x00010101, fourth byte
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json j(65793, nullptr);
                    std::vector<uint8_t> expected = {'[', '$', 'Z', '#', 'l', 0x00, 0x01, 0x01, 0x01};
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
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
                    std::vector<uint8_t> expected = {'{', '}'};
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::object();
                    std::vector<uint8_t> expected = {'{', '#', 'i', 0};
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::object();
                    std::vector<uint8_t> expected = {'{', '#', 'i', 0};
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("{\"\":null}")
            {
                SECTION("size=false type=false")
                {
                    json const j = {{"", nullptr}};
                    std::vector<uint8_t> expected = {'{', 'i', 0, 'Z', '}'};
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = {{"", nullptr}};
                    std::vector<uint8_t> expected = {'{', '#', 'i', 1, 'i', 0, 'Z'};
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = {{"", nullptr}};
                    std::vector<uint8_t> expected = {'{', '$', 'Z', '#', 'i', 1, 'i', 0};
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }
            }

            SECTION("{\"a\": {\"b\": {\"c\": {}}}}")
            {
                SECTION("size=false type=false")
                {
                    json const j = json::parse(R"({"a": {"b": {"c": {}}}})");
                    std::vector<uint8_t> expected =
                    {
                        '{', 'i', 1, 'a', '{', 'i', 1, 'b', '{', 'i', 1, 'c', '{', '}', '}', '}', '}'
                    };
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=false")
                {
                    json const j = json::parse(R"({"a": {"b": {"c": {}}}})");
                    std::vector<uint8_t> expected =
                    {
                        '{', '#', 'i', 1, 'i', 1, 'a', '{', '#', 'i', 1, 'i', 1, 'b', '{', '#', 'i', 1, 'i', 1, 'c', '{', '#', 'i', 0
                    };
                    const auto result = json::to_ubjson(j, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
                }

                SECTION("size=true type=true")
                {
                    json const j = json::parse(R"({"a": {"b": {"c": {}}}})");
                    std::vector<uint8_t> expected =
                    {
                        '{', '$', '{', '#', 'i', 1, 'i', 1, 'a', '$', '{', '#', 'i', 1, 'i', 1, 'b', '$', '{', '#', 'i', 1, 'i', 1, 'c', '#', 'i', 0
                    };
                    const auto result = json::to_ubjson(j, true, true);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result, true, false) == j);
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
                const auto result = json::from_ubjson(vec, false);
                CHECK(result == json());
            }

            SECTION("strict mode")
            {
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vec), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing UBJSON value: expected end of input; last byte: 0x5A", json::parse_error&);
            }
        }

        SECTION("excessive size")
        {
            SECTION("array")
            {
                std::vector<uint8_t> const v_ubjson = {'[', '$', 'Z', '#', 'L', 0x78, 0x28, 0x00, 0x68, 0x28, 0x69, 0x69, 0x17};
                json _;
                CHECK_THROWS_AS(_ = json::from_ubjson(v_ubjson), json::out_of_range&);

                json j;
                nlohmann::detail::json_sax_dom_callback_parser<json, decltype(nlohmann::detail::input_adapter(v_ubjson))> scp(j, [](int /*unused*/, json::parse_event_t /*unused*/, const json& /*unused*/) noexcept
                {
                    return true;
                });
                CHECK_THROWS_AS(_ = json::sax_parse(v_ubjson, &scp, json::input_format_t::ubjson), json::out_of_range&);
            }

            SECTION("object")
            {
                std::vector<uint8_t> const v_ubjson = {'{', '$', 'Z', '#', 'L', 0x78, 0x28, 0x00, 0x68, 0x28, 0x69, 0x69, 0x17};
                json _;
                CHECK_THROWS_AS(_ = json::from_ubjson(v_ubjson), json::out_of_range&);

                json j;
                nlohmann::detail::json_sax_dom_callback_parser<json, decltype(nlohmann::detail::input_adapter(v_ubjson))> scp(j, [](int /*unused*/, json::parse_event_t /*unused*/, const json& /*unused*/) noexcept
                {
                    return true;
                });
                CHECK_THROWS_AS(_ = json::sax_parse(v_ubjson, &scp, json::input_format_t::ubjson), json::out_of_range&);
            }
        }
    }

    SECTION("SAX aborts")
    {
        SECTION("start_array()")
        {
            std::vector<uint8_t> const v = {'[', 'T', 'F', ']'};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::ubjson));
        }

        SECTION("start_object()")
        {
            std::vector<uint8_t> const v = {'{', 'i', 3, 'f', 'o', 'o', 'F', '}'};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::ubjson));
        }

        SECTION("key() in object")
        {
            std::vector<uint8_t> const v = {'{', 'i', 3, 'f', 'o', 'o', 'F', '}'};
            SaxCountdown scp(1);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::ubjson));
        }

        SECTION("start_array(len)")
        {
            std::vector<uint8_t> const v = {'[', '#', 'i', '2', 'T', 'F'};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::ubjson));
        }

        SECTION("start_object(len)")
        {
            std::vector<uint8_t> const v = {'{', '#', 'i', '1', 3, 'f', 'o', 'o', 'F'};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::ubjson));
        }

        SECTION("key() in object with length")
        {
            std::vector<uint8_t> const v = {'{', 'i', 3, 'f', 'o', 'o', 'F', '}'};
            SaxCountdown scp(1);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::ubjson));
        }
    }

    SECTION("parsing values")
    {
        SECTION("strings")
        {
            // create a single-character string for all number types
            std::vector<uint8_t> s_i = {'S', 'i', 1, 'a'};
            std::vector<uint8_t> const s_U = {'S', 'U', 1, 'a'};
            std::vector<uint8_t> const s_I = {'S', 'I', 0, 1, 'a'};
            std::vector<uint8_t> const s_l = {'S', 'l', 0, 0, 0, 1, 'a'};
            std::vector<uint8_t> const s_L = {'S', 'L', 0, 0, 0, 0, 0, 0, 0, 1, 'a'};

            // check if string is parsed correctly to "a"
            CHECK(json::from_ubjson(s_i) == "a");
            CHECK(json::from_ubjson(s_U) == "a");
            CHECK(json::from_ubjson(s_I) == "a");
            CHECK(json::from_ubjson(s_l) == "a");
            CHECK(json::from_ubjson(s_L) == "a");

            // roundtrip: output should be optimized
            CHECK(json::to_ubjson(json::from_ubjson(s_i)) == s_i);
            CHECK(json::to_ubjson(json::from_ubjson(s_U)) == s_i);
            CHECK(json::to_ubjson(json::from_ubjson(s_I)) == s_i);
            CHECK(json::to_ubjson(json::from_ubjson(s_l)) == s_i);
            CHECK(json::to_ubjson(json::from_ubjson(s_L)) == s_i);
        }

        SECTION("number")
        {
            SECTION("float")
            {
                // float32
                std::vector<uint8_t> const v_d = {'d', 0x40, 0x49, 0x0f, 0xd0};
                CHECK(json::from_ubjson(v_d) == 3.14159f);

                // float64
                std::vector<uint8_t> const v_D = {'D', 0x40, 0x09, 0x21, 0xf9, 0xf0, 0x1b, 0x86, 0x6e};
                CHECK(json::from_ubjson(v_D) == 3.14159);

                // float32 is serialized as float64 as the library does not support float32
                CHECK(json::to_ubjson(json::from_ubjson(v_d)) == json::to_ubjson(3.14159f));
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
                std::vector<uint8_t> const v_I = {'[', '#', 'i', 2, 'I', 0x7F, 0xFF, 'I', 0x7F, 0xFF};
                std::vector<uint8_t> const v_l = {'[', '#', 'i', 2, 'l', 0x7F, 0xFF, 0xFF, 0xFF, 'l', 0x7F, 0xFF, 0xFF, 0xFF};
                std::vector<uint8_t> const v_L = {'[', '#', 'i', 2, 'L', 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 'L', 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                std::vector<uint8_t> const v_D = {'[', '#', 'i', 2, 'D', 0x40, 0x09, 0x21, 0xfb, 0x4d, 0x12, 0xd8, 0x4a, 'D', 0x40, 0x09, 0x21, 0xfb, 0x4d, 0x12, 0xd8, 0x4a};
                std::vector<uint8_t> const v_S = {'[', '#', 'i', 2, 'S', 'i', 1, 'a', 'S', 'i', 1, 'a'};
                std::vector<uint8_t> const v_C = {'[', '#', 'i', 2, 'C', 'a', 'C', 'a'};

                // check if vector is parsed correctly
                CHECK(json::from_ubjson(v_TU) == json({true, true}));
                CHECK(json::from_ubjson(v_T) == json({true, true}));
                CHECK(json::from_ubjson(v_F) == json({false, false}));
                CHECK(json::from_ubjson(v_Z) == json({nullptr, nullptr}));
                CHECK(json::from_ubjson(v_i) == json({127, 127}));
                CHECK(json::from_ubjson(v_U) == json({255, 255}));
                CHECK(json::from_ubjson(v_I) == json({32767, 32767}));
                CHECK(json::from_ubjson(v_l) == json({2147483647, 2147483647}));
                CHECK(json::from_ubjson(v_L) == json({9223372036854775807, 9223372036854775807}));
                CHECK(json::from_ubjson(v_D) == json({3.1415926, 3.1415926}));
                CHECK(json::from_ubjson(v_S) == json({"a", "a"}));
                CHECK(json::from_ubjson(v_C) == json({"a", "a"}));

                // roundtrip: output should be optimized
                CHECK(json::to_ubjson(json::from_ubjson(v_T), true) == v_T);
                CHECK(json::to_ubjson(json::from_ubjson(v_F), true) == v_F);
                CHECK(json::to_ubjson(json::from_ubjson(v_Z), true) == v_Z);
                CHECK(json::to_ubjson(json::from_ubjson(v_i), true) == v_i);
                CHECK(json::to_ubjson(json::from_ubjson(v_U), true) == v_U);
                CHECK(json::to_ubjson(json::from_ubjson(v_I), true) == v_I);
                CHECK(json::to_ubjson(json::from_ubjson(v_l), true) == v_l);
                CHECK(json::to_ubjson(json::from_ubjson(v_L), true) == v_L);
                CHECK(json::to_ubjson(json::from_ubjson(v_D), true) == v_D);
                CHECK(json::to_ubjson(json::from_ubjson(v_S), true) == v_S);
                CHECK(json::to_ubjson(json::from_ubjson(v_C), true) == v_S); // char is serialized to string
            }

            SECTION("optimized version (type and length)")
            {
                // create vector with two elements of the same type
                std::vector<uint8_t> const v_N = {'[', '$', 'N', '#', 'i', 2};
                std::vector<uint8_t> const v_T = {'[', '$', 'T', '#', 'i', 2};
                std::vector<uint8_t> const v_F = {'[', '$', 'F', '#', 'i', 2};
                std::vector<uint8_t> const v_Z = {'[', '$', 'Z', '#', 'i', 2};
                std::vector<uint8_t> const v_i = {'[', '$', 'i', '#', 'i', 2, 0x7F, 0x7F};
                std::vector<uint8_t> const v_U = {'[', '$', 'U', '#', 'i', 2, 0xFF, 0xFF};
                std::vector<uint8_t> const v_I = {'[', '$', 'I', '#', 'i', 2, 0x7F, 0xFF, 0x7F, 0xFF};
                std::vector<uint8_t> const v_l = {'[', '$', 'l', '#', 'i', 2, 0x7F, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF};
                std::vector<uint8_t> const v_L = {'[', '$', 'L', '#', 'i', 2, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                std::vector<uint8_t> const v_D = {'[', '$', 'D', '#', 'i', 2, 0x40, 0x09, 0x21, 0xfb, 0x4d, 0x12, 0xd8, 0x4a, 0x40, 0x09, 0x21, 0xfb, 0x4d, 0x12, 0xd8, 0x4a};
                std::vector<uint8_t> const v_S = {'[', '$', 'S', '#', 'i', 2, 'i', 1, 'a', 'i', 1, 'a'};
                std::vector<uint8_t> const v_C = {'[', '$', 'C', '#', 'i', 2, 'a', 'a'};

                // check if vector is parsed correctly
                CHECK(json::from_ubjson(v_N) == json::array());
                CHECK(json::from_ubjson(v_T) == json({true, true}));
                CHECK(json::from_ubjson(v_F) == json({false, false}));
                CHECK(json::from_ubjson(v_Z) == json({nullptr, nullptr}));
                CHECK(json::from_ubjson(v_i) == json({127, 127}));
                CHECK(json::from_ubjson(v_U) == json({255, 255}));
                CHECK(json::from_ubjson(v_I) == json({32767, 32767}));
                CHECK(json::from_ubjson(v_l) == json({2147483647, 2147483647}));
                CHECK(json::from_ubjson(v_L) == json({9223372036854775807, 9223372036854775807}));
                CHECK(json::from_ubjson(v_D) == json({3.1415926, 3.1415926}));
                CHECK(json::from_ubjson(v_S) == json({"a", "a"}));
                CHECK(json::from_ubjson(v_C) == json({"a", "a"}));

                // roundtrip: output should be optimized
                std::vector<uint8_t> const v_empty = {'[', '#', 'i', 0};
                CHECK(json::to_ubjson(json::from_ubjson(v_N), true, true) == v_empty);
                CHECK(json::to_ubjson(json::from_ubjson(v_T), true, true) == v_T);
                CHECK(json::to_ubjson(json::from_ubjson(v_F), true, true) == v_F);
                CHECK(json::to_ubjson(json::from_ubjson(v_Z), true, true) == v_Z);
                CHECK(json::to_ubjson(json::from_ubjson(v_i), true, true) == v_i);
                CHECK(json::to_ubjson(json::from_ubjson(v_U), true, true) == v_U);
                CHECK(json::to_ubjson(json::from_ubjson(v_I), true, true) == v_I);
                CHECK(json::to_ubjson(json::from_ubjson(v_l), true, true) == v_l);
                CHECK(json::to_ubjson(json::from_ubjson(v_L), true, true) == v_L);
                CHECK(json::to_ubjson(json::from_ubjson(v_D), true, true) == v_D);
                CHECK(json::to_ubjson(json::from_ubjson(v_S), true, true) == v_S);
                CHECK(json::to_ubjson(json::from_ubjson(v_C), true, true) == v_S); // char is serialized to string
            }
        }
    }

    SECTION("parse errors")
    {
        SECTION("empty byte vector")
        {
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(std::vector<uint8_t>()), "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
        }

        SECTION("char")
        {
            SECTION("eof after C byte")
            {
                std::vector<uint8_t> const v = {'C'};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing UBJSON char: unexpected end of input", json::parse_error&);
            }

            SECTION("byte out of range")
            {
                std::vector<uint8_t> const v = {'C', 130};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing UBJSON char: byte after 'C' must be in range 0x00..0x7F; last byte: 0x82", json::parse_error&);
            }
        }

        SECTION("strings")
        {
            SECTION("eof after S byte")
            {
                std::vector<uint8_t> const v = {'S'};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            }

            SECTION("invalid byte")
            {
                std::vector<uint8_t> const v = {'S', '1', 'a'};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing UBJSON string: expected length type specification (U, i, I, l, L); last byte: 0x31", json::parse_error&);
            }
        }

        SECTION("array")
        {
            SECTION("optimized array: no size following type")
            {
                std::vector<uint8_t> const v = {'[', '$', 'i', 2};
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.112] parse error at byte 4: syntax error while parsing UBJSON size: expected '#' after type information; last byte: 0x02", json::parse_error&);
            }
        }

        SECTION("strings")
        {
            std::vector<uint8_t> const vS = {'S'};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vS), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vS, true, false).is_discarded());

            std::vector<uint8_t> const v = {'S', 'i', '2', 'a'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing UBJSON string: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(v, true, false).is_discarded());

            std::vector<uint8_t> const vC = {'C'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vC), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing UBJSON char: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vC, true, false).is_discarded());
        }

        SECTION("sizes")
        {
            std::vector<uint8_t> const vU = {'[', '#', 'U'};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vU), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing UBJSON number: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vU, true, false).is_discarded());

            std::vector<uint8_t> const vi = {'[', '#', 'i'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vi), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing UBJSON number: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vi, true, false).is_discarded());

            std::vector<uint8_t> const vI = {'[', '#', 'I'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vI), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing UBJSON number: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vI, true, false).is_discarded());

            std::vector<uint8_t> const vl = {'[', '#', 'l'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vl), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing UBJSON number: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vl, true, false).is_discarded());

            std::vector<uint8_t> const vL = {'[', '#', 'L'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vL), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing UBJSON number: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vL, true, false).is_discarded());

            std::vector<uint8_t> const v0 = {'[', '#', 'T', ']'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v0), "[json.exception.parse_error.113] parse error at byte 3: syntax error while parsing UBJSON size: expected length type specification (U, i, I, l, L) after '#'; last byte: 0x54", json::parse_error&);
            CHECK(json::from_ubjson(v0, true, false).is_discarded());
        }

        SECTION("types")
        {
            std::vector<uint8_t> const v0 = {'[', '$'};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v0), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing UBJSON type: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(v0, true, false).is_discarded());

            std::vector<uint8_t> const vi = {'[', '$', '#'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vi), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vi, true, false).is_discarded());

            std::vector<uint8_t> const vT = {'[', '$', 'T'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vT), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vT, true, false).is_discarded());
        }

        SECTION("arrays")
        {
            std::vector<uint8_t> const vST = {'[', '$', 'i', '#', 'i', 2, 1};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vST), "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing UBJSON number: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vST, true, false).is_discarded());

            std::vector<uint8_t> const vS = {'[', '#', 'i', 2, 'i', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vS), "[json.exception.parse_error.110] parse error at byte 7: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vS, true, false).is_discarded());

            std::vector<uint8_t> const v = {'[', 'i', 2, 'i', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.110] parse error at byte 6: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(v, true, false).is_discarded());
        }

        SECTION("objects")
        {
            std::vector<uint8_t> const vST = {'{', '$', 'i', '#', 'i', 2, 'i', 1, 'a', 1};
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vST), "[json.exception.parse_error.110] parse error at byte 11: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vST, true, false).is_discarded());

            std::vector<uint8_t> const vT = {'{', '$', 'i', 'i', 1, 'a', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vT), "[json.exception.parse_error.112] parse error at byte 4: syntax error while parsing UBJSON size: expected '#' after type information; last byte: 0x69", json::parse_error&);
            CHECK(json::from_ubjson(vT, true, false).is_discarded());

            std::vector<uint8_t> const vS = {'{', '#', 'i', 2, 'i', 1, 'a', 'i', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vS), "[json.exception.parse_error.110] parse error at byte 10: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vS, true, false).is_discarded());

            std::vector<uint8_t> const v = {'{', 'i', 1, 'a', 'i', 1};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v), "[json.exception.parse_error.110] parse error at byte 7: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(v, true, false).is_discarded());

            std::vector<uint8_t> const v2 = {'{', 'i', 1, 'a', 'i', 1, 'i'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v2), "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing UBJSON number: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(v2, true, false).is_discarded());

            std::vector<uint8_t> const v3 = {'{', 'i', 1, 'a'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(v3), "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(v3, true, false).is_discarded());

            std::vector<uint8_t> const vST1 = {'{', '$', 'd', '#', 'i', 2, 'i', 1, 'a'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vST1), "[json.exception.parse_error.110] parse error at byte 10: syntax error while parsing UBJSON number: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vST1, true, false).is_discarded());

            std::vector<uint8_t> const vST2 = {'{', '#', 'i', 2, 'i', 1, 'a'};
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(vST2), "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing UBJSON value: unexpected end of input", json::parse_error&);
            CHECK(json::from_ubjson(vST2, true, false).is_discarded());
        }
    }

    SECTION("writing optimized values")
    {
        SECTION("integer")
        {
            SECTION("array of i")
            {
                json const j = {1, -1};
                std::vector<uint8_t> expected = {'[', '$', 'i', '#', 'i', 2, 1, 0xff};
                CHECK(json::to_ubjson(j, true, true) == expected);
            }

            SECTION("array of U")
            {
                json const j = {200, 201};
                std::vector<uint8_t> expected = {'[', '$', 'U', '#', 'i', 2, 0xC8, 0xC9};
                CHECK(json::to_ubjson(j, true, true) == expected);
            }

            SECTION("array of I")
            {
                json const j = {30000, -30000};
                std::vector<uint8_t> expected = {'[', '$', 'I', '#', 'i', 2, 0x75, 0x30, 0x8a, 0xd0};
                CHECK(json::to_ubjson(j, true, true) == expected);
            }

            SECTION("array of l")
            {
                json const j = {70000, -70000};
                std::vector<uint8_t> expected = {'[', '$', 'l', '#', 'i', 2, 0x00, 0x01, 0x11, 0x70, 0xFF, 0xFE, 0xEE, 0x90};
                CHECK(json::to_ubjson(j, true, true) == expected);
            }

            SECTION("array of L")
            {
                json const j = {5000000000, -5000000000};
                std::vector<uint8_t> expected = {'[', '$', 'L', '#', 'i', 2, 0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x00, 0xFF, 0xFF, 0xFF, 0xFE, 0xD5, 0xFA, 0x0E, 0x00};
                CHECK(json::to_ubjson(j, true, true) == expected);
            }
        }

        SECTION("unsigned integer")
        {
            SECTION("array of i")
            {
                json const j = {1u, 2u};
                std::vector<uint8_t> expected = {'[', '$', 'i', '#', 'i', 2, 1, 2};
                std::vector<uint8_t> expected_size = {'[', '#', 'i', 2, 'i', 1, 'i', 2};
                CHECK(json::to_ubjson(j, true, true) == expected);
                CHECK(json::to_ubjson(j, true) == expected_size);
            }

            SECTION("array of U")
            {
                json const j = {200u, 201u};
                std::vector<uint8_t> expected = {'[', '$', 'U', '#', 'i', 2, 0xC8, 0xC9};
                std::vector<uint8_t> expected_size = {'[', '#', 'i', 2, 'U', 0xC8, 'U', 0xC9};
                CHECK(json::to_ubjson(j, true, true) == expected);
                CHECK(json::to_ubjson(j, true) == expected_size);
            }

            SECTION("array of I")
            {
                json const j = {30000u, 30001u};
                std::vector<uint8_t> expected = {'[', '$', 'I', '#', 'i', 2, 0x75, 0x30, 0x75, 0x31};
                std::vector<uint8_t> expected_size = {'[', '#', 'i', 2, 'I', 0x75, 0x30, 'I', 0x75, 0x31};
                CHECK(json::to_ubjson(j, true, true) == expected);
                CHECK(json::to_ubjson(j, true) == expected_size);
            }

            SECTION("array of l")
            {
                json const j = {70000u, 70001u};
                std::vector<uint8_t> expected = {'[', '$', 'l', '#', 'i', 2, 0x00, 0x01, 0x11, 0x70, 0x00, 0x01, 0x11, 0x71};
                std::vector<uint8_t> expected_size = {'[', '#', 'i', 2, 'l', 0x00, 0x01, 0x11, 0x70, 'l', 0x00, 0x01, 0x11, 0x71};
                CHECK(json::to_ubjson(j, true, true) == expected);
                CHECK(json::to_ubjson(j, true) == expected_size);
            }

            SECTION("array of L")
            {
                json const j = {5000000000u, 5000000001u};
                std::vector<uint8_t> expected = {'[', '$', 'L', '#', 'i', 2, 0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x01};
                std::vector<uint8_t> expected_size = {'[', '#', 'i', 2, 'L', 0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x00, 'L', 0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x01};
                CHECK(json::to_ubjson(j, true, true) == expected);
                CHECK(json::to_ubjson(j, true) == expected_size);
            }
        }

        SECTION("discarded")
        {
            json const j = {json::value_t::discarded, json::value_t::discarded};
            std::vector<uint8_t> expected = {'[', '$', 'N', '#', 'i', 2};
            CHECK(json::to_ubjson(j, true, true) == expected);
        }
    }
}

TEST_CASE("Universal Binary JSON Specification Examples 1")
{
    SECTION("Null Value")
    {
        json const j = {{"passcode", nullptr}};
        std::vector<uint8_t> const v = {'{', 'i', 8, 'p', 'a', 's', 's', 'c', 'o', 'd', 'e', 'Z', '}'};
        CHECK(json::to_ubjson(j) == v);
        CHECK(json::from_ubjson(v) == j);
    }

    SECTION("No-Op Value")
    {
        json const j = {"foo", "bar", "baz"};
        std::vector<uint8_t> const v = {'[', 'S', 'i', 3, 'f', 'o', 'o',
                                        'S', 'i', 3, 'b', 'a', 'r',
                                        'S', 'i', 3, 'b', 'a', 'z', ']'
                                       };
        std::vector<uint8_t> const v2 = {'[', 'S', 'i', 3, 'f', 'o', 'o', 'N',
                                         'S', 'i', 3, 'b', 'a', 'r', 'N', 'N', 'N',
                                         'S', 'i', 3, 'b', 'a', 'z', 'N', 'N', ']'
                                        };
        CHECK(json::to_ubjson(j) == v);
        CHECK(json::from_ubjson(v) == j);
        CHECK(json::from_ubjson(v2) == j);
    }

    SECTION("Boolean Types")
    {
        json const j = {{"authorized", true}, {"verified", false}};
        std::vector<uint8_t> const v = {'{', 'i', 10, 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'e', 'd', 'T',
                                        'i', 8, 'v', 'e', 'r', 'i', 'f', 'i', 'e', 'd', 'F', '}'
                                       };
        CHECK(json::to_ubjson(j) == v);
        CHECK(json::from_ubjson(v) == j);
    }

    SECTION("Numeric Types")
    {
        json const j =
        {
            {"int8", 16},
            {"uint8", 255},
            {"int16", 32767},
            {"int32", 2147483647},
            {"int64", 9223372036854775807},
            {"float64", 113243.7863123}
        };
        std::vector<uint8_t> const v = {'{',
                                        'i', 7, 'f', 'l', 'o', 'a', 't', '6', '4', 'D', 0x40, 0xfb, 0xa5, 0xbc, 0x94, 0xbc, 0x34, 0xcf,
                                        'i', 5, 'i', 'n', 't', '1', '6', 'I', 0x7f, 0xff,
                                        'i', 5, 'i', 'n', 't', '3', '2', 'l', 0x7f, 0xff, 0xff, 0xff,
                                        'i', 5, 'i', 'n', 't', '6', '4', 'L', 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        'i', 4, 'i', 'n', 't', '8', 'i', 16,
                                        'i', 5, 'u', 'i', 'n', 't', '8', 'U', 0xff,
                                        '}'
                                       };
        CHECK(json::to_ubjson(j) == v);
        CHECK(json::from_ubjson(v) == j);
    }

    SECTION("Char Type")
    {
        json const j = {{"rolecode", "a"}, {"delim", ";"}};
        std::vector<uint8_t> const v = {'{', 'i', 5, 'd', 'e', 'l', 'i', 'm', 'C', ';', 'i', 8, 'r', 'o', 'l', 'e', 'c', 'o', 'd', 'e', 'C', 'a', '}'};
        //CHECK(json::to_ubjson(j) == v);
        CHECK(json::from_ubjson(v) == j);
    }

    SECTION("String Type")
    {
        SECTION("English")
        {
            json const j = "hello";
            std::vector<uint8_t> const v = {'S', 'i', 5, 'h', 'e', 'l', 'l', 'o'};
            CHECK(json::to_ubjson(j) == v);
            CHECK(json::from_ubjson(v) == j);
        }

        SECTION("Russian")
        {
            json const j = "привет";
            std::vector<uint8_t> const v = {'S', 'i', 12, 0xD0, 0xBF, 0xD1, 0x80, 0xD0, 0xB8, 0xD0, 0xB2, 0xD0, 0xB5, 0xD1, 0x82};
            CHECK(json::to_ubjson(j) == v);
            CHECK(json::from_ubjson(v) == j);
        }

        SECTION("Russian")
        {
            json const j = "مرحبا";
            std::vector<uint8_t> const v = {'S', 'i', 10, 0xD9, 0x85, 0xD8, 0xB1, 0xD8, 0xAD, 0xD8, 0xA8, 0xD8, 0xA7};
            CHECK(json::to_ubjson(j) == v);
            CHECK(json::from_ubjson(v) == j);
        }
    }

    SECTION("Array Type")
    {
        SECTION("size=false type=false")
        {
            // note the float has been replaced by a double
            json const j = {nullptr, true, false, 4782345193, 153.132, "ham"};
            std::vector<uint8_t> const v = {'[', 'Z', 'T', 'F', 'L', 0x00, 0x00, 0x00, 0x01, 0x1D, 0x0C, 0xCB, 0xE9, 'D', 0x40, 0x63, 0x24, 0x39, 0x58, 0x10, 0x62, 0x4e, 'S', 'i', 3, 'h', 'a', 'm', ']'};
            CHECK(json::to_ubjson(j) == v);
            CHECK(json::from_ubjson(v) == j);
        }

        SECTION("size=true type=false")
        {
            // note the float has been replaced by a double
            json const j = {nullptr, true, false, 4782345193, 153.132, "ham"};
            std::vector<uint8_t> const v = {'[', '#', 'i', 6, 'Z', 'T', 'F', 'L', 0x00, 0x00, 0x00, 0x01, 0x1D, 0x0C, 0xCB, 0xE9, 'D', 0x40, 0x63, 0x24, 0x39, 0x58, 0x10, 0x62, 0x4e, 'S', 'i', 3, 'h', 'a', 'm'};
            CHECK(json::to_ubjson(j, true) == v);
            CHECK(json::from_ubjson(v) == j);
        }

        SECTION("size=true type=true")
        {
            // note the float has been replaced by a double
            json const j = {nullptr, true, false, 4782345193, 153.132, "ham"};
            std::vector<uint8_t> const v = {'[', '#', 'i', 6, 'Z', 'T', 'F', 'L', 0x00, 0x00, 0x00, 0x01, 0x1D, 0x0C, 0xCB, 0xE9, 'D', 0x40, 0x63, 0x24, 0x39, 0x58, 0x10, 0x62, 0x4e, 'S', 'i', 3, 'h', 'a', 'm'};
            CHECK(json::to_ubjson(j, true, true) == v);
            CHECK(json::from_ubjson(v) == j);
        }
    }

    SECTION("Object Type")
    {
        SECTION("size=false type=false")
        {
            json const j =
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
            std::vector<uint8_t> const v = {'{', 'i', 4, 'p', 'o', 's', 't', '{',
                                            'i', 6, 'a', 'u', 't', 'h', 'o', 'r', 'S', 'i', 6, 'r', 'k', 'a', 'l', 'l', 'a',
                                            'i', 4, 'b', 'o', 'd', 'y', 'S', 'i', 16, 'I', ' ', 't', 'o', 't', 'a', 'l', 'l', 'y', ' ', 'a', 'g', 'r', 'e', 'e', '!',
                                            'i', 2, 'i', 'd', 'I', 0x04, 0x71,
                                            'i', 9, 't', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p', 'L', 0x00, 0x00, 0x01, 0x3D, 0xB1, 0x78, 0x66, 0x60,
                                            '}', '}'
                                           };
            CHECK(json::to_ubjson(j) == v);
            CHECK(json::from_ubjson(v) == j);
        }

        SECTION("size=true type=false")
        {
            json const j =
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
            std::vector<uint8_t> const v = {'{', '#', 'i', 1, 'i', 4, 'p', 'o', 's', 't', '{', '#', 'i', 4,
                                            'i', 6, 'a', 'u', 't', 'h', 'o', 'r', 'S', 'i', 6, 'r', 'k', 'a', 'l', 'l', 'a',
                                            'i', 4, 'b', 'o', 'd', 'y', 'S', 'i', 16, 'I', ' ', 't', 'o', 't', 'a', 'l', 'l', 'y', ' ', 'a', 'g', 'r', 'e', 'e', '!',
                                            'i', 2, 'i', 'd', 'I', 0x04, 0x71,
                                            'i', 9, 't', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p', 'L', 0x00, 0x00, 0x01, 0x3D, 0xB1, 0x78, 0x66, 0x60
                                           };
            CHECK(json::to_ubjson(j, true) == v);
            CHECK(json::from_ubjson(v) == j);
        }

        SECTION("size=true type=true")
        {
            json const j =
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
            std::vector<uint8_t> const v = {'{', '$', '{', '#', 'i', 1, 'i', 4, 'p', 'o', 's', 't', '#', 'i', 4,
                                            'i', 6, 'a', 'u', 't', 'h', 'o', 'r', 'S', 'i', 6, 'r', 'k', 'a', 'l', 'l', 'a',
                                            'i', 4, 'b', 'o', 'd', 'y', 'S', 'i', 16, 'I', ' ', 't', 'o', 't', 'a', 'l', 'l', 'y', ' ', 'a', 'g', 'r', 'e', 'e', '!',
                                            'i', 2, 'i', 'd', 'I', 0x04, 0x71,
                                            'i', 9, 't', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p', 'L', 0x00, 0x00, 0x01, 0x3D, 0xB1, 0x78, 0x66, 0x60
                                           };
            CHECK(json::to_ubjson(j, true, true) == v);
            CHECK(json::from_ubjson(v) == j);
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
                std::vector<uint8_t> const v = {'[',
                                                'D', 0x40, 0x3d, 0xf8, 0x51, 0xeb, 0x85, 0x1e, 0xb8,
                                                'D', 0x40, 0x3f, 0x21, 0x47, 0xae, 0x14, 0x7a, 0xe1,
                                                'D', 0x40, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                'D', 0x40, 0x00, 0xe7, 0x6c, 0x8b, 0x43, 0x95, 0x81,
                                                'D', 0x40, 0x37, 0xe3, 0x53, 0xf7, 0xce, 0xd9, 0x17,
                                                ']'
                                               };
                CHECK(json::to_ubjson(j) == v);
                CHECK(json::from_ubjson(v) == j);
            }

            SECTION("Optimized with count")
            {
                // note the floats have been replaced by doubles
                json const j = {29.97, 31.13, 67.0, 2.113, 23.888};
                std::vector<uint8_t> const v = {'[', '#', 'i', 5,
                                                'D', 0x40, 0x3d, 0xf8, 0x51, 0xeb, 0x85, 0x1e, 0xb8,
                                                'D', 0x40, 0x3f, 0x21, 0x47, 0xae, 0x14, 0x7a, 0xe1,
                                                'D', 0x40, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                'D', 0x40, 0x00, 0xe7, 0x6c, 0x8b, 0x43, 0x95, 0x81,
                                                'D', 0x40, 0x37, 0xe3, 0x53, 0xf7, 0xce, 0xd9, 0x17
                                               };
                CHECK(json::to_ubjson(j, true) == v);
                CHECK(json::from_ubjson(v) == j);
            }

            SECTION("Optimized with type & count")
            {
                // note the floats have been replaced by doubles
                json const j = {29.97, 31.13, 67.0, 2.113, 23.888};
                std::vector<uint8_t> const v = {'[', '$', 'D', '#', 'i', 5,
                                                0x40, 0x3d, 0xf8, 0x51, 0xeb, 0x85, 0x1e, 0xb8,
                                                0x40, 0x3f, 0x21, 0x47, 0xae, 0x14, 0x7a, 0xe1,
                                                0x40, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x40, 0x00, 0xe7, 0x6c, 0x8b, 0x43, 0x95, 0x81,
                                                0x40, 0x37, 0xe3, 0x53, 0xf7, 0xce, 0xd9, 0x17
                                               };
                CHECK(json::to_ubjson(j, true, true) == v);
                CHECK(json::from_ubjson(v) == j);
            }
        }

        SECTION("Object Example")
        {
            SECTION("No Optimization")
            {
                // note the floats have been replaced by doubles
                json const j = { {"lat", 29.976}, {"long", 31.131}, {"alt", 67.0} };
                std::vector<uint8_t> const v = {'{',
                                                'i', 3, 'a', 'l', 't', 'D', 0x40, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                'i', 3, 'l', 'a', 't', 'D', 0x40, 0x3d, 0xf9, 0xdb, 0x22, 0xd0, 0xe5, 0x60,
                                                'i', 4, 'l', 'o', 'n', 'g', 'D', 0x40, 0x3f, 0x21, 0x89, 0x37, 0x4b, 0xc6, 0xa8,
                                                '}'
                                               };
                CHECK(json::to_ubjson(j) == v);
                CHECK(json::from_ubjson(v) == j);
            }

            SECTION("Optimized with count")
            {
                // note the floats have been replaced by doubles
                json const j = { {"lat", 29.976}, {"long", 31.131}, {"alt", 67.0} };
                std::vector<uint8_t> const v = {'{', '#', 'i', 3,
                                                'i', 3, 'a', 'l', 't', 'D', 0x40, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                'i', 3, 'l', 'a', 't', 'D', 0x40, 0x3d, 0xf9, 0xdb, 0x22, 0xd0, 0xe5, 0x60,
                                                'i', 4, 'l', 'o', 'n', 'g', 'D', 0x40, 0x3f, 0x21, 0x89, 0x37, 0x4b, 0xc6, 0xa8
                                               };
                CHECK(json::to_ubjson(j, true) == v);
                CHECK(json::from_ubjson(v) == j);
            }

            SECTION("Optimized with type & count")
            {
                // note the floats have been replaced by doubles
                json const j = { {"lat", 29.976}, {"long", 31.131}, {"alt", 67.0} };
                std::vector<uint8_t> const v = {'{', '$', 'D', '#', 'i', 3,
                                                'i', 3, 'a', 'l', 't', 0x40, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                'i', 3, 'l', 'a', 't', 0x40, 0x3d, 0xf9, 0xdb, 0x22, 0xd0, 0xe5, 0x60,
                                                'i', 4, 'l', 'o', 'n', 'g', 0x40, 0x3f, 0x21, 0x89, 0x37, 0x4b, 0xc6, 0xa8
                                               };
                CHECK(json::to_ubjson(j, true, true) == v);
                CHECK(json::from_ubjson(v) == j);
            }
        }

        SECTION("Special Cases (Null, No-Op and Boolean)")
        {
            SECTION("Array")
            {
                std::vector<uint8_t> const v = {'[', '$', 'N', '#', 'I', 0x02, 0x00};
                CHECK(json::from_ubjson(v) == json::array());
            }

            SECTION("Object")
            {
                std::vector<uint8_t> const v = {'{', '$', 'Z', '#', 'i', 3, 'i', 4, 'n', 'a', 'm', 'e', 'i', 8, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 'i', 5, 'e', 'm', 'a', 'i', 'l'};
                CHECK(json::from_ubjson(v) == json({ {"name", nullptr}, {"password", nullptr}, {"email", nullptr} }));
            }
        }
    }
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("all UBJSON first bytes")
{
    // these bytes will fail immediately with exception parse_error.112
    std::set<uint8_t> supported =
    {
        'T', 'F', 'Z', 'U', 'i', 'I', 'l', 'L', 'd', 'D', 'C', 'S', '[', '{', 'N', 'H'
    };

    for (auto i = 0; i < 256; ++i)
    {
        const auto byte = static_cast<uint8_t>(i);
        CAPTURE(byte)

        try
        {
            auto res = json::from_ubjson(std::vector<uint8_t>(1, byte));
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

TEST_CASE("UBJSON roundtrips" * doctest::skip())
{
    SECTION("input from self-generated UBJSON files")
    {
        for (std::string filename :
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
                json const j1 = json::parse(f_json);

                // parse UBJSON file
                auto const packed = utils::read_binary_file(filename + ".ubjson");
                json j2;
                CHECK_NOTHROW(j2 = json::from_ubjson(packed));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": std::ifstream");
                // parse JSON file
                std::ifstream f_json(filename);
                json const j1 = json::parse(f_json);

                // parse UBJSON file
                std::ifstream f_ubjson(filename + ".ubjson", std::ios::binary);
                json j2;
                CHECK_NOTHROW(j2 = json::from_ubjson(f_ubjson));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": uint8_t* and size");
                // parse JSON file
                std::ifstream f_json(filename);
                const json j1 = json::parse(f_json);

                // parse UBJSON file
                auto const packed = utils::read_binary_file(filename + ".ubjson");
                json j2;
                CHECK_NOTHROW(j2 = json::from_ubjson({packed.data(), packed.size()}));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": output to output adapters");
                // parse JSON file
                std::ifstream f_json(filename);
                json const j1 = json::parse(f_json);

                // parse UBJSON file
                auto const packed = utils::read_binary_file(filename + ".ubjson");

                {
                    INFO_WITH_TEMP(filename + ": output adapters: std::vector<uint8_t>");
                    std::vector<uint8_t> vec;
                    json::to_ubjson(j1, vec);
                    CHECK(vec == packed);
                }
            }
        }
    }
}
