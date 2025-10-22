//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <fstream>
#include <sstream>
#include <iomanip>
#include <limits>
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

TEST_CASE("MessagePack")
{
    SECTION("individual values")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            json const j = json::value_t::discarded;
            const auto result = json::to_msgpack(j);
            CHECK(result.empty());
        }

        SECTION("null")
        {
            json const j = nullptr;
            std::vector<uint8_t> const expected = {0xc0};
            const auto result = json::to_msgpack(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_msgpack(result) == j);
            CHECK(json::from_msgpack(result, true, false) == j);
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json const j = true;
                std::vector<uint8_t> const expected = {0xc3};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("false")
            {
                json const j = false;
                std::vector<uint8_t> const expected = {0xc2};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }
        }

        SECTION("number")
        {
            SECTION("signed")
            {
                SECTION("-32..-1 (negative fixnum)")
                {
                    for (auto i = -32; i <= -1; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            static_cast<uint8_t>(i)
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 1);

                        // check individual bytes
                        CHECK(static_cast<int8_t>(result[0]) == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("0..127 (positive fixnum)")
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
                        std::vector<uint8_t> const expected{static_cast<uint8_t>(i)};

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 1);

                        // check individual bytes
                        CHECK(result[0] == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("128..255 (int 8)")
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
                            0xcc,
                            static_cast<uint8_t>(i),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 0xcc);
                        auto const restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("256..65535 (int 16)")
                {
                    for (size_t i = 256; i <= 65535; ++i)
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
                            0xcd,
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0xcd);
                        auto const restored = static_cast<uint16_t>((static_cast<uint8_t>(result[1]) * 256) + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("65536..4294967295 (int 32)")
                {
                    for (uint32_t i :
                            {
                                65536u, 77777u, 1048576u, 4294967295u
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
                            0xce,
                            static_cast<uint8_t>((i >> 24) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0xce);
                        uint32_t const restored = (static_cast<uint32_t>(result[1]) << 030) +
                                                  (static_cast<uint32_t>(result[2]) << 020) +
                                                  (static_cast<uint32_t>(result[3]) << 010) +
                                                  static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("4294967296..9223372036854775807 (int 64)")
                {
                    for (uint64_t i :
                            {
                                4294967296LU, 9223372036854775807LU
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
                            0xcf,
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
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0xcf);
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
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("-128..-33 (int 8)")
                {
                    for (auto i = -128; i <= -33; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            0xd0,
                            static_cast<uint8_t>(i),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 0xd0);
                        CHECK(static_cast<int8_t>(result[1]) == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("-9263 (int 16)")
                {
                    json const j = -9263;
                    std::vector<uint8_t> const expected = {0xd1, 0xdb, 0xd1};

                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);

                    auto const restored = static_cast<int16_t>((result[1] << 8) + result[2]);
                    CHECK(restored == -9263);

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }

                SECTION("-32768..-129 (int 16)")
                {
                    for (int16_t i = -32768; i <= static_cast<std::int16_t>(-129); ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            0xd1,
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0xd1);
                        auto const restored = static_cast<int16_t>((result[1] << 8) + result[2]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("-32769..-2147483648")
                {
                    std::vector<int32_t> const numbers
                    {
                        -32769,
                        -65536,
                        -77777,
                        -1048576,
                        -2147483648LL,
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
                            0xd2,
                            static_cast<uint8_t>((i >> 24) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0xd2);
                        uint32_t const restored = (static_cast<uint32_t>(result[1]) << 030) +
                                                  (static_cast<uint32_t>(result[2]) << 020) +
                                                  (static_cast<uint32_t>(result[3]) << 010) +
                                                  static_cast<uint32_t>(result[4]);
                        CHECK(static_cast<std::int32_t>(restored) == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("-9223372036854775808..-2147483649 (int 64)")
                {
                    std::vector<int64_t> const numbers
                    {
                        (std::numeric_limits<int64_t>::min)(),
                        -2147483649LL,
                    };
                    for (auto i : numbers)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            0xd3,
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
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0xd3);
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
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }
            }

            SECTION("unsigned")
            {
                SECTION("0..127 (positive fixnum)")
                {
                    for (size_t i = 0; i <= 127; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected{static_cast<uint8_t>(i)};

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 1);

                        // check individual bytes
                        CHECK(result[0] == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("128..255 (uint 8)")
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
                            0xcc,
                            static_cast<uint8_t>(i),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 0xcc);
                        auto const restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("256..65535 (uint 16)")
                {
                    for (size_t i = 256; i <= 65535; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json const j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> const expected
                        {
                            0xcd,
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0xcd);
                        auto const restored = static_cast<uint16_t>((static_cast<uint8_t>(result[1]) * 256) + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("65536..4294967295 (uint 32)")
                {
                    for (const uint32_t i :
                            {
                                65536u, 77777u, 1048576u, 4294967295u
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
                            0xce,
                            static_cast<uint8_t>((i >> 24) & 0xff),
                            static_cast<uint8_t>((i >> 16) & 0xff),
                            static_cast<uint8_t>((i >> 8) & 0xff),
                            static_cast<uint8_t>(i & 0xff),
                        };

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0xce);
                        uint32_t const restored = (static_cast<uint32_t>(result[1]) << 030) +
                                                  (static_cast<uint32_t>(result[2]) << 020) +
                                                  (static_cast<uint32_t>(result[3]) << 010) +
                                                  static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("4294967296..18446744073709551615 (uint 64)")
                {
                    for (const uint64_t i :
                            {
                                4294967296LU, 18446744073709551615LU
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
                            0xcf,
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
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0xcf);
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
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }
            }

            SECTION("float")
            {
                SECTION("3.1415925")
                {
                    double const v = 3.1415925;
                    json const j = v;
                    std::vector<uint8_t> const expected =
                    {
                        0xcb, 0x40, 0x09, 0x21, 0xfb, 0x3f, 0xa6, 0xde, 0xfc
                    };
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result) == v);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }

                SECTION("1.0")
                {
                    double const v = 1.0;
                    json const j = v;
                    std::vector<uint8_t> const expected =
                    {
                        0xca, 0x3f, 0x80, 0x00, 0x00
                    };
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result) == v);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }

                SECTION("128.128")
                {
                    double const v = 128.1280059814453125;
                    json const j = v;
                    std::vector<uint8_t> const expected =
                    {
                        0xca, 0x43, 0x00, 0x20, 0xc5
                    };
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result) == v);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }
        }

        SECTION("string")
        {
            SECTION("N = 0..31")
            {
                // explicitly enumerate the first byte for all 32 strings
                const std::vector<uint8_t> first_bytes =
                {
                    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
                    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1,
                    0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
                    0xbb, 0xbc, 0xbd, 0xbe, 0xbf
                };

                for (size_t N = 0; N < first_bytes.size(); ++N)
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json const j = s;

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    expected.push_back(first_bytes[N]);
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back('x');
                    }

                    // check first byte
                    CHECK((first_bytes[N] & 0x1f) == N);

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 1);
                    // check that no null byte is appended
                    if (N > 0)
                    {
                        CHECK(result.back() != '\x00');
                    }

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }

            SECTION("N = 32..255")
            {
                for (size_t N = 32; N <= 255; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json const j = s;

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    expected.push_back(0xd9);
                    expected.push_back(static_cast<uint8_t>(N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back('x');
                    }

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 2);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }

            SECTION("N = 256..65535")
            {
                for (size_t N :
                        {
                            256u, 999u, 1025u, 3333u, 2048u, 65535u
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
                    expected.insert(expected.begin(), 0xda);

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 3);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }

            SECTION("N = 65536..4294967295")
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
                    expected.insert(expected.begin(), 0xdb);

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 5);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }
        }

        SECTION("array")
        {
            SECTION("empty")
            {
                json const j = json::array();
                std::vector<uint8_t> const expected = {0x90};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("[null]")
            {
                json const j = {nullptr};
                std::vector<uint8_t> const expected = {0x91, 0xc0};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("[1,2,3,4,5]")
            {
                json const j = json::parse("[1,2,3,4,5]");
                std::vector<uint8_t> const expected = {0x95, 0x01, 0x02, 0x03, 0x04, 0x05};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("[[[[]]]]")
            {
                json const j = json::parse("[[[[]]]]");
                std::vector<uint8_t> const expected = {0x91, 0x91, 0x91, 0x90};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("array 16")
            {
                json j(16, nullptr);
                std::vector<uint8_t> expected(j.size() + 3, 0xc0); // all null
                expected[0] = 0xdc; // array 16
                expected[1] = 0x00; // size (0x0010), byte 0
                expected[2] = 0x10; // size (0x0010), byte 1
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("array 32")
            {
                json j(65536, nullptr);
                std::vector<uint8_t> expected(j.size() + 5, 0xc0); // all null
                expected[0] = 0xdd; // array 32
                expected[1] = 0x00; // size (0x00100000), byte 0
                expected[2] = 0x01; // size (0x00100000), byte 1
                expected[3] = 0x00; // size (0x00100000), byte 2
                expected[4] = 0x00; // size (0x00100000), byte 3
                const auto result = json::to_msgpack(j);
                //CHECK(result == expected);

                CHECK(result.size() == expected.size());
                for (size_t i = 0; i < expected.size(); ++i)
                {
                    CAPTURE(i)
                    CHECK(result[i] == expected[i]);
                }

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }
        }

        SECTION("object")
        {
            SECTION("empty")
            {
                json const j = json::object();
                std::vector<uint8_t> const expected = {0x80};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("{\"\":null}")
            {
                json const j = {{"", nullptr}};
                std::vector<uint8_t> const expected = {0x81, 0xa0, 0xc0};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("{\"a\": {\"b\": {\"c\": {}}}}")
            {
                json const j = json::parse(R"({"a": {"b": {"c": {}}}})");
                std::vector<uint8_t> const expected =
                {
                    0x81, 0xa1, 0x61, 0x81, 0xa1, 0x62, 0x81, 0xa1, 0x63, 0x80
                };
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("map 16")
            {
                json const j = R"({"00": null, "01": null, "02": null, "03": null,
                             "04": null, "05": null, "06": null, "07": null,
                             "08": null, "09": null, "10": null, "11": null,
                             "12": null, "13": null, "14": null, "15": null})"_json;

                const auto result = json::to_msgpack(j);

                // Checking against an expected vector byte by byte is
                // difficult, because no assumption on the order of key/value
                // pairs are made. We therefore only check the prefix (type and
                // size) and the overall size. The rest is then handled in the
                // roundtrip check.
                CHECK(result.size() == 67); // 1 type, 2 size, 16*4 content
                CHECK(result[0] == 0xde); // map 16
                CHECK(result[1] == 0x00); // byte 0 of size (0x0010)
                CHECK(result[2] == 0x10); // byte 1 of size (0x0010)

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("map 32")
            {
                json j;
                for (auto i = 0; i < 65536; ++i)
                {
                    // format i to a fixed width of 5
                    // each entry will need 7 bytes: 6 for fixstr, 1 for null
                    std::stringstream ss;
                    ss << std::setw(5) << std::setfill('0') << i;
                    j.emplace(ss.str(), nullptr);
                }

                const auto result = json::to_msgpack(j);

                // Checking against an expected vector byte by byte is
                // difficult, because no assumption on the order of key/value
                // pairs are made. We therefore only check the prefix (type and
                // size) and the overall size. The rest is then handled in the
                // roundtrip check.
                CHECK(result.size() == 458757); // 1 type, 4 size, 65536*7 content
                CHECK(result[0] == 0xdf); // map 32
                CHECK(result[1] == 0x00); // byte 0 of size (0x00010000)
                CHECK(result[2] == 0x01); // byte 1 of size (0x00010000)
                CHECK(result[3] == 0x00); // byte 2 of size (0x00010000)
                CHECK(result[4] == 0x00); // byte 3 of size (0x00010000)

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }
        }

        SECTION("extension")
        {
            SECTION("N = 0..255")
            {
                for (size_t N = 0; N <= 0xFF; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with byte array containing of N * 'x'
                    const auto s = std::vector<uint8_t>(N, 'x');
                    json j = json::binary(s);
                    std::uint8_t const subtype = 42;
                    j.get_binary().set_subtype(subtype);

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    switch (N)
                    {
                        case 1:
                            expected.push_back(static_cast<std::uint8_t>(0xD4));
                            break;
                        case 2:
                            expected.push_back(static_cast<std::uint8_t>(0xD5));
                            break;
                        case 4:
                            expected.push_back(static_cast<std::uint8_t>(0xD6));
                            break;
                        case 8:
                            expected.push_back(static_cast<std::uint8_t>(0xD7));
                            break;
                        case 16:
                            expected.push_back(static_cast<std::uint8_t>(0xD8));
                            break;
                        default:
                            expected.push_back(static_cast<std::uint8_t>(0xC7));
                            expected.push_back(static_cast<std::uint8_t>(N));
                            break;
                    }
                    expected.push_back(subtype);

                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back(0x78);
                    }

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    switch (N)
                    {
                        case 1:
                        case 2:
                        case 4:
                        case 8:
                        case 16:
                            CHECK(result.size() == N + 2);
                            break;
                        default:
                            CHECK(result.size() == N + 3);
                            break;
                    }

                    // check that no null byte is appended
                    if (N > 0)
                    {
                        CHECK(result.back() != '\x00');
                    }

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }

            SECTION("N = 256..65535")
            {
                for (std::size_t N :
                        {
                            256u, 999u, 1025u, 3333u, 2048u, 65535u
                        })
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::vector<uint8_t>(N, 'x');
                    json j = json::binary(s);
                    std::uint8_t const subtype = 42;
                    j.get_binary().set_subtype(subtype);

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), subtype);
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), 0xC8);

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 4);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }

            SECTION("N = 65536..4294967295")
            {
                for (std::size_t N :
                        {
                            65536u, 77777u, 1048576u
                        })
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::vector<uint8_t>(N, 'x');
                    json j = json::binary(s);
                    std::uint8_t const subtype = 42;
                    j.get_binary().set_subtype(subtype);

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), subtype);
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 16) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 24) & 0xff));
                    expected.insert(expected.begin(), 0xC9);

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 6);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }
        }

        SECTION("binary")
        {
            SECTION("N = 0..255")
            {
                for (std::size_t N = 0; N <= 0xFF; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with byte array containing of N * 'x'
                    const auto s = std::vector<uint8_t>(N, 'x');
                    json const j = json::binary(s);

                    // create expected byte vector
                    std::vector<std::uint8_t> expected;
                    expected.push_back(static_cast<std::uint8_t>(0xC4));
                    expected.push_back(static_cast<std::uint8_t>(N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back(0x78);
                    }

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 2);
                    // check that no null byte is appended
                    if (N > 0)
                    {
                        CHECK(result.back() != '\x00');
                    }

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }

            SECTION("N = 256..65535")
            {
                for (std::size_t N :
                        {
                            256u, 999u, 1025u, 3333u, 2048u, 65535u
                        })
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::vector<std::uint8_t>(N, 'x');
                    json const j = json::binary(s);

                    // create expected byte vector (hack: create string first)
                    std::vector<std::uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<std::uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<std::uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), 0xC5);

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 3);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }

            SECTION("N = 65536..4294967295")
            {
                for (std::size_t N :
                        {
                            65536u, 77777u, 1048576u
                        })
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::vector<std::uint8_t>(N, 'x');
                    json const j = json::binary(s);

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<std::uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<std::uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), static_cast<std::uint8_t>((N >> 16) & 0xff));
                    expected.insert(expected.begin(), static_cast<std::uint8_t>((N >> 24) & 0xff));
                    expected.insert(expected.begin(), 0xC6);

                    // compare result + size
                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 5);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }
            }
        }
    }

    SECTION("from float32")
    {
        auto given = std::vector<uint8_t>({0xca, 0x41, 0xc8, 0x00, 0x01});
        json const j = json::from_msgpack(given);
        CHECK(j.get<double>() == Approx(25.0000019073486));
    }

    SECTION("errors")
    {
        SECTION("empty byte vector")
        {
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>()), "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing MessagePack value: unexpected end of input", json::parse_error&);
            CHECK(json::from_msgpack(std::vector<uint8_t>(), true, false).is_discarded());
        }

        SECTION("too short byte vector")
        {
            json _;

            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0x87})),
                                 "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack string: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcc})),
                                 "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcd})),
                                 "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcd, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xce})),
                                 "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xce, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xce, 0x00, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xce, 0x00, 0x00, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcf})),
                                 "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 6: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 7: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
                                 "[json.exception.parse_error.110] parse error at byte 9: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xa5, 0x68, 0x65})),
                                 "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing MessagePack string: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0x92, 0x01})),
                                 "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack value: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0x81, 0xa1, 0x61})),
                                 "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing MessagePack value: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xc4, 0x02})),
                                 "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack binary: unexpected end of input", json::parse_error&);

            CHECK(json::from_msgpack(std::vector<uint8_t>({0x87}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcc}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcd}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcd, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xce}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcf}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xa5, 0x68, 0x65}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0x92, 0x01}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0x81, 0xA1, 0x61}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xc4, 0x02}), true, false).is_discarded());
            CHECK(json::from_msgpack(std::vector<uint8_t>({0xc4}), true, false).is_discarded());
        }

        SECTION("unexpected end inside int with stream")
        {
            json _;
            const std::string data = {static_cast<char>(0xd2u), static_cast<char>(0x12u), static_cast<char>(0x34u), static_cast<char>(0x56u)};
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::istringstream(data, std::ios::binary)),
                                 "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing MessagePack number: unexpected end of input", json::parse_error&);
        }
        SECTION("misuse wchar for binary")
        {
            json _;
            // creates 0xd2 after UTF-8 decoding, triggers get_elements in wide_string_input_adapter for code coverage
            const std::u32string data = {static_cast<char32_t>(0x0280)};
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(data),
                                 "[json.exception.parse_error.112] parse error at byte 1: wide string type cannot be interpreted as binary data", json::parse_error&);
        }

        SECTION("unsupported bytes")
        {
            SECTION("concrete examples")
            {
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0xc1})), "[json.exception.parse_error.112] parse error at byte 1: syntax error while parsing MessagePack value: invalid byte: 0xC1", json::parse_error&);
            }

            SECTION("all unsupported bytes")
            {
                for (auto byte :
                        {
                            // never used
                            0xc1
                        })
                {
                    json _;
                    CHECK_THROWS_AS(_ = json::from_msgpack(std::vector<uint8_t>({static_cast<uint8_t>(byte)})), json::parse_error&);
                    CHECK(json::from_msgpack(std::vector<uint8_t>({static_cast<uint8_t>(byte)}), true, false).is_discarded());
                }
            }
        }

        SECTION("invalid string in map")
        {
            json _;
            CHECK_THROWS_WITH_AS(_ = json::from_msgpack(std::vector<uint8_t>({0x81, 0xff, 0x01})), "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing MessagePack string: expected length specification (0xA0-0xBF, 0xD9-0xDB); last byte: 0xFF", json::parse_error&);
            CHECK(json::from_msgpack(std::vector<uint8_t>({0x81, 0xff, 0x01}), true, false).is_discarded());
        }

        SECTION("strict mode")
        {
            std::vector<uint8_t> const vec = {0xc0, 0xc0};
            SECTION("non-strict mode")
            {
                const auto result = json::from_msgpack(vec, false);
                CHECK(result == json());
            }

            SECTION("strict mode")
            {
                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_msgpack(vec), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack value: expected end of input; last byte: 0xC0", json::parse_error&);
                CHECK(json::from_msgpack(vec, true, false).is_discarded());
            }
        }
    }

    SECTION("SAX aborts")
    {
        SECTION("start_array(len)")
        {
            std::vector<uint8_t> const v = {0x93, 0x01, 0x02, 0x03};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::msgpack));
        }

        SECTION("start_object(len)")
        {
            std::vector<uint8_t> const v = {0x81, 0xa3, 0x66, 0x6F, 0x6F, 0xc2};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::msgpack));
        }

        SECTION("key()")
        {
            std::vector<uint8_t> const v = {0x81, 0xa3, 0x66, 0x6F, 0x6F, 0xc2};
            SaxCountdown scp(1);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::msgpack));
        }
    }
}

// use this testcase outside [hide] to run it with Valgrind
TEST_CASE("single MessagePack roundtrip")
{
    SECTION("sample.json")
    {
        std::string const filename = TEST_DATA_DIRECTORY "/json_testsuite/sample.json";

        // parse JSON file
        std::ifstream f_json(filename);
        const json j1 = json::parse(f_json);

        // parse MessagePack file
        auto packed = utils::read_binary_file(filename + ".msgpack");
        json j2;
        CHECK_NOTHROW(j2 = json::from_msgpack(packed));

        // compare parsed JSON values
        CHECK(j1 == j2);

        SECTION("roundtrips")
        {
            SECTION("std::ostringstream")
            {
                std::basic_ostringstream<char> ss;
                json::to_msgpack(j1, ss);
                json j3 = json::from_msgpack(ss.str());
                CHECK(j1 == j3);
            }

            SECTION("std::string")
            {
                std::string s;
                json::to_msgpack(j1, s);
                json j3 = json::from_msgpack(s);
                CHECK(j1 == j3);
            }
        }

        // check with different start index
        packed.insert(packed.begin(), 5, 0xff);
        CHECK(j1 == json::from_msgpack(packed.begin() + 5, packed.end()));
    }
}

TEST_CASE("MessagePack roundtrips" * doctest::skip())
{
    SECTION("input from msgpack-python")
    {
        // most of these are excluded due to differences in key order (not a real problem)
        std::set<std::string> exclude_packed;
        exclude_packed.insert(TEST_DATA_DIRECTORY "/json.org/1.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/json.org/2.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/json.org/3.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/json.org/4.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/json.org/5.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/json_testsuite/sample.json"); // kills AppVeyor
        exclude_packed.insert(TEST_DATA_DIRECTORY "/json_tests/pass1.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/regression/working_file.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_basic.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_duplicated_key.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_long_strings.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_simple.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_string_unicode.json");

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
                    TEST_DATA_DIRECTORY "/json_testsuite/sample.json", // kills AppVeyor
                    TEST_DATA_DIRECTORY "/json_tests/pass1.json",
                    TEST_DATA_DIRECTORY "/json_tests/pass2.json",
                    TEST_DATA_DIRECTORY "/json_tests/pass3.json",
                    TEST_DATA_DIRECTORY "/regression/floats.json",
                    TEST_DATA_DIRECTORY "/regression/signed_ints.json",
                    TEST_DATA_DIRECTORY "/regression/unsigned_ints.json",
                    TEST_DATA_DIRECTORY "/regression/working_file.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_arraysWithSpaces.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_empty-string.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_empty.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_ending_with_newline.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_false.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_heterogeneous.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_null.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_with_1_and_newline.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_with_leading_space.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_with_several_null.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_array_with_trailing_space.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_0e+1.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_0e1.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_after_space.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_double_close_to_zero.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_double_huge_neg_exp.json",
                    //TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_huge_exp.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_int_with_exp.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_minus_zero.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_negative_int.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_negative_one.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_negative_zero.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_capital_e.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_capital_e_neg_exp.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_capital_e_pos_exp.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_exponent.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_fraction_exponent.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_neg_exp.json",
                    //TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_neg_overflow.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_pos_exponent.json",
                    //TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_pos_overflow.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_underflow.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_simple_int.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_simple_real.json",
                    //TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_too_big_neg_int.json",
                    //TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_too_big_pos_int.json",
                    //TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_very_big_negative_int.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_basic.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_duplicated_key.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_duplicated_key_and_value.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_empty.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_empty_key.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_escaped_null_in_key.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_extreme_numbers.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_long_strings.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_simple.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_string_unicode.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_with_newlines.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_1_2_3_bytes_UTF-8_sequences.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_UTF-16_Surrogates_U+1D11E_MUSICAL_SYMBOL_G_CLEF.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_accepted_surrogate_pair.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_accepted_surrogate_pairs.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_allowed_escapes.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_backslash_and_u_escaped_zero.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_backslash_doublequotes.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_comments.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_double_escape_a.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_double_escape_n.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_escaped_control_character.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_escaped_noncharacter.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_in_array.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_in_array_with_leading_space.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_last_surrogates_1_and_2.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_newline_uescaped.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_nonCharacterInUTF-8_U+10FFFF.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_nonCharacterInUTF-8_U+1FFFF.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_nonCharacterInUTF-8_U+FFFF.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_null_escape.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_one-byte-utf-8.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_pi.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_simple_ascii.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_space.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_three-byte-utf-8.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_two-byte-utf-8.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_u+2028_line_sep.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_u+2029_par_sep.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_uEscape.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_unescaped_char_delete.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_unicode.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_unicodeEscapedBackslash.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_unicode_2.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_unicode_U+200B_ZERO_WIDTH_SPACE.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_unicode_U+2064_invisible_plus.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_unicode_escaped_double_quote.json",
                    // TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_utf16.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_utf8.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_string_with_del_character.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_lonely_false.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_lonely_int.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_lonely_negative_real.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_lonely_null.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_lonely_string.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_lonely_true.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_string_empty.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_trailing_newline.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_true_in_array.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_structure_whitespace_array.json"
                })
        {
            CAPTURE(filename)

            {
                INFO_WITH_TEMP(filename + ": std::vector<uint8_t>");
                // parse JSON file
                std::ifstream f_json(filename);
                const json j1 = json::parse(f_json);

                // parse MessagePack file
                auto packed = utils::read_binary_file(filename + ".msgpack");
                json j2;
                CHECK_NOTHROW(j2 = json::from_msgpack(packed));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": std::ifstream");
                // parse JSON file
                std::ifstream f_json(filename);
                const json j1 = json::parse(f_json);

                // parse MessagePack file
                std::ifstream f_msgpack(filename + ".msgpack", std::ios::binary);
                json j2;
                CHECK_NOTHROW(j2 = json::from_msgpack(f_msgpack));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": uint8_t* and size");
                // parse JSON file
                std::ifstream f_json(filename);
                const json j1 = json::parse(f_json);

                // parse MessagePack file
                auto packed = utils::read_binary_file(filename + ".msgpack");
                json j2;
                CHECK_NOTHROW(j2 = json::from_msgpack({packed.data(), packed.size()}));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": output to output adapters");
                // parse JSON file
                std::ifstream f_json(filename);
                json const j1 = json::parse(f_json);

                // parse MessagePack file
                auto packed = utils::read_binary_file(filename + ".msgpack");

                if (exclude_packed.count(filename) == 0u)
                {
                    {
                        INFO_WITH_TEMP(filename + ": output adapters: std::vector<uint8_t>");
                        std::vector<uint8_t> vec;
                        json::to_msgpack(j1, vec);
                        CHECK(vec == packed);
                    }
                }
            }
        }
    }
}

#ifdef JSON_HAS_CPP_17
// Test suite for verifying MessagePack handling with std::byte input
TEST_CASE("MessagePack with std::byte")
{

    SECTION("std::byte compatibility")
    {
        SECTION("vector roundtrip")
        {
            json original =
            {
                {"name", "test"},
                {"value", 42},
                {"array", {1, 2, 3}}
            };

            std::vector<uint8_t> temp = json::to_msgpack(original);
            // Convert the uint8_t vector to std::byte vector
            std::vector<std::byte> msgpack_data(temp.size());
            for (size_t i = 0; i < temp.size(); ++i)
            {
                msgpack_data[i] = std::byte(temp[i]);
            }
            // Deserialize from std::byte vector back to JSON
            json from_bytes;
            CHECK_NOTHROW(from_bytes = json::from_msgpack(msgpack_data));

            CHECK(from_bytes == original);
        }

        SECTION("empty vector")
        {
            const std::vector<std::byte> empty_data;
            CHECK_THROWS_WITH_AS([&]()
            {
                [[maybe_unused]] auto result = json::from_msgpack(empty_data);
                return true;
            }
            (),
            "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing MessagePack value: unexpected end of input",
            json::parse_error&);
        }

        SECTION("comparison with workaround")
        {
            json original =
            {
                {"string", "hello"},
                {"integer", 42},
                {"float", 3.14},
                {"boolean", true},
                {"null", nullptr},
                {"array", {1, 2, 3}},
                {"object", {{"key", "value"}}}
            };

            std::vector<uint8_t> temp = json::to_msgpack(original);

            std::vector<std::byte> msgpack_data(temp.size());
            for (size_t i = 0; i < temp.size(); ++i)
            {
                msgpack_data[i] = std::byte(temp[i]);
            }
            // Attempt direct deserialization using std::byte input
            const json direct_result = json::from_msgpack(msgpack_data);

            // Test the workaround approach: reinterpret as unsigned char* and use iterator range
            const auto* const char_start = reinterpret_cast<unsigned char const*>(msgpack_data.data());
            const auto* const char_end = char_start + msgpack_data.size();
            json workaround_result = json::from_msgpack(char_start, char_end);

            // Verify that the final deserialized JSON matches the original JSON
            CHECK(direct_result == workaround_result);
            CHECK(direct_result == original);
        }
    }
}
#endif
