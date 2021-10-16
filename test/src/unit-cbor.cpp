/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.4
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <test_data.hpp>
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

TEST_CASE("CBOR")
{
    SECTION("individual values")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            json j = json::value_t::discarded;
            const auto result = json::to_cbor(j);
            CHECK(result.empty());
        }

        SECTION("NaN")
        {
            // NaN value
            json j = std::numeric_limits<json::number_float_t>::quiet_NaN();
            std::vector<uint8_t> expected = {0xf9, 0x7e, 0x00};
            const auto result = json::to_cbor(j);
            CHECK(result == expected);
        }

        SECTION("Infinity")
        {
            // Infinity value
            json j = std::numeric_limits<json::number_float_t>::infinity();
            std::vector<uint8_t> expected = {0xf9, 0x7c, 0x00};
            const auto result = json::to_cbor(j);
            CHECK(result == expected);
        }

        SECTION("null")
        {
            json j = nullptr;
            std::vector<uint8_t> expected = {0xf6};
            const auto result = json::to_cbor(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_cbor(result) == j);
            CHECK(json::from_cbor(result, true, false) == j);
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json j = true;
                std::vector<uint8_t> expected = {0xf5};
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("false")
            {
                json j = false;
                std::vector<uint8_t> expected = {0xf4};
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }
        }

        SECTION("number")
        {
            SECTION("signed")
            {
                SECTION("-9223372036854775808..-4294967297")
                {
                    std::vector<int64_t> numbers;
                    numbers.push_back(INT64_MIN);
                    numbers.push_back(-1000000000000000000);
                    numbers.push_back(-100000000000000000);
                    numbers.push_back(-10000000000000000);
                    numbers.push_back(-1000000000000000);
                    numbers.push_back(-100000000000000);
                    numbers.push_back(-10000000000000);
                    numbers.push_back(-1000000000000);
                    numbers.push_back(-100000000000);
                    numbers.push_back(-10000000000);
                    numbers.push_back(-4294967297);
                    for (auto i : numbers)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(0x3b));
                        auto positive = static_cast<uint64_t>(-1 - i);
                        expected.push_back(static_cast<uint8_t>((positive >> 56) & 0xff));
                        expected.push_back(static_cast<uint8_t>((positive >> 48) & 0xff));
                        expected.push_back(static_cast<uint8_t>((positive >> 40) & 0xff));
                        expected.push_back(static_cast<uint8_t>((positive >> 32) & 0xff));
                        expected.push_back(static_cast<uint8_t>((positive >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((positive >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((positive >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(positive & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0x3b);
                        uint64_t restored = (static_cast<uint64_t>(result[1]) << 070) +
                                            (static_cast<uint64_t>(result[2]) << 060) +
                                            (static_cast<uint64_t>(result[3]) << 050) +
                                            (static_cast<uint64_t>(result[4]) << 040) +
                                            (static_cast<uint64_t>(result[5]) << 030) +
                                            (static_cast<uint64_t>(result[6]) << 020) +
                                            (static_cast<uint64_t>(result[7]) << 010) +
                                            static_cast<uint64_t>(result[8]);
                        CHECK(restored == positive);
                        CHECK(-1 - static_cast<int64_t>(restored) == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("-4294967296..-65537")
                {
                    std::vector<int64_t> numbers;
                    numbers.push_back(-65537);
                    numbers.push_back(-100000);
                    numbers.push_back(-1000000);
                    numbers.push_back(-10000000);
                    numbers.push_back(-100000000);
                    numbers.push_back(-1000000000);
                    numbers.push_back(-4294967296);
                    for (auto i : numbers)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(0x3a));
                        auto positive = static_cast<uint32_t>(static_cast<uint64_t>(-1 - i) & 0x00000000ffffffff);
                        expected.push_back(static_cast<uint8_t>((positive >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((positive >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((positive >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(positive & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0x3a);
                        uint32_t restored = (static_cast<uint32_t>(result[1]) << 030) +
                                            (static_cast<uint32_t>(result[2]) << 020) +
                                            (static_cast<uint32_t>(result[3]) << 010) +
                                            static_cast<uint32_t>(result[4]);
                        CHECK(restored == positive);
                        CHECK(-1LL - restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("-65536..-257")
                {
                    for (int32_t i = -65536; i <= -257; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(0x39));
                        auto positive = static_cast<uint16_t>(-1 - i);
                        expected.push_back(static_cast<uint8_t>((positive >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(positive & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0x39);
                        auto restored = static_cast<uint16_t>(static_cast<uint8_t>(result[1]) * 256 + static_cast<uint8_t>(result[2]));
                        CHECK(restored == positive);
                        CHECK(-1 - restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("-9263 (int 16)")
                {
                    json j = -9263;
                    std::vector<uint8_t> expected = {0x39, 0x24, 0x2e};

                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);

                    auto restored = static_cast<int16_t>(-1 - ((result[1] << 8) + result[2]));
                    CHECK(restored == -9263);

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
                }

                SECTION("-256..-24")
                {
                    for (auto i = -256; i < -24; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0x38);
                        expected.push_back(static_cast<uint8_t>(-1 - i));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 0x38);
                        CHECK(static_cast<int16_t>(-1 - result[1]) == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("-24..-1")
                {
                    for (auto i = -24; i <= -1; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(0x20 - 1 - static_cast<uint8_t>(i)));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 1);

                        // check individual bytes
                        CHECK(static_cast<int8_t>(0x20 - 1 - result[0]) == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("0..23")
                {
                    for (size_t i = 0; i <= 23; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 1);

                        // check individual bytes
                        CHECK(result[0] == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("24..255")
                {
                    for (size_t i = 24; i <= 255; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(0x18));
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 0x18);
                        CHECK(result[1] == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("256..65535")
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
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(0x19));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0x19);
                        auto restored = static_cast<uint16_t>(static_cast<uint8_t>(result[1]) * 256 + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("65536..4294967295")
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
                        std::vector<uint8_t> expected;
                        expected.push_back(0x1a);
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0x1a);
                        uint32_t restored = (static_cast<uint32_t>(result[1]) << 030) +
                                            (static_cast<uint32_t>(result[2]) << 020) +
                                            (static_cast<uint32_t>(result[3]) << 010) +
                                            static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("4294967296..4611686018427387903")
                {
                    for (uint64_t i :
                            {
                                4294967296ul, 4611686018427387903ul
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0x1b);
                        expected.push_back(static_cast<uint8_t>((i >> 070) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 060) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 050) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 040) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 030) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 020) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 010) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0x1b);
                        uint64_t restored = (static_cast<uint64_t>(result[1]) << 070) +
                                            (static_cast<uint64_t>(result[2]) << 060) +
                                            (static_cast<uint64_t>(result[3]) << 050) +
                                            (static_cast<uint64_t>(result[4]) << 040) +
                                            (static_cast<uint64_t>(result[5]) << 030) +
                                            (static_cast<uint64_t>(result[6]) << 020) +
                                            (static_cast<uint64_t>(result[7]) << 010) +
                                            static_cast<uint64_t>(result[8]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("-32768..-129 (int 16)")
                {
                    for (int16_t i = -32768; i <= int16_t(-129); ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0xd1);
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0xd1);
                        auto restored = static_cast<int16_t>((result[1] << 8) + result[2]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                    }
                }
            }

            SECTION("unsigned")
            {
                SECTION("0..23 (Integer)")
                {
                    for (size_t i = 0; i <= 23; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 1);

                        // check individual bytes
                        CHECK(result[0] == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("24..255 (one-byte uint8_t)")
                {
                    for (size_t i = 24; i <= 255; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0x18);
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 0x18);
                        auto restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("256..65535 (two-byte uint16_t)")
                {
                    for (size_t i = 256; i <= 65535; ++i)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0x19);
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0x19);
                        auto restored = static_cast<uint16_t>(static_cast<uint8_t>(result[1]) * 256 + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("65536..4294967295 (four-byte uint32_t)")
                {
                    for (uint32_t i :
                            {
                                65536u, 77777u, 1048576u
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0x1a);
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0x1a);
                        uint32_t restored = (static_cast<uint32_t>(result[1]) << 030) +
                                            (static_cast<uint32_t>(result[2]) << 020) +
                                            (static_cast<uint32_t>(result[3]) << 010) +
                                            static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }

                SECTION("4294967296..4611686018427387903 (eight-byte uint64_t)")
                {
                    for (uint64_t i :
                            {
                                4294967296ul, 4611686018427387903ul
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0x1b);
                        expected.push_back(static_cast<uint8_t>((i >> 070) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 060) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 050) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 040) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 030) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 020) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 010) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_cbor(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0x1b);
                        uint64_t restored = (static_cast<uint64_t>(result[1]) << 070) +
                                            (static_cast<uint64_t>(result[2]) << 060) +
                                            (static_cast<uint64_t>(result[3]) << 050) +
                                            (static_cast<uint64_t>(result[4]) << 040) +
                                            (static_cast<uint64_t>(result[5]) << 030) +
                                            (static_cast<uint64_t>(result[6]) << 020) +
                                            (static_cast<uint64_t>(result[7]) << 010) +
                                            static_cast<uint64_t>(result[8]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_cbor(result) == j);
                        CHECK(json::from_cbor(result, true, false) == j);
                    }
                }
            }

            SECTION("double-precision float")
            {
                SECTION("3.1415925")
                {
                    double v = 3.1415925;
                    json j = v;
                    std::vector<uint8_t> expected =
                    {
                        0xfb, 0x40, 0x09, 0x21, 0xfb, 0x3f, 0xa6, 0xde, 0xfc
                    };
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);

                    CHECK(json::from_cbor(result, true, false) == j);
                }
            }

            SECTION("single-precision float")
            {
                SECTION("0.5")
                {
                    double v = 0.5;
                    json j = v;
                    // its double-precision float binary value is
                    // {0xfb, 0x3f, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
                    // but to save memory, we can store it as single-precision float.
                    std::vector<uint8_t> expected = {0xfa, 0x3f, 0x00, 0x00, 0x00};
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }
                SECTION("0.0")
                {
                    double v = 0.0;
                    json j = v;
                    // its double-precision binary value is:
                    // {0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
                    std::vector<uint8_t> expected = {0xfa, 0x00, 0x00, 0x00, 0x00};
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }
                SECTION("-0.0")
                {
                    double v = -0.0;
                    json j = v;
                    // its double-precision binary value is:
                    // {0xfb, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
                    std::vector<uint8_t> expected = {0xfa, 0x80, 0x00, 0x00, 0x00};
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }
                SECTION("100.0")
                {
                    double v = 100.0;
                    json j = v;
                    // its double-precision binary value is:
                    // {0xfb, 0x40, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
                    std::vector<uint8_t> expected = {0xfa, 0x42, 0xc8, 0x00, 0x00};
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }
                SECTION("200.0")
                {
                    double v = 200.0;
                    json j = v;
                    // its double-precision binary value is:
                    // {0xfb, 0x40, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
                    std::vector<uint8_t> expected = {0xfa, 0x43, 0x48, 0x00, 0x00};
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }
                SECTION("3.40282e+38(max float)")
                {
                    float v = (std::numeric_limits<float>::max)();
                    json j = v;
                    std::vector<uint8_t> expected =
                    {
                        0xfa, 0x7f, 0x7f, 0xff, 0xff
                    };
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }
                SECTION("-3.40282e+38(lowest float)")
                {
                    auto v = static_cast<double>(std::numeric_limits<float>::lowest());
                    json j = v;
                    std::vector<uint8_t> expected =
                    {
                        0xfa, 0xff, 0x7f, 0xff, 0xff
                    };
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }
                SECTION("1 + 3.40282e+38(more than max float)")
                {
                    double v = static_cast<double>((std::numeric_limits<float>::max)()) + 0.1e+34;
                    json j = v;
                    std::vector<uint8_t> expected =
                    {
                        0xfb, 0x47, 0xf0, 0x00, 0x03, 0x04, 0xdc, 0x64, 0x49
                    };
                    // double
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }
                SECTION("-1 - 3.40282e+38(less than lowest float)")
                {
                    double v = static_cast<double>(std::numeric_limits<float>::lowest()) - 1.0;
                    json j = v;
                    std::vector<uint8_t> expected =
                    {
                        0xfa, 0xff, 0x7f, 0xff, 0xff
                    };
                    // the same with lowest float
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result) == v);
                }

            }

            SECTION("half-precision float (edge cases)")
            {
                SECTION("errors")
                {
                    SECTION("no byte follows")
                    {
                        json _;
                        CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0xf9})), json::parse_error&);
                        CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0xf9})),
                                          "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR number: unexpected end of input");
                        CHECK(json::from_cbor(std::vector<uint8_t>({0xf9}), true, false).is_discarded());
                    }
                    SECTION("only one byte follows")
                    {
                        json _;
                        CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0xf9, 0x7c})), json::parse_error&);
                        CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0xf9, 0x7c})),
                                          "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing CBOR number: unexpected end of input");
                        CHECK(json::from_cbor(std::vector<uint8_t>({0xf9, 0x7c}), true, false).is_discarded());
                    }
                }

                SECTION("exp = 0b00000")
                {
                    SECTION("0 (0 00000 0000000000)")
                    {
                        json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0x00, 0x00}));
                        json::number_float_t d{j};
                        CHECK(d == 0.0);
                    }

                    SECTION("-0 (1 00000 0000000000)")
                    {
                        json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0x80, 0x00}));
                        json::number_float_t d{j};
                        CHECK(d == -0.0);
                    }

                    SECTION("2**-24 (0 00000 0000000001)")
                    {
                        json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0x00, 0x01}));
                        json::number_float_t d{j};
                        CHECK(d == std::pow(2.0, -24.0));
                    }
                }

                SECTION("exp = 0b11111")
                {
                    SECTION("infinity (0 11111 0000000000)")
                    {
                        json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0x7c, 0x00}));
                        json::number_float_t d{j};
                        CHECK(d == std::numeric_limits<json::number_float_t>::infinity());
                        CHECK(j.dump() == "null");
                    }

                    SECTION("-infinity (1 11111 0000000000)")
                    {
                        json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0xfc, 0x00}));
                        json::number_float_t d{j};
                        CHECK(d == -std::numeric_limits<json::number_float_t>::infinity());
                        CHECK(j.dump() == "null");
                    }
                }

                SECTION("other values from https://en.wikipedia.org/wiki/Half-precision_floating-point_format")
                {
                    SECTION("1 (0 01111 0000000000)")
                    {
                        json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0x3c, 0x00}));
                        json::number_float_t d{j};
                        CHECK(d == 1);
                    }

                    SECTION("-2 (1 10000 0000000000)")
                    {
                        json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0xc0, 0x00}));
                        json::number_float_t d{j};
                        CHECK(d == -2);
                    }

                    SECTION("65504 (0 11110 1111111111)")
                    {
                        json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0x7b, 0xff}));
                        json::number_float_t d{j};
                        CHECK(d == 65504);
                    }
                }

                SECTION("infinity")
                {
                    json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0x7c, 0x00}));
                    json::number_float_t d{j};
                    CHECK(!std::isfinite(d));
                    CHECK(j.dump() == "null");
                }

                SECTION("NaN")
                {
                    json j = json::from_cbor(std::vector<uint8_t>({0xf9, 0x7e, 0x00}));
                    json::number_float_t d{j};
                    CHECK(std::isnan(d));
                    CHECK(j.dump() == "null");
                }
            }
        }

        SECTION("string")
        {
            SECTION("N = 0..23")
            {
                for (size_t N = 0; N <= 0x17; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json j = s;

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    expected.push_back(static_cast<uint8_t>(0x60 + N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back('x');
                    }

                    // compare result + size
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 1);
                    // check that no null byte is appended
                    if (N > 0)
                    {
                        CHECK(result.back() != '\x00');
                    }

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
                }
            }

            SECTION("N = 24..255")
            {
                for (size_t N = 24; N <= 255; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json j = s;

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    expected.push_back(0x78);
                    expected.push_back(static_cast<uint8_t>(N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back('x');
                    }

                    // compare result + size
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 2);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
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
                    json j = s;

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), 0x79);

                    // compare result + size
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 3);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
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
                    json j = s;

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 16) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 24) & 0xff));
                    expected.insert(expected.begin(), 0x7a);

                    // compare result + size
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 5);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
                }
            }
        }

        SECTION("array")
        {
            SECTION("empty")
            {
                json j = json::array();
                std::vector<uint8_t> expected = {0x80};
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("[null]")
            {
                json j = {nullptr};
                std::vector<uint8_t> expected = {0x81, 0xf6};
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("[1,2,3,4,5]")
            {
                json j = json::parse("[1,2,3,4,5]");
                std::vector<uint8_t> expected = {0x85, 0x01, 0x02, 0x03, 0x04, 0x05};
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("[[[[]]]]")
            {
                json j = json::parse("[[[[]]]]");
                std::vector<uint8_t> expected = {0x81, 0x81, 0x81, 0x80};
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("array with uint16_t elements")
            {
                json j(257, nullptr);
                std::vector<uint8_t> expected(j.size() + 3, 0xf6); // all null
                expected[0] = 0x99; // array 16 bit
                expected[1] = 0x01; // size (0x0101), byte 0
                expected[2] = 0x01; // size (0x0101), byte 1
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("array with uint32_t elements")
            {
                json j(65793, nullptr);
                std::vector<uint8_t> expected(j.size() + 5, 0xf6); // all null
                expected[0] = 0x9a; // array 32 bit
                expected[1] = 0x00; // size (0x00010101), byte 0
                expected[2] = 0x01; // size (0x00010101), byte 1
                expected[3] = 0x01; // size (0x00010101), byte 2
                expected[4] = 0x01; // size (0x00010101), byte 3
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }
        }

        SECTION("object")
        {
            SECTION("empty")
            {
                json j = json::object();
                std::vector<uint8_t> expected = {0xa0};
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("{\"\":null}")
            {
                json j = {{"", nullptr}};
                std::vector<uint8_t> expected = {0xa1, 0x60, 0xf6};
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("{\"a\": {\"b\": {\"c\": {}}}}")
            {
                json j = json::parse(R"({"a": {"b": {"c": {}}}})");
                std::vector<uint8_t> expected =
                {
                    0xa1, 0x61, 0x61, 0xa1, 0x61, 0x62, 0xa1, 0x61, 0x63, 0xa0
                };
                const auto result = json::to_cbor(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("object with uint8_t elements")
            {
                json j;
                for (auto i = 0; i < 255; ++i)
                {
                    // format i to a fixed width of 5
                    // each entry will need 7 bytes: 6 for string, 1 for null
                    std::stringstream ss;
                    ss << std::setw(5) << std::setfill('0') << i;
                    j.emplace(ss.str(), nullptr);
                }

                const auto result = json::to_cbor(j);

                // Checking against an expected vector byte by byte is
                // difficult, because no assumption on the order of key/value
                // pairs are made. We therefore only check the prefix (type and
                // size and the overall size. The rest is then handled in the
                // roundtrip check.
                CHECK(result.size() == 1787); // 1 type, 1 size, 255*7 content
                CHECK(result[0] == 0xb8); // map 8 bit
                CHECK(result[1] == 0xff); // size byte (0xff)
                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("object with uint16_t elements")
            {
                json j;
                for (auto i = 0; i < 256; ++i)
                {
                    // format i to a fixed width of 5
                    // each entry will need 7 bytes: 6 for string, 1 for null
                    std::stringstream ss;
                    ss << std::setw(5) << std::setfill('0') << i;
                    j.emplace(ss.str(), nullptr);
                }

                const auto result = json::to_cbor(j);

                // Checking against an expected vector byte by byte is
                // difficult, because no assumption on the order of key/value
                // pairs are made. We therefore only check the prefix (type and
                // size and the overall size. The rest is then handled in the
                // roundtrip check.
                CHECK(result.size() == 1795); // 1 type, 2 size, 256*7 content
                CHECK(result[0] == 0xb9); // map 16 bit
                CHECK(result[1] == 0x01); // byte 0 of size (0x0100)
                CHECK(result[2] == 0x00); // byte 1 of size (0x0100)

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }

            SECTION("object with uint32_t elements")
            {
                json j;
                for (auto i = 0; i < 65536; ++i)
                {
                    // format i to a fixed width of 5
                    // each entry will need 7 bytes: 6 for string, 1 for null
                    std::stringstream ss;
                    ss << std::setw(5) << std::setfill('0') << i;
                    j.emplace(ss.str(), nullptr);
                }

                const auto result = json::to_cbor(j);

                // Checking against an expected vector byte by byte is
                // difficult, because no assumption on the order of key/value
                // pairs are made. We therefore only check the prefix (type and
                // size and the overall size. The rest is then handled in the
                // roundtrip check.
                CHECK(result.size() == 458757); // 1 type, 4 size, 65536*7 content
                CHECK(result[0] == 0xba); // map 32 bit
                CHECK(result[1] == 0x00); // byte 0 of size (0x00010000)
                CHECK(result[2] == 0x01); // byte 1 of size (0x00010000)
                CHECK(result[3] == 0x00); // byte 2 of size (0x00010000)
                CHECK(result[4] == 0x00); // byte 3 of size (0x00010000)

                // roundtrip
                CHECK(json::from_cbor(result) == j);
                CHECK(json::from_cbor(result, true, false) == j);
            }
        }

        SECTION("binary")
        {
            SECTION("N = 0..23")
            {
                for (size_t N = 0; N <= 0x17; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with byte array containing of N * 'x'
                    const auto s = std::vector<uint8_t>(N, 'x');
                    json j = json::binary(s);

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    expected.push_back(static_cast<uint8_t>(0x40 + N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back(0x78);
                    }

                    // compare result + size
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 1);
                    // check that no null byte is appended
                    if (N > 0)
                    {
                        CHECK(result.back() != '\x00');
                    }

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
                }
            }

            SECTION("N = 24..255")
            {
                for (size_t N = 24; N <= 255; ++N)
                {
                    CAPTURE(N)

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::vector<uint8_t>(N, 'x');
                    json j = json::binary(s);

                    // create expected byte vector
                    std::vector<uint8_t> expected;
                    expected.push_back(0x58);
                    expected.push_back(static_cast<uint8_t>(N));
                    for (size_t i = 0; i < N; ++i)
                    {
                        expected.push_back('x');
                    }

                    // compare result + size
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 2);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
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
                    const auto s = std::vector<uint8_t>(N, 'x');
                    json j = json::binary(s);

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), 0x59);

                    // compare result + size
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 3);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
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
                    const auto s = std::vector<uint8_t>(N, 'x');
                    json j = json::binary(s);

                    // create expected byte vector (hack: create string first)
                    std::vector<uint8_t> expected(N, 'x');
                    // reverse order of commands, because we insert at begin()
                    expected.insert(expected.begin(), static_cast<uint8_t>(N & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 8) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 16) & 0xff));
                    expected.insert(expected.begin(), static_cast<uint8_t>((N >> 24) & 0xff));
                    expected.insert(expected.begin(), 0x5a);

                    // compare result + size
                    const auto result = json::to_cbor(j);
                    CHECK(result == expected);
                    CHECK(result.size() == N + 5);
                    // check that no null byte is appended
                    CHECK(result.back() != '\x00');

                    // roundtrip
                    CHECK(json::from_cbor(result) == j);
                    CHECK(json::from_cbor(result, true, false) == j);
                }
            }

            SECTION("indefinite size")
            {
                std::vector<std::uint8_t> input = {0x5F, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0x43, 0xee, 0xff, 0x99, 0xFF};
                auto j = json::from_cbor(input);
                CHECK(j.is_binary());
                auto k = json::binary({0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99});
                CAPTURE(j.dump(0, ' ', false, json::error_handler_t::strict))
                CHECK(j == k);
            }

            SECTION("binary in array")
            {
                // array with three empty byte strings
                std::vector<std::uint8_t> input = {0x83, 0x40, 0x40, 0x40};
                json _;
                CHECK_NOTHROW(_ = json::from_cbor(input));
            }

            SECTION("binary in object")
            {
                // object mapping "foo" to empty byte string
                std::vector<std::uint8_t> input = {0xA1, 0x63, 0x66, 0x6F, 0x6F, 0x40};
                json _;
                CHECK_NOTHROW(_ = json::from_cbor(input));
            }

            SECTION("SAX callback with binary")
            {
                // object mapping "foo" to byte string
                std::vector<std::uint8_t> input = {0xA1, 0x63, 0x66, 0x6F, 0x6F, 0x41, 0x00};

                // callback to set binary_seen to true if a binary value was seen
                bool binary_seen = false;
                auto callback = [&binary_seen](int /*depth*/, json::parse_event_t /*event*/, json & parsed)
                {
                    if (parsed.is_binary())
                    {
                        binary_seen = true;
                    }
                    return true;
                };

                json j;
                auto cbp = nlohmann::detail::json_sax_dom_callback_parser<json>(j, callback, true);
                CHECK(json::sax_parse(input, &cbp, json::input_format_t::cbor));
                CHECK(j.at("foo").is_binary());
                CHECK(binary_seen);
            }
        }
    }

    SECTION("additional deserialization")
    {
        SECTION("0x5b (byte array)")
        {
            std::vector<uint8_t> given = {0x5b, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01, 0x61
                                         };
            json j = json::from_cbor(given);
            CHECK(j == json::binary(std::vector<uint8_t> {'a'}));
        }

        SECTION("0x7b (string)")
        {
            std::vector<uint8_t> given = {0x7b, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01, 0x61
                                         };
            json j = json::from_cbor(given);
            CHECK(j == "a");
        }

        SECTION("0x9b (array)")
        {
            std::vector<uint8_t> given = {0x9b, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01, 0xf4
                                         };
            json j = json::from_cbor(given);
            CHECK(j == json::parse("[false]"));
        }

        SECTION("0xbb (map)")
        {
            std::vector<uint8_t> given = {0xbb, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01, 0x60, 0xf4
                                         };
            json j = json::from_cbor(given);
            CHECK(j == json::parse("{\"\": false}"));
        }
    }

    SECTION("errors")
    {
        SECTION("empty byte vector")
        {
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>()), json::parse_error&);
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>()),
                              "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing CBOR value: unexpected end of input");
            CHECK(json::from_cbor(std::vector<uint8_t>(), true, false).is_discarded());
        }

        SECTION("too short byte vector")
        {
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x18})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x19})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x19, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1a})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1a, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1a, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1a, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1b})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x62})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x62, 0x60})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x7F})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x7F, 0x60})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x82, 0x01})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x9F, 0x01})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0xBF, 0x61, 0x61, 0xF5})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0xA1, 0x61, 0X61})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0xBF, 0x61, 0X61})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x5F})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x5F, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x41})), json::parse_error&);

            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x18})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x19})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x19, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1a})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1a, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1a, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1a, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1b})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 6: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 7: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 9: syntax error while parsing CBOR number: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x62})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR string: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x62, 0x60})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing CBOR string: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x7F})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR string: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x7F, 0x60})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing CBOR string: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x82, 0x01})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing CBOR value: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x9F, 0x01})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing CBOR value: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0xBF, 0x61, 0x61, 0xF5})),
                              "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing CBOR string: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0xA1, 0x61, 0x61})),
                              "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing CBOR value: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0xBF, 0x61, 0x61})),
                              "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing CBOR value: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x5F})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR binary: unexpected end of input");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x5F, 0x00})),
                              "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing CBOR binary: expected length specification (0x40-0x5B) or indefinite binary array type (0x5F); last byte: 0x00");
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x41})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR binary: unexpected end of input");

            CHECK(json::from_cbor(std::vector<uint8_t>({0x18}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x19}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x19, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1a}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1a, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1a, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1a, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1b}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1b, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x62}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x62, 0x60}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x7F}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x7F, 0x60}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x82, 0x01}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x9F, 0x01}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0xBF, 0x61, 0x61, 0xF5}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0xA1, 0x61, 0x61}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0xBF, 0x61, 0x61}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x5F}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x5F, 0x00}), true, false).is_discarded());
            CHECK(json::from_cbor(std::vector<uint8_t>({0x41}), true, false).is_discarded());
        }

        SECTION("unsupported bytes")
        {
            SECTION("concrete examples")
            {
                json _;
                CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0x1c})), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0x1c})),
                                  "[json.exception.parse_error.112] parse error at byte 1: syntax error while parsing CBOR value: invalid byte: 0x1C");
                CHECK(json::from_cbor(std::vector<uint8_t>({0x1c}), true, false).is_discarded());

                CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0xf8})), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0xf8})),
                                  "[json.exception.parse_error.112] parse error at byte 1: syntax error while parsing CBOR value: invalid byte: 0xF8");
                CHECK(json::from_cbor(std::vector<uint8_t>({0xf8}), true, false).is_discarded());
            }

            SECTION("all unsupported bytes")
            {
                for (auto byte :
                        {
                            // ?
                            0x1c, 0x1d, 0x1e, 0x1f,
                            // ?
                            0x3c, 0x3d, 0x3e, 0x3f,
                            // ?
                            0x5c, 0x5d, 0x5e,
                            // ?
                            0x7c, 0x7d, 0x7e,
                            // ?
                            0x9c, 0x9d, 0x9e,
                            // ?
                            0xbc, 0xbd, 0xbe,
                            // date/time
                            0xc0, 0xc1,
                            // bignum
                            0xc2, 0xc3,
                            // fraction
                            0xc4,
                            // bigfloat
                            0xc5,
                            // tagged item
                            0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
                            // expected conversion
                            0xd5, 0xd6, 0xd7,
                            // more tagged items
                            0xd8, 0xd9, 0xda, 0xdb,
                            // ?
                            0xdc, 0xdd, 0xde, 0xdf,
                            // (simple value)
                            0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3,
                            // undefined
                            0xf7,
                            // simple value
                            0xf8
                        })
                {
                    json _;
                    CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({static_cast<uint8_t>(byte)})), json::parse_error&);
                    CHECK(json::from_cbor(std::vector<uint8_t>({static_cast<uint8_t>(byte)}), true, false).is_discarded());
                }
            }
        }

        SECTION("invalid string in map")
        {
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(std::vector<uint8_t>({0xa1, 0xff, 0x01})), json::parse_error&);
            CHECK_THROWS_WITH(_ = json::from_cbor(std::vector<uint8_t>({0xa1, 0xff, 0x01})),
                              "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing CBOR string: expected length specification (0x60-0x7B) or indefinite string type (0x7F); last byte: 0xFF");
            CHECK(json::from_cbor(std::vector<uint8_t>({0xa1, 0xff, 0x01}), true, false).is_discarded());
        }

        SECTION("strict mode")
        {
            std::vector<uint8_t> vec = {0xf6, 0xf6};
            SECTION("non-strict mode")
            {
                const auto result = json::from_cbor(vec, false);
                CHECK(result == json());
                CHECK(!json::from_cbor(vec, false, false).is_discarded());
            }

            SECTION("strict mode")
            {
                json _;
                CHECK_THROWS_AS(_ = json::from_cbor(vec), json::parse_error&);
                CHECK_THROWS_WITH(_ = json::from_cbor(vec),
                                  "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR value: expected end of input; last byte: 0xF6");
                CHECK(json::from_cbor(vec, true, false).is_discarded());
            }
        }
    }

    SECTION("SAX aborts")
    {
        SECTION("start_array(len)")
        {
            std::vector<uint8_t> v = {0x83, 0x01, 0x02, 0x03};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::cbor));
        }

        SECTION("start_object(len)")
        {
            std::vector<uint8_t> v = {0xA1, 0x63, 0x66, 0x6F, 0x6F, 0xF4};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::cbor));
        }

        SECTION("key()")
        {
            std::vector<uint8_t> v = {0xA1, 0x63, 0x66, 0x6F, 0x6F, 0xF4};
            SaxCountdown scp(1);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::cbor));
        }
    }
}

// use this testcase outside [hide] to run it with Valgrind
TEST_CASE("single CBOR roundtrip")
{
    SECTION("sample.json")
    {
        std::string filename = TEST_DATA_DIRECTORY "/json_testsuite/sample.json";

        // parse JSON file
        std::ifstream f_json(filename);
        json j1 = json::parse(f_json);

        // parse CBOR file
        auto packed = utils::read_binary_file(filename + ".cbor");
        json j2;
        CHECK_NOTHROW(j2 = json::from_cbor(packed));

        // compare parsed JSON values
        CHECK(j1 == j2);

        SECTION("roundtrips")
        {
            SECTION("std::ostringstream")
            {
                std::basic_ostringstream<std::uint8_t> ss;
                json::to_cbor(j1, ss);
                json j3 = json::from_cbor(ss.str());
                CHECK(j1 == j3);
            }

            SECTION("std::string")
            {
                std::string s;
                json::to_cbor(j1, s);
                json j3 = json::from_cbor(s);
                CHECK(j1 == j3);
            }
        }

        // check with different start index
        packed.insert(packed.begin(), 5, 0xff);
        CHECK(j1 == json::from_cbor(packed.begin() + 5, packed.end()));
    }
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("CBOR regressions")
{
    SECTION("fuzz test results")
    {
        /*
        The following test cases were found during a two-day session with
        AFL-Fuzz. As a result, empty byte vectors and excessive lengths are
        detected.
        */
        for (std::string filename :
                {
                    TEST_DATA_DIRECTORY "/cbor_regression/test01",
                    TEST_DATA_DIRECTORY "/cbor_regression/test02",
                    TEST_DATA_DIRECTORY "/cbor_regression/test03",
                    TEST_DATA_DIRECTORY "/cbor_regression/test04",
                    TEST_DATA_DIRECTORY "/cbor_regression/test05",
                    TEST_DATA_DIRECTORY "/cbor_regression/test06",
                    TEST_DATA_DIRECTORY "/cbor_regression/test07",
                    TEST_DATA_DIRECTORY "/cbor_regression/test08",
                    TEST_DATA_DIRECTORY "/cbor_regression/test09",
                    TEST_DATA_DIRECTORY "/cbor_regression/test10",
                    TEST_DATA_DIRECTORY "/cbor_regression/test11",
                    TEST_DATA_DIRECTORY "/cbor_regression/test12",
                    TEST_DATA_DIRECTORY "/cbor_regression/test13",
                    TEST_DATA_DIRECTORY "/cbor_regression/test14",
                    TEST_DATA_DIRECTORY "/cbor_regression/test15",
                    TEST_DATA_DIRECTORY "/cbor_regression/test16",
                    TEST_DATA_DIRECTORY "/cbor_regression/test17",
                    TEST_DATA_DIRECTORY "/cbor_regression/test18",
                    TEST_DATA_DIRECTORY "/cbor_regression/test19",
                    TEST_DATA_DIRECTORY "/cbor_regression/test20",
                    TEST_DATA_DIRECTORY "/cbor_regression/test21"
                })
        {
            CAPTURE(filename)

            try
            {
                // parse CBOR file
                auto vec1 = utils::read_binary_file(filename);
                json j1 = json::from_cbor(vec1);

                try
                {
                    // step 2: round trip
                    std::vector<uint8_t> vec2 = json::to_cbor(j1);

                    // parse serialization
                    json j2 = json::from_cbor(vec2);

                    // deserializations must match
                    CHECK(j1 == j2);
                }
                catch (const json::parse_error&)
                {
                    // parsing a CBOR serialization must not fail
                    CHECK(false);
                }
            }
            catch (const json::parse_error&)
            {
                // parse errors are ok, because input may be random bytes
            }
        }
    }
}
#endif

TEST_CASE("CBOR roundtrips" * doctest::skip())
{
    SECTION("input from flynn")
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
        exclude_packed.insert(TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_duplicated_key.json");
        exclude_packed.insert(TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_object_long_strings.json");

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
                json j1 = json::parse(f_json);

                // parse CBOR file
                auto packed = utils::read_binary_file(filename + ".cbor");
                json j2;
                CHECK_NOTHROW(j2 = json::from_cbor(packed));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": std::ifstream");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse CBOR file
                std::ifstream f_cbor(filename + ".cbor", std::ios::binary);
                json j2;
                CHECK_NOTHROW(j2 = json::from_cbor(f_cbor));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": uint8_t* and size");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse CBOR file
                auto packed = utils::read_binary_file(filename + ".cbor");
                json j2;
                CHECK_NOTHROW(j2 = json::from_cbor({packed.data(), packed.size()}));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": output to output adapters");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse CBOR file
                auto packed = utils::read_binary_file(filename + ".cbor");

                if (exclude_packed.count(filename) == 0u)
                {
                    {
                        INFO_WITH_TEMP(filename + ": output adapters: std::vector<uint8_t>");
                        std::vector<uint8_t> vec;
                        json::to_cbor(j1, vec);
                        CHECK(vec == packed);
                    }
                }
            }
        }
    }
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("all CBOR first bytes")
{
    // these bytes will fail immediately with exception parse_error.112
    std::set<uint8_t> unsupported =
    {
        //// types not supported by this library

        // date/time
        0xc0, 0xc1,
        // bignum
        0xc2, 0xc3,
        // decimal fracion
        0xc4,
        // bigfloat
        0xc5,
        // tagged item
        0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
        0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd8,
        0xd9, 0xda, 0xdb,
        // expected conversion
        0xd5, 0xd6, 0xd7,
        // simple value
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xef, 0xf0,
        0xf1, 0xf2, 0xf3,
        0xf8,
        // undefined
        0xf7,

        //// bytes not specified by CBOR

        0x1c, 0x1d, 0x1e, 0x1f,
        0x3c, 0x3d, 0x3e, 0x3f,
        0x5c, 0x5d, 0x5e,
        0x7c, 0x7d, 0x7e,
        0x9c, 0x9d, 0x9e,
        0xbc, 0xbd, 0xbe,
        0xdc, 0xdd, 0xde, 0xdf,
        0xee,
        0xfc, 0xfe, 0xfd,

        /// break cannot be the first byte

        0xff
    };

    for (auto i = 0; i < 256; ++i)
    {
        const auto byte = static_cast<uint8_t>(i);

        try
        {
            auto res = json::from_cbor(std::vector<uint8_t>(1, byte));
        }
        catch (const json::parse_error& e)
        {
            // check that parse_error.112 is only thrown if the
            // first byte is in the unsupported set
            INFO_WITH_TEMP(e.what());
            if (unsupported.find(byte) != unsupported.end())
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

TEST_CASE("examples from RFC 7049 Appendix A")
{
    SECTION("numbers")
    {
        CHECK(json::to_cbor(json::parse("0")) == std::vector<uint8_t>({0x00}));
        CHECK(json::parse("0") == json::from_cbor(std::vector<uint8_t>({0x00})));

        CHECK(json::to_cbor(json::parse("1")) == std::vector<uint8_t>({0x01}));
        CHECK(json::parse("1") == json::from_cbor(std::vector<uint8_t>({0x01})));

        CHECK(json::to_cbor(json::parse("10")) == std::vector<uint8_t>({0x0a}));
        CHECK(json::parse("10") == json::from_cbor(std::vector<uint8_t>({0x0a})));

        CHECK(json::to_cbor(json::parse("23")) == std::vector<uint8_t>({0x17}));
        CHECK(json::parse("23") == json::from_cbor(std::vector<uint8_t>({0x17})));

        CHECK(json::to_cbor(json::parse("24")) == std::vector<uint8_t>({0x18, 0x18}));
        CHECK(json::parse("24") == json::from_cbor(std::vector<uint8_t>({0x18, 0x18})));

        CHECK(json::to_cbor(json::parse("25")) == std::vector<uint8_t>({0x18, 0x19}));
        CHECK(json::parse("25") == json::from_cbor(std::vector<uint8_t>({0x18, 0x19})));

        CHECK(json::to_cbor(json::parse("100")) == std::vector<uint8_t>({0x18, 0x64}));
        CHECK(json::parse("100") == json::from_cbor(std::vector<uint8_t>({0x18, 0x64})));

        CHECK(json::to_cbor(json::parse("1000")) == std::vector<uint8_t>({0x19, 0x03, 0xe8}));
        CHECK(json::parse("1000") == json::from_cbor(std::vector<uint8_t>({0x19, 0x03, 0xe8})));

        CHECK(json::to_cbor(json::parse("1000000")) == std::vector<uint8_t>({0x1a, 0x00, 0x0f, 0x42, 0x40}));
        CHECK(json::parse("1000000") == json::from_cbor(std::vector<uint8_t>({0x1a, 0x00, 0x0f, 0x42, 0x40})));

        CHECK(json::to_cbor(json::parse("1000000000000")) == std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}));
        CHECK(json::parse("1000000000000") == json::from_cbor(std::vector<uint8_t>({0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00})));

        CHECK(json::to_cbor(json::parse("18446744073709551615")) == std::vector<uint8_t>({0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));
        CHECK(json::parse("18446744073709551615") == json::from_cbor(std::vector<uint8_t>({0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})));

        // positive bignum is not supported
        //CHECK(json::to_cbor(json::parse("18446744073709551616")) == std::vector<uint8_t>({0xc2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
        //CHECK(json::parse("18446744073709551616") == json::from_cbor(std::vector<uint8_t>({0xc2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})));

        //CHECK(json::to_cbor(json::parse("-18446744073709551616")) == std::vector<uint8_t>({0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));
        //CHECK(json::parse("-18446744073709551616") == json::from_cbor(std::vector<uint8_t>({0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})));

        // negative bignum is not supported
        //CHECK(json::to_cbor(json::parse("-18446744073709551617")) == std::vector<uint8_t>({0xc3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
        //CHECK(json::parse("-18446744073709551617") == json::from_cbor(std::vector<uint8_t>({0xc3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})));

        CHECK(json::to_cbor(json::parse("-1")) == std::vector<uint8_t>({0x20}));
        CHECK(json::parse("-1") == json::from_cbor(std::vector<uint8_t>({0x20})));

        CHECK(json::to_cbor(json::parse("-10")) == std::vector<uint8_t>({0x29}));
        CHECK(json::parse("-10") == json::from_cbor(std::vector<uint8_t>({0x29})));

        CHECK(json::to_cbor(json::parse("-100")) == std::vector<uint8_t>({0x38, 0x63}));
        CHECK(json::parse("-100") == json::from_cbor(std::vector<uint8_t>({0x38, 0x63})));

        CHECK(json::to_cbor(json::parse("-1000")) == std::vector<uint8_t>({0x39, 0x03, 0xe7}));
        CHECK(json::parse("-1000") == json::from_cbor(std::vector<uint8_t>({0x39, 0x03, 0xe7})));

        // half-precision float
        //CHECK(json::to_cbor(json::parse("0.0")) == std::vector<uint8_t>({0xf9, 0x00, 0x00}));
        CHECK(json::parse("0.0") == json::from_cbor(std::vector<uint8_t>({0xf9, 0x00, 0x00})));

        // half-precision float
        //CHECK(json::to_cbor(json::parse("-0.0")) == std::vector<uint8_t>({0xf9, 0x80, 0x00}));
        CHECK(json::parse("-0.0") == json::from_cbor(std::vector<uint8_t>({0xf9, 0x80, 0x00})));

        // half-precision float
        //CHECK(json::to_cbor(json::parse("1.0")) == std::vector<uint8_t>({0xf9, 0x3c, 0x00}));
        CHECK(json::parse("1.0") == json::from_cbor(std::vector<uint8_t>({0xf9, 0x3c, 0x00})));

        CHECK(json::to_cbor(json::parse("1.1")) == std::vector<uint8_t>({0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a}));
        CHECK(json::parse("1.1") == json::from_cbor(std::vector<uint8_t>({0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a})));

        // half-precision float
        //CHECK(json::to_cbor(json::parse("1.5")) == std::vector<uint8_t>({0xf9, 0x3e, 0x00}));
        CHECK(json::parse("1.5") == json::from_cbor(std::vector<uint8_t>({0xf9, 0x3e, 0x00})));

        // half-precision float
        //CHECK(json::to_cbor(json::parse("65504.0")) == std::vector<uint8_t>({0xf9, 0x7b, 0xff}));
        CHECK(json::parse("65504.0") == json::from_cbor(std::vector<uint8_t>({0xf9, 0x7b, 0xff})));

        //CHECK(json::to_cbor(json::parse("100000.0")) == std::vector<uint8_t>({0xfa, 0x47, 0xc3, 0x50, 0x00}));
        CHECK(json::parse("100000.0") == json::from_cbor(std::vector<uint8_t>({0xfa, 0x47, 0xc3, 0x50, 0x00})));

        //CHECK(json::to_cbor(json::parse("3.4028234663852886e+38")) == std::vector<uint8_t>({0xfa, 0x7f, 0x7f, 0xff, 0xff}));
        CHECK(json::parse("3.4028234663852886e+38") == json::from_cbor(std::vector<uint8_t>({0xfa, 0x7f, 0x7f, 0xff, 0xff})));

        CHECK(json::to_cbor(json::parse("1.0e+300")) == std::vector<uint8_t>({0xfb, 0x7e, 0x37, 0xe4, 0x3c, 0x88, 0x00, 0x75, 0x9c}));
        CHECK(json::parse("1.0e+300") == json::from_cbor(std::vector<uint8_t>({0xfb, 0x7e, 0x37, 0xe4, 0x3c, 0x88, 0x00, 0x75, 0x9c})));

        // half-precision float
        //CHECK(json::to_cbor(json::parse("5.960464477539063e-8")) == std::vector<uint8_t>({0xf9, 0x00, 0x01}));
        CHECK(json::parse("-4.0") == json::from_cbor(std::vector<uint8_t>({0xf9, 0xc4, 0x00})));

        // half-precision float
        //CHECK(json::to_cbor(json::parse("0.00006103515625")) == std::vector<uint8_t>({0xf9, 0x04, 0x00}));
        CHECK(json::parse("-4.0") == json::from_cbor(std::vector<uint8_t>({0xf9, 0xc4, 0x00})));

        // half-precision float
        //CHECK(json::to_cbor(json::parse("-4.0")) == std::vector<uint8_t>({0xf9, 0xc4, 0x00}));
        CHECK(json::parse("-4.0") == json::from_cbor(std::vector<uint8_t>({0xf9, 0xc4, 0x00})));

        CHECK(json::to_cbor(json::parse("-4.1")) == std::vector<uint8_t>({0xfb, 0xc0, 0x10, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}));
        CHECK(json::parse("-4.1") == json::from_cbor(std::vector<uint8_t>({0xfb, 0xc0, 0x10, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66})));
    }

    SECTION("simple values")
    {
        CHECK(json::to_cbor(json::parse("false")) == std::vector<uint8_t>({0xf4}));
        CHECK(json::parse("false") == json::from_cbor(std::vector<uint8_t>({0xf4})));

        CHECK(json::to_cbor(json::parse("true")) == std::vector<uint8_t>({0xf5}));
        CHECK(json::parse("true") == json::from_cbor(std::vector<uint8_t>({0xf5})));

        CHECK(json::to_cbor(json::parse("true")) == std::vector<uint8_t>({0xf5}));
        CHECK(json::parse("true") == json::from_cbor(std::vector<uint8_t>({0xf5})));
    }

    SECTION("strings")
    {
        CHECK(json::to_cbor(json::parse("\"\"")) == std::vector<uint8_t>({0x60}));
        CHECK(json::parse("\"\"") == json::from_cbor(std::vector<uint8_t>({0x60})));

        CHECK(json::to_cbor(json::parse("\"a\"")) == std::vector<uint8_t>({0x61, 0x61}));
        CHECK(json::parse("\"a\"") == json::from_cbor(std::vector<uint8_t>({0x61, 0x61})));

        CHECK(json::to_cbor(json::parse("\"IETF\"")) == std::vector<uint8_t>({0x64, 0x49, 0x45, 0x54, 0x46}));
        CHECK(json::parse("\"IETF\"") == json::from_cbor(std::vector<uint8_t>({0x64, 0x49, 0x45, 0x54, 0x46})));

        CHECK(json::to_cbor(json::parse("\"\\u00fc\"")) == std::vector<uint8_t>({0x62, 0xc3, 0xbc}));
        CHECK(json::parse("\"\\u00fc\"") == json::from_cbor(std::vector<uint8_t>({0x62, 0xc3, 0xbc})));

        CHECK(json::to_cbor(json::parse("\"\\u6c34\"")) == std::vector<uint8_t>({0x63, 0xe6, 0xb0, 0xb4}));
        CHECK(json::parse("\"\\u6c34\"") == json::from_cbor(std::vector<uint8_t>({0x63, 0xe6, 0xb0, 0xb4})));

        CHECK(json::to_cbor(json::parse("\"\\ud800\\udd51\"")) == std::vector<uint8_t>({0x64, 0xf0, 0x90, 0x85, 0x91}));
        CHECK(json::parse("\"\\ud800\\udd51\"") == json::from_cbor(std::vector<uint8_t>({0x64, 0xf0, 0x90, 0x85, 0x91})));

        // indefinite length strings
        CHECK(json::parse("\"streaming\"") == json::from_cbor(std::vector<uint8_t>({0x7f, 0x65, 0x73, 0x74, 0x72, 0x65, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x67, 0xff})));
    }

    SECTION("byte arrays")
    {
        auto packed = utils::read_binary_file(TEST_DATA_DIRECTORY "/binary_data/cbor_binary.cbor");
        json j;
        CHECK_NOTHROW(j = json::from_cbor(packed));

        auto expected = utils::read_binary_file(TEST_DATA_DIRECTORY "/binary_data/cbor_binary.out");
        CHECK(j == json::binary(expected));

        // 0xd8
        CHECK(json::to_cbor(json::binary(std::vector<uint8_t> {}, 0x42)) == std::vector<uint8_t> {0xd8, 0x42, 0x40});
        CHECK(!json::from_cbor(json::to_cbor(json::binary(std::vector<uint8_t> {}, 0x42)), true, true, json::cbor_tag_handler_t::ignore).get_binary().has_subtype());
        CHECK(json::from_cbor(json::to_cbor(json::binary(std::vector<uint8_t> {}, 0x42)), true, true, json::cbor_tag_handler_t::store).get_binary().subtype() == 0x42);
        // 0xd9
        CHECK(json::to_cbor(json::binary(std::vector<uint8_t> {}, 1000)) == std::vector<uint8_t> {0xd9, 0x03, 0xe8, 0x40});
        CHECK(!json::from_cbor(json::to_cbor(json::binary(std::vector<uint8_t> {}, 1000)), true, true, json::cbor_tag_handler_t::ignore).get_binary().has_subtype());
        CHECK(json::from_cbor(json::to_cbor(json::binary(std::vector<uint8_t> {}, 1000)), true, true, json::cbor_tag_handler_t::store).get_binary().subtype() == 1000);
        // 0xda
        CHECK(json::to_cbor(json::binary(std::vector<uint8_t> {}, 394216)) == std::vector<uint8_t> {0xda, 0x00, 0x06, 0x03, 0xe8, 0x40});
        CHECK(!json::from_cbor(json::to_cbor(json::binary(std::vector<uint8_t> {}, 394216)), true, true, json::cbor_tag_handler_t::ignore).get_binary().has_subtype());
        CHECK(json::from_cbor(json::to_cbor(json::binary(std::vector<uint8_t> {}, 394216)), true, true, json::cbor_tag_handler_t::store).get_binary().subtype() == 394216);
        // 0xdb
        CHECK(json::to_cbor(json::binary(std::vector<uint8_t> {}, 8589934590)) == std::vector<uint8_t> {0xdb, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xfe, 0x40});
        CHECK(!json::from_cbor(json::to_cbor(json::binary(std::vector<uint8_t> {}, 8589934590)), true, true, json::cbor_tag_handler_t::ignore).get_binary().has_subtype());
        CHECK(json::from_cbor(json::to_cbor(json::binary(std::vector<uint8_t> {}, 8589934590)), true, true, json::cbor_tag_handler_t::store).get_binary().subtype() == 8589934590);
    }

    SECTION("arrays")
    {
        CHECK(json::to_cbor(json::parse("[]")) == std::vector<uint8_t>({0x80}));
        CHECK(json::parse("[]") == json::from_cbor(std::vector<uint8_t>({0x80})));

        CHECK(json::to_cbor(json::parse("[1, 2, 3]")) == std::vector<uint8_t>({0x83, 0x01, 0x02, 0x03}));
        CHECK(json::parse("[1, 2, 3]") == json::from_cbor(std::vector<uint8_t>({0x83, 0x01, 0x02, 0x03})));

        CHECK(json::to_cbor(json::parse("[1, [2, 3], [4, 5]]")) == std::vector<uint8_t>({0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05}));
        CHECK(json::parse("[1, [2, 3], [4, 5]]") == json::from_cbor(std::vector<uint8_t>({0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05})));

        CHECK(json::to_cbor(json::parse("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]")) == std::vector<uint8_t>({0x98, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19}));
        CHECK(json::parse("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]") == json::from_cbor(std::vector<uint8_t>({0x98, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19})));

        // indefinite length arrays
        CHECK(json::parse("[]") == json::from_cbor(std::vector<uint8_t>({0x9f, 0xff})));
        CHECK(json::parse("[1, [2, 3], [4, 5]] ") == json::from_cbor(std::vector<uint8_t>({0x9f, 0x01, 0x82, 0x02, 0x03, 0x9f, 0x04, 0x05, 0xff, 0xff})));
        CHECK(json::parse("[1, [2, 3], [4, 5]]") == json::from_cbor(std::vector<uint8_t>({0x9f, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05, 0xff})));
        CHECK(json::parse("[1, [2, 3], [4, 5]]") == json::from_cbor(std::vector<uint8_t>({0x83, 0x01, 0x82, 0x02, 0x03, 0x9f, 0x04, 0x05, 0xff})));
        CHECK(json::parse("[1, [2, 3], [4, 5]]") == json::from_cbor(std::vector<uint8_t>({0x83, 0x01, 0x9f, 0x02, 0x03, 0xff, 0x82, 0x04, 0x05})));
        CHECK(json::parse("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]") == json::from_cbor(std::vector<uint8_t>({0x9f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19, 0xff})));
    }

    SECTION("objects")
    {
        CHECK(json::to_cbor(json::parse("{}")) == std::vector<uint8_t>({0xa0}));
        CHECK(json::parse("{}") == json::from_cbor(std::vector<uint8_t>({0xa0})));

        CHECK(json::to_cbor(json::parse("{\"a\": 1, \"b\": [2, 3]}")) == std::vector<uint8_t>({0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03}));
        CHECK(json::parse("{\"a\": 1, \"b\": [2, 3]}") == json::from_cbor(std::vector<uint8_t>({0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03})));

        CHECK(json::to_cbor(json::parse("[\"a\", {\"b\": \"c\"}]")) == std::vector<uint8_t>({0x82, 0x61, 0x61, 0xa1, 0x61, 0x62, 0x61, 0x63}));
        CHECK(json::parse("[\"a\", {\"b\": \"c\"}]") == json::from_cbor(std::vector<uint8_t>({0x82, 0x61, 0x61, 0xa1, 0x61, 0x62, 0x61, 0x63})));

        CHECK(json::to_cbor(json::parse("{\"a\": \"A\", \"b\": \"B\", \"c\": \"C\", \"d\": \"D\", \"e\": \"E\"}")) == std::vector<uint8_t>({0xa5, 0x61, 0x61, 0x61, 0x41, 0x61, 0x62, 0x61, 0x42, 0x61, 0x63, 0x61, 0x43, 0x61, 0x64, 0x61, 0x44, 0x61, 0x65, 0x61, 0x45}));
        CHECK(json::parse("{\"a\": \"A\", \"b\": \"B\", \"c\": \"C\", \"d\": \"D\", \"e\": \"E\"}") == json::from_cbor(std::vector<uint8_t>({0xa5, 0x61, 0x61, 0x61, 0x41, 0x61, 0x62, 0x61, 0x42, 0x61, 0x63, 0x61, 0x43, 0x61, 0x64, 0x61, 0x44, 0x61, 0x65, 0x61, 0x45})));

        // indefinite length objects
        CHECK(json::parse("{\"a\": 1, \"b\": [2, 3]}") == json::from_cbor(std::vector<uint8_t>({0xbf, 0x61, 0x61, 0x01, 0x61, 0x62, 0x9f, 0x02, 0x03, 0xff, 0xff})));
        CHECK(json::parse("[\"a\", {\"b\": \"c\"}]") == json::from_cbor(std::vector<uint8_t>({0x82, 0x61, 0x61, 0xbf, 0x61, 0x62, 0x61, 0x63, 0xff})));
        CHECK(json::parse("{\"Fun\": true, \"Amt\": -2}") == json::from_cbor(std::vector<uint8_t>({0xbf, 0x63, 0x46, 0x75, 0x6e, 0xf5, 0x63, 0x41, 0x6d, 0x74, 0x21, 0xff})));
    }
}

TEST_CASE("Tagged values")
{
    json j = "s";
    auto v = json::to_cbor(j);

    SECTION("0xC6..0xD4")
    {
        for (auto b : std::vector<std::uint8_t>
    {
        0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4
    })
        {
            CAPTURE(b);

            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), b);

            // check that parsing fails in error mode
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);

            // check that parsing succeeds and gets original value in ignore mode
            auto j_tagged = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore);
            CHECK(j_tagged == j);

            auto j_tagged_stored = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::store);
            CHECK(j_tagged_stored == j);
        }
    }

    SECTION("0xD8 - 1 byte follows")
    {
        SECTION("success")
        {
            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), 0x42); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0xD8); // tag

            // check that parsing fails in error mode
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);

            // check that parsing succeeds and gets original value in ignore mode
            auto j_tagged = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore);
            CHECK(j_tagged == j);
        }

        SECTION("missing byte after tag")
        {
            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), 0xD8); // tag

            // check that parsing fails in all modes
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore), json::parse_error);
        }
    }

    SECTION("0xD9 - 2 byte follow")
    {
        SECTION("success")
        {
            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), 0x42); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x23); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0xD9); // tag

            // check that parsing fails in error mode
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);

            // check that parsing succeeds and gets original value in ignore mode
            auto j_tagged = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore);
            CHECK(j_tagged == j);
        }

        SECTION("missing byte after tag")
        {
            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), 0x23); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0xD9); // tag

            // check that parsing fails in all modes
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore), json::parse_error);
        }
    }

    SECTION("0xDA - 4 bytes follow")
    {
        SECTION("success")
        {
            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), 0x42); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x23); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x22); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x11); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0xDA); // tag

            // check that parsing fails in error mode
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);

            // check that parsing succeeds and gets original value in ignore mode
            auto j_tagged = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore);
            CHECK(j_tagged == j);
        }

        SECTION("missing bytes after tag")
        {
            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), 0x23); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x22); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x11); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0xDA); // tag

            // check that parsing fails in all modes
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore), json::parse_error);
        }
    }

    SECTION("0xDB - 8 bytes follow")
    {
        SECTION("success")
        {
            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), 0x42); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x23); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x22); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x11); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x42); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x23); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x22); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x11); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0xDB); // tag

            // check that parsing fails in error mode
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);

            // check that parsing succeeds and gets original value in ignore mode
            auto j_tagged = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore);
            CHECK(j_tagged == j);
        }

        SECTION("missing byte after tag")
        {
            // add tag to value
            auto v_tagged = v;
            v_tagged.insert(v_tagged.begin(), 0x42); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x23); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x22); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x11); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x23); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x22); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0x11); // 1 byte
            v_tagged.insert(v_tagged.begin(), 0xDB); // tag

            // check that parsing fails in all modes
            json _;
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::error), json::parse_error);
            CHECK_THROWS_AS(_ = json::from_cbor(v_tagged, true, true, json::cbor_tag_handler_t::ignore), json::parse_error);
        }
    }

    SECTION("tagged binary")
    {
        // create a binary value of subtype 42
        json j_binary;
        j_binary["binary"] = json::binary({0xCA, 0xFE, 0xBA, 0xBE}, 42);

        // convert to CBOR
        const auto vec = json::to_cbor(j_binary);
        CHECK(vec == std::vector<std::uint8_t> {0xA1, 0x66, 0x62, 0x69, 0x6E, 0x61, 0x72, 0x79, 0xD8, 0x2A, 0x44, 0xCA, 0xFE, 0xBA, 0xBE});

        // parse error when parsing tagged value
        json _;
        CHECK_THROWS_AS(_ = json::from_cbor(vec), json::parse_error);
        CHECK_THROWS_WITH(_ = json::from_cbor(vec), "[json.exception.parse_error.112] parse error at byte 9: syntax error while parsing CBOR value: invalid byte: 0xD8");

        // binary without subtype when tags are ignored
        json jb = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::ignore);
        CHECK(jb.is_object());
        CHECK(jb["binary"].is_binary());
        CHECK(!jb["binary"].get_binary().has_subtype());
    }
}
