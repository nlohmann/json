/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.6.1
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
#include <set>

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

    bool boolean(bool)
    {
        return events_left-- > 0;
    }

    bool number_integer(json::number_integer_t)
    {
        return events_left-- > 0;
    }

    bool number_unsigned(json::number_unsigned_t)
    {
        return events_left-- > 0;
    }

    bool number_float(json::number_float_t, const std::string&)
    {
        return events_left-- > 0;
    }

    bool string(std::string&)
    {
        return events_left-- > 0;
    }

    bool start_object(std::size_t)
    {
        return events_left-- > 0;
    }

    bool key(std::string&)
    {
        return events_left-- > 0;
    }

    bool end_object()
    {
        return events_left-- > 0;
    }

    bool start_array(std::size_t)
    {
        return events_left-- > 0;
    }

    bool end_array()
    {
        return events_left-- > 0;
    }

    bool parse_error(std::size_t, const std::string&, const json::exception&)
    {
        return false;
    }

  private:
    int events_left = 0;
};
}

TEST_CASE("MessagePack")
{
    SECTION("individual values")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            json j = json::value_t::discarded;
            const auto result = json::to_msgpack(j);
            CHECK(result.empty());
        }

        SECTION("null")
        {
            json j = nullptr;
            std::vector<uint8_t> expected = {0xc0};
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
                json j = true;
                std::vector<uint8_t> expected = {0xc3};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("false")
            {
                json j = false;
                std::vector<uint8_t> expected = {0xc2};
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
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(i));

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
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(i));

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
                        std::vector<uint8_t> expected;
                        expected.push_back(0xcc);
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 0xcc);
                        uint8_t restored = static_cast<uint8_t>(result[1]);
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
                        std::vector<uint8_t> expected;
                        expected.push_back(0xcd);
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0xcd);
                        uint16_t restored = static_cast<uint16_t>(static_cast<uint8_t>(result[1]) * 256 + static_cast<uint8_t>(result[2]));
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
                        std::vector<uint8_t> expected;
                        expected.push_back(0xce);
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0xce);
                        uint32_t restored = (static_cast<uint32_t>(result[1]) << 030) +
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
                                4294967296lu, 9223372036854775807lu
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
                        expected.push_back(0xcf);
                        expected.push_back(static_cast<uint8_t>((i >> 070) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 060) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 050) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 040) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 030) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 020) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 010) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0xcf);
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
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0xd0);
                        expected.push_back(static_cast<uint8_t>(i));

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
                    json j = -9263;
                    std::vector<uint8_t> expected = {0xd1, 0xdb, 0xd1};

                    const auto result = json::to_msgpack(j);
                    CHECK(result == expected);

                    int16_t restored = static_cast<int16_t>((result[1] << 8) + result[2]);
                    CHECK(restored == -9263);

                    // roundtrip
                    CHECK(json::from_msgpack(result) == j);
                    CHECK(json::from_msgpack(result, true, false) == j);
                }

                SECTION("-32768..-129 (int 16)")
                {
                    for (int16_t i = -32768; i <= -129; ++i)
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
                        int16_t restored = static_cast<int16_t>((result[1] << 8) + result[2]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("-32769..-2147483648")
                {
                    std::vector<int32_t> numbers;
                    numbers.push_back(-32769);
                    numbers.push_back(-65536);
                    numbers.push_back(-77777);
                    numbers.push_back(-1048576);
                    numbers.push_back(-2147483648ll);
                    for (auto i : numbers)
                    {
                        CAPTURE(i)

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0xd2);
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0xd2);
                        uint32_t restored = (static_cast<uint32_t>(result[1]) << 030) +
                                            (static_cast<uint32_t>(result[2]) << 020) +
                                            (static_cast<uint32_t>(result[3]) << 010) +
                                            static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("-9223372036854775808..-2147483649 (int 64)")
                {
                    std::vector<int64_t> numbers;
                    numbers.push_back(INT64_MIN);
                    numbers.push_back(-2147483649ll);
                    for (auto i : numbers)
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0xd3);
                        expected.push_back(static_cast<uint8_t>((i >> 070) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 060) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 050) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 040) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 030) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 020) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 010) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0xd3);
                        int64_t restored = (static_cast<int64_t>(result[1]) << 070) +
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
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>(i));

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
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0xcc);
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 0xcc);
                        uint8_t restored = static_cast<uint8_t>(result[1]);
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
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0xcd);
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 0xcd);
                        uint16_t restored = static_cast<uint16_t>(static_cast<uint8_t>(result[1]) * 256 + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }

                SECTION("65536..4294967295 (uint 32)")
                {
                    for (uint32_t i :
                            {
                                65536u, 77777u, 1048576u, 4294967295u
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0xce);
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 0xce);
                        uint32_t restored = (static_cast<uint32_t>(result[1]) << 030) +
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
                    for (uint64_t i :
                            {
                                4294967296lu, 18446744073709551615lu
                            })
                    {
                        CAPTURE(i)

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(0xcf);
                        expected.push_back(static_cast<uint8_t>((i >> 070) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 060) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 050) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 040) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 030) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 020) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 010) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_msgpack(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 0xcf);
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
                        CHECK(json::from_msgpack(result) == j);
                        CHECK(json::from_msgpack(result, true, false) == j);
                    }
                }
            }

            SECTION("float")
            {
                SECTION("3.1415925")
                {
                    double v = 3.1415925;
                    json j = v;
                    std::vector<uint8_t> expected =
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
                    json j = s;

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
                    json j = s;

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
                    json j = s;

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
                    json j = s;

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
                json j = json::array();
                std::vector<uint8_t> expected = {0x90};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("[null]")
            {
                json j = {nullptr};
                std::vector<uint8_t> expected = {0x91, 0xc0};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("[1,2,3,4,5]")
            {
                json j = json::parse("[1,2,3,4,5]");
                std::vector<uint8_t> expected = {0x95, 0x01, 0x02, 0x03, 0x04, 0x05};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("[[[[]]]]")
            {
                json j = json::parse("[[[[]]]]");
                std::vector<uint8_t> expected = {0x91, 0x91, 0x91, 0x90};
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
                json j = json::object();
                std::vector<uint8_t> expected = {0x80};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("{\"\":null}")
            {
                json j = {{"", nullptr}};
                std::vector<uint8_t> expected = {0x81, 0xa0, 0xc0};
                const auto result = json::to_msgpack(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_msgpack(result) == j);
                CHECK(json::from_msgpack(result, true, false) == j);
            }

            SECTION("{\"a\": {\"b\": {\"c\": {}}}}")
            {
                json j = json::parse("{\"a\": {\"b\": {\"c\": {}}}}");
                std::vector<uint8_t> expected =
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
                json j = R"({"00": null, "01": null, "02": null, "03": null,
                             "04": null, "05": null, "06": null, "07": null,
                             "08": null, "09": null, "10": null, "11": null,
                             "12": null, "13": null, "14": null, "15": null})"_json;

                const auto result = json::to_msgpack(j);

                // Checking against an expected vector byte by byte is
                // difficult, because no assumption on the order of key/value
                // pairs are made. We therefore only check the prefix (type and
                // size and the overall size. The rest is then handled in the
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
                // size and the overall size. The rest is then handled in the
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
    }

    SECTION("from float32")
    {
        auto given = std::vector<uint8_t>({0xca, 0x41, 0xc8, 0x00, 0x01});
        json j = json::from_msgpack(given);
        CHECK(j.get<double>() == Approx(25.0000019073486));
    }

    SECTION("errors")
    {
        SECTION("empty byte vector")
        {
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>()), json::parse_error&);
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>()),
                              "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing MessagePack value: unexpected end of input");
            CHECK(json::from_msgpack(std::vector<uint8_t>(), true, false).is_discarded());
        }

        SECTION("too short byte vector")
        {
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0x87})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcc})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcd})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcd, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xce})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcf})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xa5, 0x68, 0x65})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0x92, 0x01})), json::parse_error&);
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0x81, 0xa1, 0x61})), json::parse_error&);

            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0x87})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack string: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcc})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcd})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcd, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xce})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xce, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcf})),
                              "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 6: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 7: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 8: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
                              "[json.exception.parse_error.110] parse error at byte 9: syntax error while parsing MessagePack number: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xa5, 0x68, 0x65})),
                              "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing MessagePack string: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0x92, 0x01})),
                              "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing MessagePack value: unexpected end of input");
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0x81, 0xa1, 0x61})),
                              "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing MessagePack value: unexpected end of input");

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
        }

        SECTION("unsupported bytes")
        {
            SECTION("concrete examples")
            {
                CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xc1})), json::parse_error&);
                CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xc1})),
                                  "[json.exception.parse_error.112] parse error at byte 1: syntax error while parsing MessagePack value: invalid byte: 0xC1");
                CHECK(json::from_msgpack(std::vector<uint8_t>({0xc6}), true, false).is_discarded());

                CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0xc6})), json::parse_error&);
                CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0xc6})),
                                  "[json.exception.parse_error.112] parse error at byte 1: syntax error while parsing MessagePack value: invalid byte: 0xC6");
                CHECK(json::from_msgpack(std::vector<uint8_t>({0xc6}), true, false).is_discarded());
            }

            SECTION("all unsupported bytes")
            {
                for (auto byte :
                        {
                            // never used
                            0xc1,
                            // bin
                            0xc4, 0xc5, 0xc6,
                            // ext
                            0xc7, 0xc8, 0xc9,
                            // fixext
                            0xd4, 0xd5, 0xd6, 0xd7, 0xd8
                        })
                {
                    CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({static_cast<uint8_t>(byte)})), json::parse_error&);
                    CHECK(json::from_msgpack(std::vector<uint8_t>({static_cast<uint8_t>(byte)}), true, false).is_discarded());
                }
            }
        }

        SECTION("invalid string in map")
        {
            CHECK_THROWS_AS(json::from_msgpack(std::vector<uint8_t>({0x81, 0xff, 0x01})), json::parse_error&);
            CHECK_THROWS_WITH(json::from_msgpack(std::vector<uint8_t>({0x81, 0xff, 0x01})),
                              "[json.exception.parse_error.113] parse error at byte 2: syntax error while parsing MessagePack string: expected length specification (0xA0-0xBF, 0xD9-0xDB); last byte: 0xFF");
            CHECK(json::from_msgpack(std::vector<uint8_t>({0x81, 0xff, 0x01}), true, false).is_discarded());
        }

        SECTION("strict mode")
        {
            std::vector<uint8_t> vec = {0xc0, 0xc0};
            SECTION("non-strict mode")
            {
                const auto result = json::from_msgpack(vec, false);
                CHECK(result == json());
            }

            SECTION("strict mode")
            {
                CHECK_THROWS_AS(json::from_msgpack(vec), json::parse_error&);
                CHECK_THROWS_WITH(json::from_msgpack(vec),
                                  "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing MessagePack value: expected end of input; last byte: 0xC0");
                CHECK(json::from_msgpack(vec, true, false).is_discarded());
            }
        }
    }

    SECTION("SAX aborts")
    {
        SECTION("start_array(len)")
        {
            std::vector<uint8_t> v = {0x93, 0x01, 0x02, 0x03};
            SaxCountdown scp(0);
            CHECK(not json::sax_parse(v, &scp, json::input_format_t::msgpack));
        }

        SECTION("start_object(len)")
        {
            std::vector<uint8_t> v = {0x81, 0xa3, 0x66, 0x6F, 0x6F, 0xc2};
            SaxCountdown scp(0);
            CHECK(not json::sax_parse(v, &scp, json::input_format_t::msgpack));
        }

        SECTION("key()")
        {
            std::vector<uint8_t> v = {0x81, 0xa3, 0x66, 0x6F, 0x6F, 0xc2};
            SaxCountdown scp(1);
            CHECK(not json::sax_parse(v, &scp, json::input_format_t::msgpack));
        }
    }
}

// use this testcase outside [hide] to run it with Valgrind
TEST_CASE("single MessagePack roundtrip")
{
    SECTION("sample.json")
    {
        std::string filename = "test/data/json_testsuite/sample.json";

        // parse JSON file
        std::ifstream f_json(filename);
        json j1 = json::parse(f_json);

        // parse MessagePack file
        std::ifstream f_msgpack(filename + ".msgpack", std::ios::binary);
        std::vector<uint8_t> packed((std::istreambuf_iterator<char>(f_msgpack)),
                                    std::istreambuf_iterator<char>());
        json j2;
        CHECK_NOTHROW(j2 = json::from_msgpack(packed));

        // compare parsed JSON values
        CHECK(j1 == j2);

        SECTION("roundtrips")
        {
            SECTION("std::ostringstream")
            {
                std::ostringstream ss;
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
        // most of these are exluded due to differences in key order (not a real problem)
        auto exclude_packed = std::set<std::string>
        {
            "test/data/json.org/1.json",
            "test/data/json.org/2.json",
            "test/data/json.org/3.json",
            "test/data/json.org/4.json",
            "test/data/json.org/5.json",
            "test/data/json_testsuite/sample.json", // kills AppVeyor
            "test/data/json_tests/pass1.json",
            "test/data/regression/working_file.json",
            "test/data/nst_json_testsuite/test_parsing/y_object.json",
            "test/data/nst_json_testsuite/test_parsing/y_object_basic.json",
            "test/data/nst_json_testsuite/test_parsing/y_object_duplicated_key.json",
            "test/data/nst_json_testsuite/test_parsing/y_object_long_strings.json",
            "test/data/nst_json_testsuite/test_parsing/y_object_simple.json",
            "test/data/nst_json_testsuite/test_parsing/y_object_string_unicode.json",
        };

        for (std::string filename :
                {
                    "test/data/json_nlohmann_tests/all_unicode.json",
                    "test/data/json.org/1.json",
                    "test/data/json.org/2.json",
                    "test/data/json.org/3.json",
                    "test/data/json.org/4.json",
                    "test/data/json.org/5.json",
                    "test/data/json_roundtrip/roundtrip01.json",
                    "test/data/json_roundtrip/roundtrip02.json",
                    "test/data/json_roundtrip/roundtrip03.json",
                    "test/data/json_roundtrip/roundtrip04.json",
                    "test/data/json_roundtrip/roundtrip05.json",
                    "test/data/json_roundtrip/roundtrip06.json",
                    "test/data/json_roundtrip/roundtrip07.json",
                    "test/data/json_roundtrip/roundtrip08.json",
                    "test/data/json_roundtrip/roundtrip09.json",
                    "test/data/json_roundtrip/roundtrip10.json",
                    "test/data/json_roundtrip/roundtrip11.json",
                    "test/data/json_roundtrip/roundtrip12.json",
                    "test/data/json_roundtrip/roundtrip13.json",
                    "test/data/json_roundtrip/roundtrip14.json",
                    "test/data/json_roundtrip/roundtrip15.json",
                    "test/data/json_roundtrip/roundtrip16.json",
                    "test/data/json_roundtrip/roundtrip17.json",
                    "test/data/json_roundtrip/roundtrip18.json",
                    "test/data/json_roundtrip/roundtrip19.json",
                    "test/data/json_roundtrip/roundtrip20.json",
                    "test/data/json_roundtrip/roundtrip21.json",
                    "test/data/json_roundtrip/roundtrip22.json",
                    "test/data/json_roundtrip/roundtrip23.json",
                    "test/data/json_roundtrip/roundtrip24.json",
                    "test/data/json_roundtrip/roundtrip25.json",
                    "test/data/json_roundtrip/roundtrip26.json",
                    "test/data/json_roundtrip/roundtrip27.json",
                    "test/data/json_roundtrip/roundtrip28.json",
                    "test/data/json_roundtrip/roundtrip29.json",
                    "test/data/json_roundtrip/roundtrip30.json",
                    "test/data/json_roundtrip/roundtrip31.json",
                    "test/data/json_roundtrip/roundtrip32.json",
                    "test/data/json_testsuite/sample.json", // kills AppVeyor
                    "test/data/json_tests/pass1.json",
                    "test/data/json_tests/pass2.json",
                    "test/data/json_tests/pass3.json",
                    "test/data/regression/floats.json",
                    "test/data/regression/signed_ints.json",
                    "test/data/regression/unsigned_ints.json",
                    "test/data/regression/working_file.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_arraysWithSpaces.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_empty-string.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_empty.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_ending_with_newline.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_false.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_heterogeneous.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_null.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_with_1_and_newline.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_with_leading_space.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_with_several_null.json",
                    "test/data/nst_json_testsuite/test_parsing/y_array_with_trailing_space.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_0e+1.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_0e1.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_after_space.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_double_close_to_zero.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_double_huge_neg_exp.json",
                    //"test/data/nst_json_testsuite/test_parsing/y_number_huge_exp.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_int_with_exp.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_minus_zero.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_negative_int.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_negative_one.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_negative_zero.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_real_capital_e.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_real_capital_e_neg_exp.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_real_capital_e_pos_exp.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_real_exponent.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_real_fraction_exponent.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_real_neg_exp.json",
                    //"test/data/nst_json_testsuite/test_parsing/y_number_real_neg_overflow.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_real_pos_exponent.json",
                    //"test/data/nst_json_testsuite/test_parsing/y_number_real_pos_overflow.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_real_underflow.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_simple_int.json",
                    "test/data/nst_json_testsuite/test_parsing/y_number_simple_real.json",
                    //"test/data/nst_json_testsuite/test_parsing/y_number_too_big_neg_int.json",
                    //"test/data/nst_json_testsuite/test_parsing/y_number_too_big_pos_int.json",
                    //"test/data/nst_json_testsuite/test_parsing/y_number_very_big_negative_int.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_basic.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_duplicated_key.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_duplicated_key_and_value.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_empty.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_empty_key.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_escaped_null_in_key.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_extreme_numbers.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_long_strings.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_simple.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_string_unicode.json",
                    "test/data/nst_json_testsuite/test_parsing/y_object_with_newlines.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_1_2_3_bytes_UTF-8_sequences.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_UTF-16_Surrogates_U+1D11E_MUSICAL_SYMBOL_G_CLEF.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_accepted_surrogate_pair.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_accepted_surrogate_pairs.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_allowed_escapes.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_backslash_and_u_escaped_zero.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_backslash_doublequotes.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_comments.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_double_escape_a.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_double_escape_n.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_escaped_control_character.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_escaped_noncharacter.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_in_array.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_in_array_with_leading_space.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_last_surrogates_1_and_2.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_newline_uescaped.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_nonCharacterInUTF-8_U+10FFFF.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_nonCharacterInUTF-8_U+1FFFF.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_nonCharacterInUTF-8_U+FFFF.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_null_escape.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_one-byte-utf-8.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_pi.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_simple_ascii.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_space.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_three-byte-utf-8.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_two-byte-utf-8.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_u+2028_line_sep.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_u+2029_par_sep.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_uEscape.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_unescaped_char_delete.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_unicode.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_unicodeEscapedBackslash.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_unicode_2.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_unicode_U+200B_ZERO_WIDTH_SPACE.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_unicode_U+2064_invisible_plus.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_unicode_escaped_double_quote.json",
                    // "test/data/nst_json_testsuite/test_parsing/y_string_utf16.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_utf8.json",
                    "test/data/nst_json_testsuite/test_parsing/y_string_with_del_character.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_lonely_false.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_lonely_int.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_lonely_negative_real.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_lonely_null.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_lonely_string.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_lonely_true.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_string_empty.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_trailing_newline.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_true_in_array.json",
                    "test/data/nst_json_testsuite/test_parsing/y_structure_whitespace_array.json"
                })
        {
            CAPTURE(filename)

            {
                INFO_WITH_TEMP(filename + ": std::vector<uint8_t>");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse MessagePack file
                std::ifstream f_msgpack(filename + ".msgpack", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_msgpack)),
                    std::istreambuf_iterator<char>());
                json j2;
                CHECK_NOTHROW(j2 = json::from_msgpack(packed));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": std::ifstream");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

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
                json j1 = json::parse(f_json);

                // parse MessagePack file
                std::ifstream f_msgpack(filename + ".msgpack", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_msgpack)),
                    std::istreambuf_iterator<char>());
                json j2;
                CHECK_NOTHROW(j2 = json::from_msgpack({packed.data(), packed.size()}));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": output to output adapters");
                // parse JSON file
                std::ifstream f_json(filename);
                json j1 = json::parse(f_json);

                // parse MessagePack file
                std::ifstream f_msgpack(filename + ".msgpack", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_msgpack)),
                    std::istreambuf_iterator<char>());

                if (!exclude_packed.count(filename))
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
