/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.0.1
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2017 Niels Lohmann <http://nlohmann.me>.

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

#include "catch.hpp"

#include "json.hpp"
using nlohmann::json;

#include <fstream>

TEST_CASE("UBJSON")
{
    SECTION("individual values")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            json j = json::value_t::discarded;
            const auto result = json::to_ubjson(j);
            CHECK(result.empty());
        }

        SECTION("null")
        {
            json j = nullptr;
            std::vector<uint8_t> expected = {'Z'};
            const auto result = json::to_ubjson(j);
            CHECK(result == expected);

            // roundtrip
            CHECK(json::from_ubjson(result) == j);
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json j = true;
                std::vector<uint8_t> expected = {'T'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }

            SECTION("false")
            {
                json j = false;
                std::vector<uint8_t> expected = {'F'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }
        }

        SECTION("number")
        {
            SECTION("signed")
            {
                SECTION("-9223372036854775808..-2147483649 (int64)")
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
                    numbers.push_back(-2147483649);
                    for (auto i : numbers)
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>('L'));
                        expected.push_back(static_cast<uint8_t>((i >> 56) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 48) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 40) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 32) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
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
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("-2147483648..-32769 (int32)")
                {
                    std::vector<int64_t> numbers;
                    numbers.push_back(-32769);
                    numbers.push_back(-100000);
                    numbers.push_back(-1000000);
                    numbers.push_back(-10000000);
                    numbers.push_back(-100000000);
                    numbers.push_back(-1000000000);
                    numbers.push_back(-2147483648);
                    for (auto i : numbers)
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>('l'));
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        int32_t restored = (static_cast<int32_t>(result[1]) << 030) +
                                           (static_cast<int32_t>(result[2]) << 020) +
                                           (static_cast<int32_t>(result[3]) << 010) +
                                           static_cast<int32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("-32768..-129 (int16)")
                {
                    for (int32_t i = -32768; i <= -129; ++i)
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>('I'));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        int16_t restored = static_cast<int16_t>(((result[1] << 8) + result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("-9263 (int16)")
                {
                    json j = -9263;
                    std::vector<uint8_t> expected = {'I', 0xdb, 0xd1};

                    // compare result + size
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);
                    CHECK(result.size() == 3);

                    // check individual bytes
                    CHECK(result[0] == 'I');
                    int16_t restored = static_cast<int16_t>(((result[1] << 8) + result[2]));
                    CHECK(restored == -9263);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                }

                SECTION("-128..-1 (int8)")
                {
                    for (auto i = -128; i <= -1; ++i)
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back('i');
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        CHECK(static_cast<int8_t>(result[1]) == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("0..127 (int8)")
                {
                    for (size_t i = 0; i <= 127; ++i)
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>('i'));
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        CHECK(result[1] == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("128..255 (uint8)")
                {
                    for (size_t i = 128; i <= 255; ++i)
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>('U'));
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'U');
                        CHECK(result[1] == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("256..32767 (int16)")
                {
                    for (size_t i = 256; i <= 32767; ++i)
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back(static_cast<uint8_t>('I'));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        uint16_t restored = static_cast<uint16_t>(static_cast<uint8_t>(result[1]) * 256 + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("65536..2147483647 (int32)")
                {
                    for (uint32_t i :
                            {
                                65536u, 77777u, 1048576u
                            })
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back('l');
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        uint32_t restored = (static_cast<uint32_t>(result[1]) << 030) +
                                            (static_cast<uint32_t>(result[2]) << 020) +
                                            (static_cast<uint32_t>(result[3]) << 010) +
                                            static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("2147483648..9223372036854775807 (int64)")
                {
                    for (uint64_t i :
                            {
                                2147483648ul, 9223372036854775807ul
                            })
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = -1;
                        j.get_ref<json::number_integer_t&>() = static_cast<json::number_integer_t>(i);

                        // check type
                        CHECK(j.is_number_integer());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back('L');
                        expected.push_back(static_cast<uint8_t>((i >> 070) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 060) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 050) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 040) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 030) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 020) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 010) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
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
                        CHECK(json::from_ubjson(result) == j);
                    }
                }
            }

            SECTION("unsigned")
            {
                SECTION("0..127 (int8)")
                {
                    for (size_t i = 0; i <= 127; ++i)
                    {
                        CAPTURE(i);

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back('i');
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'i');
                        uint8_t restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("128..255 (uint8)")
                {
                    for (size_t i = 128; i <= 255; ++i)
                    {
                        CAPTURE(i);

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back('U');
                        expected.push_back(static_cast<uint8_t>(i));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 2);

                        // check individual bytes
                        CHECK(result[0] == 'U');
                        uint8_t restored = static_cast<uint8_t>(result[1]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("256..32767 (int16)")
                {
                    for (size_t i = 256; i <= 32767; ++i)
                    {
                        CAPTURE(i);

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back('I');
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 3);

                        // check individual bytes
                        CHECK(result[0] == 'I');
                        uint16_t restored = static_cast<uint16_t>(static_cast<uint8_t>(result[1]) * 256 + static_cast<uint8_t>(result[2]));
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("65536..2147483647 (int32)")
                {
                    for (uint32_t i :
                            {
                                65536u, 77777u, 1048576u
                            })
                    {
                        CAPTURE(i);

                        // create JSON value with unsigned integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back('l');
                        expected.push_back(static_cast<uint8_t>((i >> 24) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 16) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 8) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 5);

                        // check individual bytes
                        CHECK(result[0] == 'l');
                        uint32_t restored = (static_cast<uint32_t>(result[1]) << 030) +
                                            (static_cast<uint32_t>(result[2]) << 020) +
                                            (static_cast<uint32_t>(result[3]) << 010) +
                                            static_cast<uint32_t>(result[4]);
                        CHECK(restored == i);

                        // roundtrip
                        CHECK(json::from_ubjson(result) == j);
                    }
                }

                SECTION("2147483648..9223372036854775807 (int64)")
                {
                    for (uint64_t i :
                            {
                                2147483648ul, 9223372036854775807ul
                            })
                    {
                        CAPTURE(i);

                        // create JSON value with integer number
                        json j = i;

                        // check type
                        CHECK(j.is_number_unsigned());

                        // create expected byte vector
                        std::vector<uint8_t> expected;
                        expected.push_back('L');
                        expected.push_back(static_cast<uint8_t>((i >> 070) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 060) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 050) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 040) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 030) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 020) & 0xff));
                        expected.push_back(static_cast<uint8_t>((i >> 010) & 0xff));
                        expected.push_back(static_cast<uint8_t>(i & 0xff));

                        // compare result + size
                        const auto result = json::to_ubjson(j);
                        CHECK(result == expected);
                        CHECK(result.size() == 9);

                        // check individual bytes
                        CHECK(result[0] == 'L');
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
                        CHECK(json::from_ubjson(result) == j);
                    }
                }
            }

            SECTION("float64")
            {
                SECTION("3.1415925")
                {
                    double v = 3.1415925;
                    json j = v;
                    std::vector<uint8_t> expected =
                    {
                        'D', 0x40, 0x09, 0x21, 0xfb, 0x3f, 0xa6, 0xde, 0xfc
                    };
                    const auto result = json::to_ubjson(j);
                    CHECK(result == expected);

                    // roundtrip
                    CHECK(json::from_ubjson(result) == j);
                    CHECK(json::from_ubjson(result) == v);
                }
            }
        }

        SECTION("string")
        {
            SECTION("N = 0..127")
            {
                for (size_t N = 0; N <= 127; ++N)
                {
                    CAPTURE(N);

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json j = s;

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
                }
            }

            SECTION("N = 128..255")
            {
                for (size_t N = 128; N <= 255; ++N)
                {
                    CAPTURE(N);

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json j = s;

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
                }
            }

            SECTION("N = 256..32767")
            {
                for (size_t N :
                        {
                            256u, 999u, 1025u, 3333u, 2048u, 32767u
                        })
                {
                    CAPTURE(N);

                    // create JSON value with string containing of N * 'x'
                    const auto s = std::string(N, 'x');
                    json j = s;

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
                }
            }

            SECTION("N = 65536..2147483647")
            {
                for (size_t N :
                        {
                            65536u, 77777u, 1048576u
                        })
                {
                    CAPTURE(N);

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
                }
            }
        }

        SECTION("array")
        {
            SECTION("empty")
            {
                json j = json::array();
                std::vector<uint8_t> expected = {'[', ']'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }

            SECTION("[null]")
            {
                json j = {nullptr};
                std::vector<uint8_t> expected = {'[', 'Z', ']'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }

            SECTION("[1,2,3,4,5]")
            {
                json j = json::parse("[1,2,3,4,5]");
                std::vector<uint8_t> expected = {'[', 'i', 1, 'i', 2, 'i', 3, 'i', 4, 'i', 5, ']'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }

            SECTION("[[[[]]]]")
            {
                json j = json::parse("[[[[]]]]");
                std::vector<uint8_t> expected = {'[', '[', '[', '[', ']', ']', ']', ']'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }

            SECTION("array with uint16_t elements")
            {
                json j(257, nullptr);
                std::vector<uint8_t> expected(j.size() + 2, 'Z'); // all null
                expected[0] = '['; // opening array
                expected[258] = ']'; // closing array
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }

            SECTION("array with uint32_t elements")
            {
                json j(65793, nullptr);
                std::vector<uint8_t> expected(j.size() + 2, 'Z'); // all null
                expected[0] = '['; // opening array
                expected[65794] = ']'; // closing array
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }
        }

        SECTION("object")
        {
            SECTION("empty")
            {
                json j = json::object();
                std::vector<uint8_t> expected = {'{', '}'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }

            SECTION("{\"\":null}")
            {
                json j = {{"", nullptr}};
                std::vector<uint8_t> expected = {'{', 'i', 0, 'Z', '}'};
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }

            SECTION("{\"a\": {\"b\": {\"c\": {}}}}")
            {
                json j = json::parse("{\"a\": {\"b\": {\"c\": {}}}}");
                std::vector<uint8_t> expected =
                {
                    '{', 'i', 1, 'a', '{', 'i', 1, 'b', '{', 'i', 1, 'c', '{', '}', '}', '}', '}'
                };
                const auto result = json::to_ubjson(j);
                CHECK(result == expected);

                // roundtrip
                CHECK(json::from_ubjson(result) == j);
            }
        }
    }

    SECTION("errors")
    {
        SECTION("empty byte vector")
        {
            CHECK_THROWS_AS(json::from_ubjson(std::vector<uint8_t>()), json::parse_error&);
            CHECK_THROWS_WITH(json::from_ubjson(std::vector<uint8_t>()),
                              "[json.exception.parse_error.110] parse error at 1: unexpected end of input");
        }

        SECTION("too short byte vector")
        {
        }

        SECTION("unsupported bytes")
        {
            SECTION("concrete examples")
            {
                CHECK_THROWS_AS(json::from_cbor(std::vector<uint8_t>({0x1c})), json::parse_error&);
                CHECK_THROWS_WITH(json::from_cbor(std::vector<uint8_t>({0x1c})),
                                  "[json.exception.parse_error.112] parse error at 1: error reading CBOR; last byte: 0x1C");
                CHECK_THROWS_AS(json::from_cbor(std::vector<uint8_t>({0xf8})), json::parse_error&);
                CHECK_THROWS_WITH(json::from_cbor(std::vector<uint8_t>({0xf8})),
                                  "[json.exception.parse_error.112] parse error at 1: error reading CBOR; last byte: 0xF8");
            }

            SECTION("all unsupported bytes")
            {
                for (auto byte :
                        {
                            // ?
                            0x1c, 0x1d, 0x1e, 0x1f,
                            // ?
                            0x3c, 0x3d, 0x3e, 0x3f,
                            // byte strings
                            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                            // byte strings
                            0x58, 0x59, 0x5a, 0x5b,
                            // ?
                            0x5c, 0x5d, 0x5e,
                            // byte string
                            0x5f,
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
                    CHECK_THROWS_AS(json::from_cbor(std::vector<uint8_t>({static_cast<uint8_t>(byte)})), json::parse_error&);
                }
            }
        }

        SECTION("invalid string in map")
        {
            CHECK_THROWS_AS(json::from_cbor(std::vector<uint8_t>({0xa1, 0xff, 0x01})), json::parse_error&);
            CHECK_THROWS_WITH(json::from_cbor(std::vector<uint8_t>({0xa1, 0xff, 0x01})),
                              "[json.exception.parse_error.113] parse error at 2: expected a CBOR string; last byte: 0xFF");
        }

        SECTION("strict mode")
        {
            std::vector<uint8_t> vec = {0xf6, 0xf6};
            SECTION("non-strict mode")
            {
                const auto result = json::from_cbor(vec, false);
                CHECK(result == json());
            }

            SECTION("strict mode")
            {
                CHECK_THROWS_AS(json::from_cbor(vec), json::parse_error&);
                CHECK_THROWS_WITH(json::from_cbor(vec),
                                  "[json.exception.parse_error.110] parse error at 2: expected end of input");
            }
        }
    }
}

// use this testcase outside [hide] to run it with Valgrind
TEST_CASE("single CBOR roundtrip")
{
    SECTION("sample.json")
    {
        std::string filename = "test/data/json_testsuite/sample.json";

        // parse JSON file
        std::ifstream f_json(filename);
        json j1 = json::parse(f_json);

        // parse MessagePack file
        std::ifstream f_cbor(filename + ".cbor", std::ios::binary);
        std::vector<uint8_t> packed((std::istreambuf_iterator<char>(f_cbor)),
                                    std::istreambuf_iterator<char>());
        json j2;
        CHECK_NOTHROW(j2 = json::from_cbor(packed));

        // compare parsed JSON values
        CHECK(j1 == j2);

        SECTION("roundtrips")
        {
            SECTION("std::ostringstream")
            {
                std::ostringstream ss;
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

TEST_CASE("CBOR roundtrips", "[hide]")
{
    SECTION("input from flynn")
    {
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
            CAPTURE(filename);

            // parse JSON file
            std::ifstream f_json(filename);
            json j1 = json::parse(f_json);

            SECTION("std::vector<uint8_t>")
            {
                // parse CBOR file
                std::ifstream f_cbor(filename + ".cbor", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_cbor)),
                    std::istreambuf_iterator<char>());
                json j2;
                CHECK_NOTHROW(j2 = json::from_cbor(packed));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            SECTION("std::ifstream")
            {
                // parse CBOR file
                std::ifstream f_cbor(filename + ".cbor", std::ios::binary);
                json j2;
                CHECK_NOTHROW(j2 = json::from_cbor(f_cbor));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            SECTION("uint8_t* and size")
            {
                // parse CBOR file
                std::ifstream f_cbor(filename + ".cbor", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_cbor)),
                    std::istreambuf_iterator<char>());
                json j2;
                CHECK_NOTHROW(j2 = json::from_cbor({packed.data(), packed.size()}));

                // compare parsed JSON values
                CHECK(j1 == j2);
            }

            SECTION("output to output adapters")
            {
                // parse CBOR file
                std::ifstream f_cbor(filename + ".cbor", std::ios::binary);
                std::vector<uint8_t> packed(
                    (std::istreambuf_iterator<char>(f_cbor)),
                    std::istreambuf_iterator<char>());

                SECTION("std::vector<uint8_t>")
                {
                    std::vector<uint8_t> vec;
                    json::to_cbor(j1, vec);
                    CHECK(vec == packed);
                }
            }
        }
    }
}

/*
TEST_CASE("Universal Binary JSON Specification Examples")
{
    for (std::string prefix :
            {
                "test/data/universal-binary-json-java/CouchDB4k",
                "test/data/universal-binary-json-java/MediaContent",
                "test/data/universal-binary-json-java/TwitterTimeline"
            })
    {
        CAPTURE(prefix);

        // parse JSON file
        std::ifstream f_json(prefix + ".formatted.json");
        json j1 = json::parse(f_json);

        SECTION("std::vector<uint8_t>")
        {
            // parse UBJSON file
            std::ifstream f_ubjson(prefix + ".ubj", std::ios::binary);
            std::vector<uint8_t> packed(
                (std::istreambuf_iterator<char>(f_ubjson)),
                std::istreambuf_iterator<char>());
            json j2;
            CHECK_NOTHROW(j2 = json::from_ubjson(packed));

            // compare parsed JSON values
            CHECK(j1 == j2);
        }
    }
}
*/


/*
TEST_CASE("all first bytes", "[!throws]")
{
    // these bytes will fail immediately with exception parse_error.112
    std::set<uint8_t> unsupported =
    {
        //// types not supported by this library

        // byte strings
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        // byte strings
        0x58, 0x59, 0x5a, 0x5b, 0x5f,
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
            json::from_cbor(std::vector<uint8_t>(1, byte));
        }
        catch (const json::parse_error& e)
        {
            // check that parse_error.112 is only thrown if the
            // first byte is in the unsupported set
            CAPTURE(e.what());
            if (std::find(unsupported.begin(), unsupported.end(), byte) != unsupported.end())
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
*/

/*
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
        CHECK(json::parse("\"streaming\"") == json::from_cbor(std::vector<uint8_t>({0x7f, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0xff})));
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
*/
