/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.2
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
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <iostream>
#include <fstream>
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

TEST_CASE("BON8")
{
    SECTION("individual values")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            json j = json::value_t::discarded;
            const auto result = json::to_bon8(j);
            CHECK(result.empty());
        }

        SECTION("null")
        {
            json j = nullptr;
            std::vector<uint8_t> expected = {0xFA};
            const auto result = json::to_bon8(j);
            CHECK(result == expected);
            CHECK(json::from_bon8(result) == j);
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json j = true;
                std::vector<uint8_t> expected = {0xF9};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
                CHECK(json::from_bon8(result) == j);
            }

            SECTION("false")
            {
                json j = false;
                std::vector<uint8_t> expected = {0xF8};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
                CHECK(json::from_bon8(result) == j);
            }
        }

        SECTION("unsigned integers")
        {
            SECTION("0..39")
            {
                SECTION("0")
                {
                    json j = 0U;
                    std::vector<uint8_t> expected = {0x90};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("39")
                {
                    json j = 39U;
                    std::vector<uint8_t> expected = {0xB7};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("40..3879")
            {
                SECTION("40")
                {
                    json j = 40U;
                    std::vector<uint8_t> expected = {0xC2, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("3879")
                {
                    json j = 3879U;
                    std::vector<uint8_t> expected = {0xDF, 0x7F};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("3880..524287")
            {
                SECTION("3880")
                {
                    json j = 3880U;
                    std::vector<uint8_t> expected = {0xE0, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("528167")
                {
                    json j = 528167U;
                    std::vector<uint8_t> expected = {0xEF, 0x7F, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("528168..67637031")
            {
                SECTION("528168")
                {
                    json j = 528168U;
                    std::vector<uint8_t> expected = {0xF0, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("67637031")
                {
                    json j = 67637031U;
                    std::vector<uint8_t> expected = {0xF7, 0x7F, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("67637032..2147483647 (int32max)")
            {
                SECTION("67637032")
                {
                    json j = 67637032U;
                    std::vector<uint8_t> expected = {0x8C, 0x04, 0x08, 0x0F, 0x28};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("2147483647 (int32max)")
                {
                    json j = 2147483647U;
                    std::vector<uint8_t> expected = {0x8C, 0x7F, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("2147483648..9223372036854775807 (int64max)")
            {
                SECTION("2147483648")
                {
                    json j = 2147483648U;
                    std::vector<uint8_t> expected = {0x8D, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("9223372036854775807 (int64max)")
                {
                    json j = 9223372036854775807U;
                    std::vector<uint8_t> expected = {0x8D, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("greater than int64max")
            {
                json j = 9223372036854775808U;
                CHECK_THROWS_WITH_AS(json::to_bon8(j), "[json.exception.out_of_range.407] integer number 9223372036854775808 cannot be represented by BON8 as it does not fit int64", json::out_of_range);
            }
        }

        SECTION("signed integers")
        {
            SECTION("-9223372036854775808 (int64min)..-2147483649")
            {
                SECTION("-9223372036854775808")
                {
                    json j = INT64_MIN;
                    std::vector<uint8_t> expected = {0x8D, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("-2147483649")
                {
                    // cannot use -2147483649 directly, see https://developercommunity.visualstudio.com/t/-2147483648-c4146-error/141813#T-N229960
                    json j = static_cast<std::int64_t>(-2147483647) - 2;
                    std::vector<uint8_t> expected = {0x8D, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("-2147483648 (int32min)..-33818507")
            {
                SECTION("-2147483648")
                {
                    // cannot use -2147483648 directly, see https://developercommunity.visualstudio.com/t/-2147483648-c4146-error/141813#T-N229960
                    json j = -2147483647 - 1;
                    std::vector<uint8_t> expected = {0x8C, 0x80, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("-33818507")
                {
                    json j = -33818507;
                    std::vector<uint8_t> expected = {0x8C, 0xFD, 0xFB, 0xF8, 0x75};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("-33818506..-264075")
            {
                SECTION("-33818506")
                {
                    json j = -33818506;
                    std::vector<uint8_t> expected = {0xF7, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("-264075")
                {
                    json j = -264075;
                    std::vector<uint8_t> expected = {0xF0, 0xC0, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("-264074..-1931")
            {
                SECTION("-264074")
                {
                    json j = -264074;
                    std::vector<uint8_t> expected = {0xEF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("-1931")
                {
                    json j = -1931;
                    std::vector<uint8_t> expected = {0xE0, 0xC0, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("-1930..-11")
            {
                SECTION("-1930")
                {
                    json j = -1930;
                    std::vector<uint8_t> expected = {0xDF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("-11")
                {
                    json j = -11;
                    std::vector<uint8_t> expected = {0xC2, 0xC0};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("-10..-1")
            {
                SECTION("-10")
                {
                    json j = -10;
                    std::vector<uint8_t> expected = {0xC1};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("-1")
                {
                    json j = -1;
                    std::vector<uint8_t> expected = {0xB8};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("0..39")
            {
                SECTION("0")
                {
                    json j = 0;
                    std::vector<uint8_t> expected = {0x90};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("39")
                {
                    json j = 39;
                    std::vector<uint8_t> expected = {0xB7};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("40..3879")
            {
                SECTION("40")
                {
                    json j = 40;
                    std::vector<uint8_t> expected = {0xC2, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("3879")
                {
                    json j = 3879;
                    std::vector<uint8_t> expected = {0xDF, 0x7F};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("3880..524287")
            {
                SECTION("3880")
                {
                    json j = 3880;
                    std::vector<uint8_t> expected = {0xE0, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("528167")
                {
                    json j = 528167;
                    std::vector<uint8_t> expected = {0xEF, 0x7F, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("528168..67637031")
            {
                SECTION("528168")
                {
                    json j = 528168;
                    std::vector<uint8_t> expected = {0xF0, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("67637031")
                {
                    json j = 67637031;
                    std::vector<uint8_t> expected = {0xF7, 0x7F, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("67637032..2147483647 (int32max)")
            {
                SECTION("67637032")
                {
                    json j = 67637032;
                    std::vector<uint8_t> expected = {0x8C, 0x04, 0x08, 0x0F, 0x28};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("2147483647 (int32max)")
                {
                    json j = 2147483647;
                    std::vector<uint8_t> expected = {0x8C, 0x7F, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("2147483648..9223372036854775807 (int64max)")
            {
                SECTION("2147483648")
                {
                    json j = 2147483648;
                    std::vector<uint8_t> expected = {0x8D, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("9223372036854775807 (int64max)")
                {
                    json j = 9223372036854775807;
                    std::vector<uint8_t> expected = {0x8D, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }
        }

        SECTION("floating-point numbers")
        {
            SECTION("special values")
            {
                SECTION("-1.0")
                {
                    json j = -1.0;
                    std::vector<uint8_t> expected = {0xFB};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("0.0")
                {
                    json j = 0.0;
                    std::vector<uint8_t> expected = {0xFC};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("1.0")
                {
                    json j = 1.0;
                    std::vector<uint8_t> expected = {0xFD};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("-0.0")
                {
                    json j = -0.0;
                    std::vector<uint8_t> expected = {0x8E, 0x80, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("NAN")
                {
                    json j = NAN;
                    std::vector<uint8_t> expected = {0x8E, 0x7F, 0x80, 0x00, 0x01};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    json::number_float_t d{json::from_bon8(result)};
                    CHECK(std::isnan(d));
                }

                SECTION("infinity")
                {
                    json j = INFINITY;
                    std::vector<uint8_t> expected = {0x8E, 0x7F, 0x80, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("-infinity")
                {
                    json j = -INFINITY;
                    std::vector<uint8_t> expected = {0x8E, 0xFF, 0x80, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("floats")
            {
                SECTION("2.0")
                {
                    json j = 2.0;
                    std::vector<uint8_t> expected = {0x8E, 0x40, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("doubles")
            {
                SECTION("100000000.1")
                {
                    json j = 100000000.1;
                    std::vector<uint8_t> expected = {0x8F, 0x41, 0x97, 0xD7, 0x84, 0x00, 0x66, 0x66, 0x66};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }
        }

        SECTION("string")
        {
            SECTION("empty string")
            {
                json j = "";
                std::vector<uint8_t> expected = {0xFF};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
                CHECK(json::from_bon8(result) == j);
            }

            SECTION("other strings")
            {
                json j = "This is a string.";
                std::vector<uint8_t> expected = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 's', 't', 'r', 'i', 'n', 'g', '.', 0xFF};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
                CHECK(json::from_bon8(result) == j);
            }

            SECTION("multi-byte, 2 bytes")
            {
                json j = "\xC2\xA3";
                std::vector<uint8_t> expected = {0xC2, 0xA3, 0xFF};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
                CHECK(json::from_bon8(result) == j);
            }

            SECTION("multi-byte, 3 bytes")
            {
                json j = "\xEF\xB8\xBB";
                std::vector<uint8_t> expected = {0xEF, 0xB8, 0xBB, 0xFF};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
                CHECK(json::from_bon8(result) == j);
            }

            SECTION("multi-byte, 4 bytes")
            {
                json j = "\xF0\x9F\x80\x84";
                std::vector<uint8_t> expected = {0xF0, 0x9F, 0x80, 0x84, 0xFF};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
                CHECK(json::from_bon8(result) == j);
            }

            SECTION("invalid string")
            {
                std::vector<uint8_t> v = {0xF0, 0x9F, 0x80, 0x84};
                json j;
                CHECK_THROWS_WITH_AS(j = json::from_bon8(v), "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing BON8 string: unexpected end of input", json::parse_error);
            }
        }

        SECTION("array")
        {
            SECTION("array with count")
            {
                SECTION("empty array")
                {
                    json j = json::array();
                    std::vector<uint8_t> expected = {0x80};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("[false]")
                {
                    json j = {false};
                    std::vector<uint8_t> expected = {0x81, 0xF8};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("[false, null]")
                {
                    json j = {false, nullptr};
                    std::vector<uint8_t> expected = {0x82, 0xF8, 0xFA};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("[false, null, true]")
                {
                    json j = {false, nullptr, true};
                    std::vector<uint8_t> expected = {0x83, 0xF8, 0xFA, 0xF9};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("[false, null, true, 1.0]")
                {
                    json j = {false, nullptr, true, 1.0};
                    std::vector<uint8_t> expected = {0x84, 0xF8, 0xFA, 0xF9, 0xFD};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("[\"s\", \"s\"]")
                {
                    json j = {"s", "s"};
                    std::vector<uint8_t> expected = {0x82, 's', 0xFF, 's', 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("[\"\", \"s\"]")
                {
                    json j = {"", "s"};
                    std::vector<uint8_t> expected = {0x82, 0xFF, 's', 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("[[[\"foo\"]]]")
                {
                    json j = R"([[["foo"]]])"_json;
                    std::vector<uint8_t> expected = {0x81, 0x81, 0x81, 'f', 'o', 'o', 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("[[[1]]]")
                {
                    json j = R"([[[1]]])"_json;
                    std::vector<uint8_t> expected = {0x81, 0x81, 0x81, 0x91};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("[[[\"\"]]]")
                {
                    json j = R"([[[""]]])"_json;
                    std::vector<uint8_t> expected = {0x81, 0x81, 0x81, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }

            SECTION("array without count")
            {
                SECTION("[false, null, true, 1.0, [], 0.0]")
                {
                    json j = {false, nullptr, true, 1.0, json::array(), 0.0};
                    std::vector<uint8_t> expected = {0x85, 0xF8, 0xFA, 0xF9, 0xFD, 0x80, 0xFC, 0xFE};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }
        }

        SECTION("object")
        {
            SECTION("object with count")
            {
                SECTION("empty object")
                {
                    json j = json::object();
                    std::vector<uint8_t> expected = {0x86};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("{\"foo\": null}")
                {
                    json j = {{"foo", nullptr}};
                    std::vector<uint8_t> expected = {0x87, 'f', 'o', 'o', 0xFA};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("{\"\": true, \"foo\": null}")
                {
                    json j = {{"", true}, {"foo", nullptr}};
                    std::vector<uint8_t> expected = {0x88, 0xFF, 0xF9, 'f', 'o', 'o', 0xFA};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }

                SECTION("{\"a\": \"\", \"c\": \"d\"}")
                {
                    json j = {{"a", ""}, {"c", "d"}};
                    std::vector<uint8_t> expected = {0x88, 'a', 0xFF, 0xFF, 'c', 0xFF, 'd', 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("{\"a\": \"b\", \"c\": \"d\"}")
                {
                    json j = {{"a", "b"}, {"c", "d"}};
                    std::vector<uint8_t> expected = {0x88, 'a', 0xFF, 'b', 0xFF, 'c', 0xFF, 'd', 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("object without count")
            {
                SECTION("{\"one\": 1, \"two\": 2, \"three\": 3, \"four\": 4, \"five\": 5}")
                {
                    json j = R"({"one": 1, "two": 2, "three": 3, "four": 4, "five": 5})"_json;
                    std::vector<uint8_t> expected = {0x8b, 'f', 'i', 'v', 'e', 0x95, 'f', 'o', 'u', 'r', 0x94, 'o', 'n', 'e', 0x91, 't', 'h', 'r', 'e', 'e', 0x93, 't', 'w', 'o', 0x92, 0xFE};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                    CHECK(json::from_bon8(result) == j);
                }
            }
        }
    }

    SECTION("SAX aborts")
    {
        SECTION("start_array(len)")
        {
            std::vector<uint8_t> v = {0x80};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("error in array with size")
        {
            std::vector<uint8_t> v = {0x81};
            SaxCountdown scp(1000);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("error in array without size")
        {
            std::vector<uint8_t> v = {0x85};
            SaxCountdown scp(1000);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("start_object(len)")
        {
            std::vector<uint8_t> v = {0x86};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("key()")
        {
            std::vector<uint8_t> v = {0x87, 'f', 'o', 'o', 0xFF, 0xFA};
            SaxCountdown scp(1);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("error in object with size")
        {
            std::vector<uint8_t> v = {0x87, 'f', 'o', 'o', 0xFF};
            SaxCountdown scp(1000);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("error in object without size")
        {
            std::vector<uint8_t> v = {0x8B, 'f', 'o', 'o', 0xFF};
            SaxCountdown scp(1000);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }
    }
}
