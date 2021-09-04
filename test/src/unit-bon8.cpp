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

#include <iostream>
#include <fstream>
#include <set>
#include <test_data.hpp>
#include "test_utils.hpp"

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
        }

        SECTION("boolean")
        {
            SECTION("true")
            {
                json j = true;
                std::vector<uint8_t> expected = {0xF9};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
            }

            SECTION("false")
            {
                json j = false;
                std::vector<uint8_t> expected = {0xF8};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
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
                }

                SECTION("39")
                {
                    json j = 39U;
                    std::vector<uint8_t> expected = {0xB7};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("40..3839")
            {
                SECTION("40")
                {
                    json j = 40U;
                    std::vector<uint8_t> expected = {0xC2, 0x28};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("3839")
                {
                    json j = 3839U;
                    std::vector<uint8_t> expected = {0xDF, 0x7F};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("3840..524287")
            {
                SECTION("3840")
                {
                    json j = 3840U;
                    std::vector<uint8_t> expected = {0xE0, 0x0F, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("524287")
                {
                    json j = 524287U;
                    std::vector<uint8_t> expected = {0xEF, 0x7F, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("524288..67108863")
            {
                SECTION("524288")
                {
                    json j = 524288U;
                    std::vector<uint8_t> expected = {0xF0, 0x08, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("67108863")
                {
                    json j = 67108863U;
                    std::vector<uint8_t> expected = {0xF7, 0x7F, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("67108864..2147483647 (int32max)")
            {
                SECTION("67108864")
                {
                    json j = 67108864U;
                    std::vector<uint8_t> expected = {0x8C, 0x04, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("2147483647 (int32max)")
                {
                    json j = 2147483647U;
                    std::vector<uint8_t> expected = {0x8C, 0x7F, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
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
                }

                SECTION("9223372036854775807 (int64max)")
                {
                    json j = 9223372036854775807U;
                    std::vector<uint8_t> expected = {0x8D, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
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
                }

                SECTION("-2147483649")
                {
                    // cannot use -2147483649 directly, see https://developercommunity.visualstudio.com/t/-2147483648-c4146-error/141813#T-N229960
                    json j = std::int64_t(-2147483647) - 2;
                    std::vector<uint8_t> expected = {0x8D, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("-2147483648 (int32min)..-33554433")
            {
                SECTION("-2147483648")
                {
                    // cannot use -2147483648 directly, see https://developercommunity.visualstudio.com/t/-2147483648-c4146-error/141813#T-N229960
                    json j = -2147483647 - 1;
                    std::vector<uint8_t> expected = {0x8C, 0x80, 0x00, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("-33554433")
                {
                    json j = -33554433;
                    std::vector<uint8_t> expected = {0x8C, 0xFD, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("-33554432..-262145")
            {
                SECTION("-33554432")
                {
                    json j = -33554432;
                    std::vector<uint8_t> expected = {0xF7, 0xFF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("-262145")
                {
                    json j = -262145;
                    std::vector<uint8_t> expected = {0xF0, 0xC4, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("-262144..-1921")
            {
                SECTION("-262144")
                {
                    json j = -262144;
                    std::vector<uint8_t> expected = {0xEF, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("-1921")
                {
                    json j = -1921;
                    std::vector<uint8_t> expected = {0xE0, 0xC7, 0x80};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("-1920..-11")
            {
                SECTION("-1920")
                {
                    json j = -1920;
                    std::vector<uint8_t> expected = {0xDF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("-11")
                {
                    json j = -11;
                    std::vector<uint8_t> expected = {0xC2, 0xCA};
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
                }

                SECTION("-1")
                {
                    json j = -1;
                    std::vector<uint8_t> expected = {0xB8};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
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
                }

                SECTION("39")
                {
                    json j = 39;
                    std::vector<uint8_t> expected = {0xB7};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("40..3839")
            {
                SECTION("40")
                {
                    json j = 40;
                    std::vector<uint8_t> expected = {0xC2, 0x28};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("3839")
                {
                    json j = 3839;
                    std::vector<uint8_t> expected = {0xDF, 0x7F};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("3840..524287")
            {
                SECTION("3840")
                {
                    json j = 3840;
                    std::vector<uint8_t> expected = {0xE0, 0x0F, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("524287")
                {
                    json j = 524287;
                    std::vector<uint8_t> expected = {0xEF, 0x7F, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("524288..67108863")
            {
                SECTION("524288")
                {
                    json j = 524288;
                    std::vector<uint8_t> expected = {0xF0, 0x08, 0x00, 0x00};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("67108863")
                {
                    json j = 67108863;
                    std::vector<uint8_t> expected = {0xF7, 0x7F, 0xFF, 0xFF};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }

            SECTION("67108864..2147483647 (int32max)")
            {
                SECTION("67108864")
                {
                    json j = 67108864;
                    std::vector<uint8_t> expected = {0x8C, 0x04, 0x00, 0x00, 0x00};
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
            SECTION("-1.0")
            {
                json j = -1.0;
                std::vector<uint8_t> expected = {0xFB};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
            }

            SECTION("0.0")
            {
                json j = 0.0;
                std::vector<uint8_t> expected = {0xFC};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
            }

            SECTION("1.0")
            {
                json j = 1.0;
                std::vector<uint8_t> expected = {0xFD};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
            }

            SECTION("-0.0")
            {
                json j = -0.0;
                std::vector<uint8_t> expected = {0x8E, 0x80, 0x00, 0x00, 0x00};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
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
            }

            SECTION("other strings")
            {
                json j = "This is a string.";
                std::vector<uint8_t> expected = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 's', 't', 'r', 'i', 'n', 'g', '.'};
                const auto result = json::to_bon8(j);
                CHECK(result == expected);
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
                }

                SECTION("[false]")
                {
                    json j = {false};
                    std::vector<uint8_t> expected = {0x81, 0xF8};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("[false, null]")
                {
                    json j = {false, nullptr};
                    std::vector<uint8_t> expected = {0x82, 0xF8, 0xFA};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("[false, null, true]")
                {
                    json j = {false, nullptr, true};
                    std::vector<uint8_t> expected = {0x83, 0xF8, 0xFA, 0xF9};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("[false, null, true, 1.0]")
                {
                    json j = {false, nullptr, true, 1.0};
                    std::vector<uint8_t> expected = {0x84, 0xF8, 0xFA, 0xF9, 0xFD};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("[\"s\", \"s\"]")
                {
                    json j = {"s", "s"};
                    std::vector<uint8_t> expected = {0x82, 's', 0xFF, 's'};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("[\"\", \"s\"]")
                {
                    json j = {"", "s"};
                    std::vector<uint8_t> expected = {0x82, 0xFF, 's'};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
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
                }

                SECTION("{\"foo\": null}")
                {
                    json j = {{"foo", nullptr}};
                    std::vector<uint8_t> expected = {0x87, 'f', 'o', 'o', 0xFA};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("{\"\": true, \"foo\": null}")
                {
                    json j = {{"", true}, {"foo", nullptr}};
                    std::vector<uint8_t> expected = {0x88, 0xFF, 0xF9, 'f', 'o', 'o', 0xFA};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }

                SECTION("{\"a\": \"\", \"c\": \"d\"}")
                {
                    json j = {{"a", ""}, {"c", "d"}};
                    std::vector<uint8_t> expected = {0x88, 'a', 0xFF, 0xFF, 'c', 0xFF, 'd'};
                    const auto result = json::to_bon8(j);
                    CHECK(result == expected);
                }
            }
        }
    }
}
