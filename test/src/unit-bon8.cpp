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
