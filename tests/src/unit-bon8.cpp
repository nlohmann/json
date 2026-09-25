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
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <cmath>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
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

using bytes = std::vector<std::uint8_t>;

/// check that @a j is serialized to @a expected and that @a expected is read back as @a j
void check_bon8(const json& j, const bytes& expected)
{
    CAPTURE(j)
    CHECK(json::to_bon8(j) == expected);

    const json read = json::from_bon8(expected);
    CHECK(read == j);
    // integers are not read back as floats and vice versa
    CHECK(read.type() == j.type());
}

/// @return the string with the given bytes
std::string str(const bytes& b)
{
    return {b.begin(), b.end()};
}

/// @return @a b followed by @a tail
bytes concat(bytes b, const bytes& tail)
{
    b.insert(b.end(), tail.begin(), tail.end());
    return b;
}
} // namespace

TEST_CASE("BON8")
{
    SECTION("individual values")
    {
        SECTION("discarded")
        {
            // discarded values are not serialized
            const json j = json::value_t::discarded;
            CHECK(json::to_bon8(j).empty());
        }

        SECTION("null")
        {
            check_bon8(nullptr, {0xFA});
        }

        SECTION("boolean")
        {
            check_bon8(true, {0xF9});
            check_bon8(false, {0xF8});
        }

        SECTION("integers")
        {
            // test vectors from HikoGUI (src/hikogui/codec/BON8_tests.cpp,
            // Copyright Take Vos 2021, Boost Software License 1.0), which
            // cover the first and last value of each encoding
            SECTION("positive")
            {
                check_bon8(0u, {0x90});
                check_bon8(39u, {0xB7});
                check_bon8(40u, {0xC2, 0x00});
                check_bon8(3879u, {0xDF, 0x7F});
                check_bon8(3880u, {0xE0, 0x00, 0x00});
                check_bon8(528167u, {0xEF, 0x7F, 0xFF});
                check_bon8(528168u, {0xF0, 0x00, 0x00, 0x00});
                check_bon8(67637031u, {0xF7, 0x7F, 0xFF, 0xFF});
                check_bon8(67637032u, {0x8C, 0x04, 0x08, 0x0F, 0x28});
                check_bon8(2147483647u, {0x8C, 0x7F, 0xFF, 0xFF, 0xFF});
                check_bon8(2147483648u, {0x8D, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00});
                check_bon8(9223372036854775807u, {0x8D, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
            }

            SECTION("negative")
            {
                check_bon8(-1, {0xB8});
                check_bon8(-10, {0xC1});
                check_bon8(-11, {0xC2, 0xC0});
                check_bon8(-1930, {0xDF, 0xFF});
                check_bon8(-1931, {0xE0, 0xC0, 0x00});
                check_bon8(-264074, {0xEF, 0xFF, 0xFF});
                check_bon8(-264075, {0xF0, 0xC0, 0x00, 0x00});
                check_bon8(-33818506, {0xF7, 0xFF, 0xFF, 0xFF});
                check_bon8(-33818507, {0x8C, 0xFD, 0xFB, 0xF8, 0x75});
                check_bon8(-2147483648, {0x8C, 0x80, 0x00, 0x00, 0x00});
                check_bon8(-2147483649, {0x8D, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF});
                check_bon8((std::numeric_limits<std::int64_t>::min)(), {0x8D, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            }

            SECTION("values inside the ranges")
            {
                check_bon8(1u, {0x91});
                check_bon8(100u, {0xC2, 0x3C});
                check_bon8(1000u, {0xC9, 0x40});
                check_bon8(100000u, {0xE2, 0x77, 0x78});
                check_bon8(1000000u, {0xF0, 0x07, 0x33, 0x18});
                check_bon8(-9, {0xC0});
                check_bon8(-100, {0xC3, 0xD9});
                check_bon8(-100000, {0xE5, 0xFF, 0x15});
                check_bon8(-1000000, {0xF0, 0xCB, 0x3A, 0xB5});
            }

            SECTION("every integer from -300000 to 600000")
            {
                for (std::int64_t i = -300000; i <= 600000; ++i)
                {
                    const json j = i;
                    const auto packed = json::to_bon8(j);
                    CHECK(packed.size() == (i >= -10 && i <= 39 ? 1u : i >= -1930 && i <= 3879 ? 2u : i >= -264074 && i <= 528167 ? 3u : 4u));
                    const json read = json::from_bon8(packed);
                    if (read != j)
                    {
                        CAPTURE(i)
                        CHECK(read == j);
                    }
                }
            }

            SECTION("signed values are read back as unsigned when not negative")
            {
                const json j = json::from_bon8(json::to_bon8(json(std::int64_t(1000))));
                CHECK(j.is_number_unsigned());
                CHECK(j == 1000);
            }

            SECTION("unsigned integers above int64")
            {
                json _;
                const json j = 9223372036854775808u;
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(j), "[json.exception.out_of_range.407] integer number 9223372036854775808 cannot be represented by BON8 as it does not fit int64", json::out_of_range&);
            }
        }

        SECTION("floating-point numbers")
        {
            SECTION("one-byte values")
            {
                check_bon8(-1.0, {0xFB});
                check_bon8(0.0, {0xFC});
                check_bon8(1.0, {0xFD});
            }

            SECTION("binary32")
            {
                check_bon8(2.0, {0x8E, 0x40, 0x00, 0x00, 0x00});
                check_bon8(0.5, {0x8E, 0x3F, 0x00, 0x00, 0x00});
                check_bon8(-1.5, {0x8E, 0xBF, 0xC0, 0x00, 0x00});
                check_bon8(3.4028234663852886e38, {0x8E, 0x7F, 0x7F, 0xFF, 0xFF});
            }

            SECTION("binary64")
            {
                check_bon8(100000000.1, {0x8F, 0x41, 0x97, 0xD7, 0x84, 0x00, 0x66, 0x66, 0x66});
                check_bon8(3.14159, {0x8F, 0x40, 0x09, 0x21, 0xF9, 0xF0, 0x1B, 0x86, 0x6E});
                check_bon8(1e300, {0x8F, 0x7E, 0x37, 0xE4, 0x3C, 0x88, 0x00, 0x75, 0x9C});
            }

            SECTION("-0.0 is written as binary32")
            {
                const json j = -0.0;
                CHECK(json::to_bon8(j) == bytes{0x8E, 0x80, 0x00, 0x00, 0x00});
                const json read = json::from_bon8(json::to_bon8(j));
                CHECK(read.get<double>() == 0.0);
                CHECK(std::signbit(read.get<double>()));
            }

            SECTION("infinity is written as binary32")
            {
                check_bon8(std::numeric_limits<double>::infinity(), {0x8E, 0x7F, 0x80, 0x00, 0x00});
                check_bon8(-std::numeric_limits<double>::infinity(), {0x8E, 0xFF, 0x80, 0x00, 0x00});
            }

            SECTION("NaN is written as binary32 0x7F800001")
            {
                const json j = std::numeric_limits<double>::quiet_NaN();
                CHECK(json::to_bon8(j) == bytes{0x8E, 0x7F, 0x80, 0x00, 0x01});
                CHECK(std::isnan(json::from_bon8(json::to_bon8(j)).get<double>()));
            }
        }

        SECTION("strings")
        {
            SECTION("empty string")
            {
                check_bon8("", {0xFF});
            }

            SECTION("ASCII")
            {
                check_bon8("a", {'a', 0xFF});
                check_bon8("This is a string.", concat(bytes{'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 's', 't', 'r', 'i', 'n', 'g', '.'}, {0xFF}));
                check_bon8(str({0x00}), {0x00, 0xFF});
                check_bon8(str({0x7F}), {0x7F, 0xFF});
            }

            SECTION("multi-byte UTF-8")
            {
                check_bon8("\xC2\xA3", {0xC2, 0xA3, 0xFF});                   // U+00A3
                check_bon8("\xEF\xB8\xBB", {0xEF, 0xB8, 0xBB, 0xFF});         // U+FE3B
                check_bon8("\xF0\x9F\x80\x84", {0xF0, 0x9F, 0x80, 0x84, 0xFF}); // U+1F004
                check_bon8("\xC2\x80", {0xC2, 0x80, 0xFF});                   // U+0080
                check_bon8("\xDF\xBF", {0xDF, 0xBF, 0xFF});                   // U+07FF
                check_bon8("\xE0\xA0\x80", {0xE0, 0xA0, 0x80, 0xFF});         // U+0800
                check_bon8("\xED\x9F\xBF", {0xED, 0x9F, 0xBF, 0xFF});         // U+D7FF
                check_bon8("\xEE\x80\x80", {0xEE, 0x80, 0x80, 0xFF});         // U+E000
                check_bon8("\xF0\x90\x80\x80", {0xF0, 0x90, 0x80, 0x80, 0xFF}); // U+10000
                check_bon8("\xF4\x8F\xBF\xBF", {0xF4, 0x8F, 0xBF, 0xBF, 0xFF}); // U+10FFFF
                check_bon8("a\xC2\xA3" "b", {'a', 0xC2, 0xA3, 'b', 0xFF});
            }

            SECTION("invalid UTF-8 cannot be written")
            {
                json _;
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(str({0x80})), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0x80", json::type_error&);
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(str({'a', 0xC0, 0x80})), "[json.exception.type_error.316] invalid UTF-8 byte at index 1: 0xC0", json::type_error&);
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(str({0xE0, 0x80, 0x80})), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xE0", json::type_error&);
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(str({0xED, 0xA0, 0x80})), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xED", json::type_error&);
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(str({0xF4, 0x90, 0x80, 0x80})), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xF4", json::type_error&);
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(str({0xF5, 0x80, 0x80, 0x80})), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xF5", json::type_error&);
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(str({0xC2, 'a'})), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xC2", json::type_error&);
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(str({'a', 0xE2, 0x82})), "[json.exception.type_error.316] invalid UTF-8 byte at index 1: 0xE2", json::type_error&);
                CHECK_THROWS_WITH_AS(_ = json::to_bon8(json::object({{str({0xFF}), 1}})), "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF", json::type_error&);
            }
        }

        SECTION("arrays")
        {
            check_bon8(json::array(), {0x80});
            check_bon8({false}, {0x81, 0xF8});
            check_bon8({false, nullptr}, {0x82, 0xF8, 0xFA});
            check_bon8({false, nullptr, true}, {0x83, 0xF8, 0xFA, 0xF9});
            check_bon8({false, nullptr, true, 1.0}, {0x84, 0xF8, 0xFA, 0xF9, 0xFD});
            check_bon8({false, nullptr, true, 1.0, json::array(), 0.0}, {0x85, 0xF8, 0xFA, 0xF9, 0xFD, 0x80, 0xFC, 0xFE});
            check_bon8({{{1}}}, {0x81, 0x81, 0x81, 0x91});
            check_bon8({{{"foo"}}}, {0x81, 0x81, 0x81, 'f', 'o', 'o', 0xFF});
            check_bon8({{{""}}}, {0x81, 0x81, 0x81, 0xFF});

            SECTION("large array")
            {
                json j = json::array();
                bytes expected = {0x85};
                for (int i = 0; i < 1000; ++i)
                {
                    j.push_back(nullptr);
                    expected.push_back(0xFA);
                }
                expected.push_back(0xFE);
                check_bon8(j, expected);
            }
        }

        SECTION("objects")
        {
            check_bon8(json::object(), {0x86});
            check_bon8({{"foo", nullptr}}, {0x87, 'f', 'o', 'o', 0xFA});
            check_bon8({{"", true}, {"foo", nullptr}}, {0x88, 0xFF, 0xF9, 'f', 'o', 'o', 0xFA});
            check_bon8({{"a", 1}, {"b", 2}, {"c", 3}}, {0x89, 'a', 0x91, 'b', 0x92, 'c', 0x93});
            check_bon8({{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}}, {0x8A, 'a', 0x91, 'b', 0x92, 'c', 0x93, 'd', 0x94});
            const json five = {{"one", 1}, {"two", 2}, {"three", 3}, {"four", 4}, {"five", 5}};
            check_bon8(five, {0x8B, 'f', 'i', 'v', 'e', 0x95, 'f', 'o', 'u', 'r', 0x94, 'o', 'n', 'e', 0x91, 't', 'h', 'r', 'e', 'e', 0x93, 't', 'w', 'o', 0x92, 0xFE});
        }

        SECTION("binary values are written as arrays of integers")
        {
            CHECK(json::to_bon8(json::binary({})) == bytes{0x80});
            CHECK(json::to_bon8(json::binary({0x00, 0x27, 0x28, 0xFF})) == bytes{0x84, 0x90, 0xB7, 0xC2, 0x00, 0xC3, 0x57});
            CHECK(json::to_bon8(json::binary({1, 2, 3, 4, 5}, 42)) == bytes{0x85, 0x91, 0x92, 0x93, 0x94, 0x95, 0xFE});
            CHECK(json::to_bon8({"a", json::binary({1})}) == bytes{0x82, 'a', 0x81, 0x91});
            CHECK(json::from_bon8(json::to_bon8(json::binary({1, 2, 3, 4, 5}))) == json({1, 2, 3, 4, 5}));
        }
    }

    SECTION("examples from the specification")
    {
        check_bon8("ab", {'a', 'b', 0xFF});
        check_bon8({"ab", "bc"}, {0x82, 'a', 'b', 0xFF, 'b', 'c', 0xFF});
        check_bon8({"a", "b", "c", "d", "e"}, {0x85, 'a', 0xFF, 'b', 0xFF, 'c', 0xFF, 'd', 0xFF, 'e', 0xFE});
        check_bon8({{"ab", 1}, {"bc", 2}}, {0x88, 'a', 'b', 0x91, 'b', 'c', 0x92});
        // the specification prints this example without the end-of-string
        // markers after "b" and "c", which its own rules require: without
        // them, the bytes read as the single string "bcd"
        check_bon8({{"a", {"b", "c"}}, {"d", 1}}, {0x88, 'a', 0x82, 'b', 0xFF, 'c', 0xFF, 'd', 0x91});
        check_bon8({{"", 1}, {"a", 2}}, {0x88, 0xFF, 0x91, 'a', 0x92});
    }

    SECTION("examples from the discussion of the specification (#2980)")
    {
        check_bon8({{"a", ""}, {"c", "d"}}, {0x88, 'a', 0xFF, 0xFF, 'c', 0xFF, 'd', 0xFF});
    }

    SECTION("end of strings")
    {
        SECTION("a string ends at the first byte of an integer")
        {
            check_bon8({{"a", 100}}, {0x87, 'a', 0xC2, 0x3C});
            check_bon8({{"a", -9}}, {0x87, 'a', 0xC0});
            check_bon8({{"a", -10}}, {0x87, 'a', 0xC1});
            check_bon8({{"a", 5}}, {0x87, 'a', 0x95});
            check_bon8({{"a", 100000}}, {0x87, 'a', 0xE2, 0x77, 0x78});
            check_bon8({{"a", -1000000}}, {0x87, 'a', 0xF0, 0xCB, 0x3A, 0xB5});
            check_bon8({{"a", 67637032}}, {0x87, 'a', 0x8C, 0x04, 0x08, 0x0F, 0x28});
            check_bon8({{"a", 2147483648}}, {0x87, 'a', 0x8D, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00});
            check_bon8({"\xC2\xA3", 100}, {0x82, 0xC2, 0xA3, 0xC2, 0x3C});
            check_bon8({"\xF0\x9F\x80\x84", -1000000}, {0x82, 0xF0, 0x9F, 0x80, 0x84, 0xF0, 0xCB, 0x3A, 0xB5});
        }

        SECTION("a string ends at the first byte of other values")
        {
            check_bon8({"a", 2.0}, {0x82, 'a', 0x8E, 0x40, 0x00, 0x00, 0x00});
            check_bon8({"a", 0.1}, {0x82, 'a', 0x8F, 0x3F, 0xB9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9A});
            check_bon8({"a", nullptr, "b", true, "c", false}, {0x85, 'a', 0xFA, 'b', 0xF9, 'c', 0xF8, 0xFE});
            check_bon8({"a", -1.0, "b", 0.0, "c", 1.0}, {0x85, 'a', 0xFB, 'b', 0xFC, 'c', 0xFD, 0xFE});
            check_bon8({"a", json::array()}, {0x82, 'a', 0x80});
            check_bon8({"a", json::object()}, {0x82, 'a', 0x86});
            check_bon8({{"a", {1, 2, 3, 4, 5}}}, {0x87, 'a', 0x85, 0x91, 0x92, 0x93, 0x94, 0x95, 0xFE});
            check_bon8({{"a", {{"b", 1}, {"c", 2}, {"d", 3}, {"e", 4}, {"f", 5}}}}, {0x87, 'a', 0x8B, 'b', 0x91, 'c', 0x92, 'd', 0x93, 'e', 0x94, 'f', 0x95, 0xFE});
        }

        SECTION("a string ends at the end of its container")
        {
            check_bon8({1, 2, 3, 4, "e"}, {0x85, 0x91, 0x92, 0x93, 0x94, 'e', 0xFE});
            check_bon8({{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}, {"e", "f"}}, {0x8B, 'a', 0x91, 'b', 0x92, 'c', 0x93, 'd', 0x94, 'e', 0xFF, 'f', 0xFE});
            check_bon8({{1, 2, 3, 4, "e"}, 1}, {0x82, 0x85, 0x91, 0x92, 0x93, 0x94, 'e', 0xFE, 0x91});
            check_bon8({{1, 2, 3, 4, "\xC2\xA3"}, 100}, {0x82, 0x85, 0x91, 0x92, 0x93, 0x94, 0xC2, 0xA3, 0xFE, 0xC2, 0x3C});
        }

        SECTION("a string that another string follows is terminated")
        {
            check_bon8({"s", "s"}, {0x82, 's', 0xFF, 's', 0xFF});
            check_bon8({"", "s"}, {0x82, 0xFF, 's', 0xFF});
            check_bon8({"s", ""}, {0x82, 's', 0xFF, 0xFF});
            check_bon8({"", ""}, {0x82, 0xFF, 0xFF});
            check_bon8({{"a", "b"}, {"c", "d"}}, {0x88, 'a', 0xFF, 'b', 0xFF, 'c', 0xFF, 'd', 0xFF});
            check_bon8({{"a", ""}}, {0x87, 'a', 0xFF, 0xFF});
            check_bon8({{"", ""}}, {0x87, 0xFF, 0xFF});
        }

        SECTION("a container that ends with a string and that a string follows")
        {
            check_bon8({{"a"}, "b"}, {0x82, 0x81, 'a', 0xFF, 'b', 0xFF});
            check_bon8({{{{"a"}}}, "b"}, {0x82, 0x81, 0x81, 0x81, 'a', 0xFF, 'b', 0xFF});
            check_bon8({{"a", {"x"}}, {"b", 1}}, {0x88, 'a', 0x81, 'x', 0xFF, 'b', 0x91});
            check_bon8({{"a", {{"b", "c"}}}, {"d", 1}}, {0x88, 'a', 0x87, 'b', 0xFF, 'c', 0xFF, 'd', 0x91});
            check_bon8({{"a"}, {"b"}}, {0x82, 0x81, 'a', 0x81, 'b', 0xFF});
        }

        SECTION("a string that ends the message is terminated")
        {
            check_bon8({"a"}, {0x81, 'a', 0xFF});
            check_bon8({{"a", "b"}}, {0x87, 'a', 0xFF, 'b', 0xFF});
            check_bon8({{{"a"}}}, {0x81, 0x81, 0x81, 'a', 0xFF});
        }
    }

    SECTION("non-canonical input is accepted")
    {
        // an integer with a longer encoding than necessary
        CHECK(json::from_bon8(bytes{0x8C, 0x00, 0x00, 0x00, 0x01}) == 1);
        CHECK(json::from_bon8(bytes{0x8D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) == -1);
        // a float with a longer encoding than necessary
        CHECK(json::from_bon8(bytes{0x8F, 0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) == 1.0);
        CHECK(json::from_bon8(bytes{0x8E, 0x00, 0x00, 0x00, 0x00}) == 0.0);
        // an unsized container with few elements
        CHECK(json::from_bon8(bytes{0x85, 0x91, 0x92, 0xFE}) == json({1, 2}));
        CHECK(json::from_bon8(bytes{0x85, 0xFE}) == json::array());
        CHECK(json::from_bon8(bytes{0x8B, 'a', 0x91, 0xFE}) == json({{"a", 1}}));
        // unsorted keys
        CHECK(json::from_bon8(bytes{0x88, 'b', 0x91, 'a', 0x92}) == json({{"a", 2}, {"b", 1}}));
        // an end-of-string marker that is not needed
        CHECK(json::from_bon8(bytes{0x82, 'a', 0xFF, 0x91}) == json({"a", 1}));
        CHECK(json::from_bon8(bytes{0x87, 'a', 0xFF, 0x91}) == json({{"a", 1}}));
    }

    SECTION("types of values read")
    {
        CHECK(json::from_bon8(bytes{0x90}).is_number_unsigned());
        CHECK(json::from_bon8(bytes{0xC2, 0x00}).is_number_unsigned());
        CHECK(json::from_bon8(bytes{0x8C, 0x00, 0x00, 0x00, 0x00}).is_number_unsigned());
        CHECK(json::from_bon8(bytes{0xB8}).is_number_integer());
        CHECK(!json::from_bon8(bytes{0xB8}).is_number_unsigned());
        CHECK(json::from_bon8(bytes{0xC2, 0xC0}).is_number_integer());
        CHECK(json::from_bon8(bytes{0xFC}).is_number_float());
        CHECK(json::from_bon8(bytes{0x8E, 0x40, 0x00, 0x00, 0x00}).is_number_float());
        CHECK(json::from_bon8(bytes{0xFF}).is_string());
    }

    SECTION("errors")
    {
        json _;

        SECTION("empty input")
        {
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes()), "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing BON8 value: unexpected end of input", json::parse_error&);
            CHECK(json::from_bon8(bytes(), true, false).is_discarded());
        }

        SECTION("too short numbers")
        {
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x8C}), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x8C, 0x00, 0x00, 0x00}), "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x8D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), "[json.exception.parse_error.110] parse error at byte 9: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x8E, 0x00}), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x8F, 0x00}), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xC2}), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xE0, 0x00}), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xF0, 0x00, 0x00}), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x82, 'a', 0xF0, 0xC0}), "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing BON8 number: unexpected end of input", json::parse_error&);
        }

        SECTION("unterminated strings")
        {
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{'a'}), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BON8 string: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x81, 'a', 'b'}), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BON8 string: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xF0, 0x9F, 0x80, 0x84}), "[json.exception.parse_error.110] parse error at byte 5: syntax error while parsing BON8 string: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xF0, 0x9F, 0x80}), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BON8 string: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87, 'a'}), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 string: unexpected end of input", json::parse_error&);
        }

        SECTION("invalid UTF-8")
        {
            // overlong
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xE0, 0x80, 0x80, 0xFF}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 string: invalid UTF-8 byte: 0x80", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xF0, 0x80, 0x80, 0x80, 0xFF}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 string: invalid UTF-8 byte: 0x80", json::parse_error&);
            // surrogate
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xED, 0xA0, 0x80, 0xFF}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 string: invalid UTF-8 byte: 0xA0", json::parse_error&);
            // above U+10FFFF
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xF4, 0x90, 0x80, 0x80, 0xFF}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 string: invalid UTF-8 byte: 0x90", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xF5, 0x80, 0x80, 0x80, 0xFF}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 string: invalid UTF-8 byte: 0x80", json::parse_error&);
            // missing continuation byte
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xE2, 0x82, 'a', 0xFF}), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BON8 string: invalid UTF-8 byte: 0x61", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x81, 'a', 0xE2, 0x82, 'b'}), "[json.exception.parse_error.112] parse error at byte 5: syntax error while parsing BON8 string: invalid UTF-8 byte: 0x62", json::parse_error&);
        }

        SECTION("end-of-container marker where a value is expected")
        {
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0xFE}), "[json.exception.parse_error.112] parse error at byte 1: syntax error while parsing BON8 value: invalid byte: 0xFE", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x81, 0xFE}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 value: invalid byte: 0xFE", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x8B, 'a', 0xFE}), "[json.exception.parse_error.112] parse error at byte 3: syntax error while parsing BON8 value: invalid byte: 0xFE", json::parse_error&);
        }

        SECTION("keys that are not strings")
        {
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87, 0x91, 0x91}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 key: expected a string; last byte: 0x91", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87, 0xFA, 0x91}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 key: expected a string; last byte: 0xFA", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87, 0x80, 0x91}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 key: expected a string; last byte: 0x80", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87, 0xFE}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 key: expected a string; last byte: 0xFE", json::parse_error&);
            // an integer that begins with a UTF-8 lead byte
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87, 0xC2, 0x00, 0x91}), "[json.exception.parse_error.112] parse error at byte 2: syntax error while parsing BON8 key: expected a string; last byte: 0xC2", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x88, 'a', 0x91, 0xF0, 0xC0, 0x00, 0x00, 0x91}), "[json.exception.parse_error.112] parse error at byte 4: syntax error while parsing BON8 key: expected a string; last byte: 0xF0", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87}), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BON8 key: unexpected end of input", json::parse_error&);
        }

        SECTION("unterminated containers")
        {
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x82, 0x91}), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 value: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x85, 0x91}), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 value: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x8B, 'a', 0x91}), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BON8 key: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87, 'a'}), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 string: unexpected end of input", json::parse_error&);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(bytes{0x87, 'a', 0xFF}), "[json.exception.parse_error.110] parse error at byte 4: syntax error while parsing BON8 value: unexpected end of input", json::parse_error&);
        }

        SECTION("strict mode")
        {
            const bytes vec = {0x90, 0x90};
            CHECK(json::from_bon8(vec, false) == 0);
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(vec), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing BON8 value: expected end of input; last byte: 0x90", json::parse_error&);
            CHECK(json::from_bon8(vec, true, false).is_discarded());

            // the byte after a string that ends a container
            const bytes vec2 = {0x81, 'a', 0x90};
            CHECK(json::from_bon8(vec2, false) == json({"a"}));
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(vec2), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 value: expected end of input; last byte: 0x90", json::parse_error&);

            const bytes vec3 = {0x81, 'a', 0xC2, 0x00};
            CHECK(json::from_bon8(vec3, false) == json({"a"}));
            CHECK_THROWS_WITH_AS(_ = json::from_bon8(vec3), "[json.exception.parse_error.110] parse error at byte 3: syntax error while parsing BON8 value: expected end of input; last byte: 0xC2", json::parse_error&);
        }
    }

    SECTION("SAX aborts")
    {
        SECTION("start_array(len)")
        {
            const bytes v = {0x83, 0x91, 0x92, 0x93};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("start_array()")
        {
            const bytes v = {0x85, 0x91, 0xFE};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("end_array()")
        {
            const bytes v = {0x85, 0x91, 0xFE};
            SaxCountdown scp(2);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("start_object(len)")
        {
            const bytes v = {0x87, 'f', 'o', 'o', 0xF8};
            SaxCountdown scp(0);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("key()")
        {
            const bytes v = {0x87, 'f', 'o', 'o', 0xF8};
            SaxCountdown scp(1);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("end_object()")
        {
            const bytes v = {0x87, 'f', 'o', 'o', 0xF8};
            SaxCountdown scp(3);
            CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
        }

        SECTION("values")
        {
            const std::vector<bytes> values =
            {
                {0xFA}, {0xF9}, {0x91}, {0xB8}, {0xC2, 0x00}, {0xC2, 0xC0}, {0xE0, 0x00, 0x00},
                {0x8C, 0, 0, 0, 1}, {0x8D, 0, 0, 0, 0, 0, 0, 0, 1}, {0xFB}, {0xFC}, {0xFD},
                {0x8E, 0x40, 0, 0, 0}, {0x8F, 0x40, 0, 0, 0, 0, 0, 0, 0}, {'a', 0xFF}, {0xFF}
            };
            for (const auto& v : values)
            {
                SaxCountdown scp(0);
                CHECK(!json::sax_parse(v, &scp, json::input_format_t::bon8));
            }
        }
    }
}

// use this testcase outside [hide] to run it with Valgrind
TEST_CASE("BON8 nesting does not consume the call stack")
{
    // Note that deeply nested values must not be compared, copied or dumped
    // here: those operations are still recursive. Depth is measured by
    // descending instead.

    SECTION("an unterminated chain is reported, not crashed on")
    {
        json _;
        const bytes input(300000, 0x81);
        CHECK_THROWS_WITH_AS(_ = json::from_bon8(input), "[json.exception.parse_error.110] parse error at byte 300001: syntax error while parsing BON8 value: unexpected end of input", json::parse_error&);
        CHECK(json::from_bon8(input, true, false).is_discarded());
    }

    SECTION("a well-formed deep value is read through the SAX interface")
    {
        bytes input(300000, 0x85);
        input.push_back(0x91); // innermost value
        input.insert(input.end(), 300000, 0xFE);

        SaxCountdown accept_all(600001);
        CHECK(json::sax_parse(input, &accept_all, json::input_format_t::bon8));
    }

    SECTION("a well-formed deep value is read into a value")
    {
        const std::size_t depth = 10000;
        bytes input;
        for (std::size_t i = 0; i < depth; ++i)
        {
            input.push_back(0x87);
            input.push_back('a');
        }
        // the innermost key is followed by a string, so it is terminated
        input.push_back(0xFF);
        input.push_back('b');
        input.push_back(0xFF);

        json j = json::from_bon8(input);

        std::size_t measured = 0;
        const json* p = &j;
        while (p->is_object() && !p->empty())
        {
            p = &p->at("a");
            ++measured;
        }
        CHECK(measured == depth);
        CHECK(*p == "b");
    }
}

TEST_CASE("single BON8 roundtrip")
{
    SECTION("sample.json")
    {
        std::string const filename = TEST_DATA_DIRECTORY "/json_testsuite/sample.json";

        // parse JSON file
        std::ifstream f_json(filename);
        const json j1 = json::parse(f_json);

        // parse BON8 file
        auto packed = utils::read_binary_file(filename + ".bon8");
        json j2;
        CHECK_NOTHROW(j2 = json::from_bon8(packed));

        // compare parsed JSON values
        CHECK(j1 == j2);

        SECTION("roundtrips")
        {
            SECTION("std::ostringstream")
            {
                std::basic_ostringstream<char> ss;
                json::to_bon8(j1, ss);
                json j3 = json::from_bon8(ss.str());
                CHECK(j1 == j3);
            }

            SECTION("std::string")
            {
                std::string s;
                json::to_bon8(j1, s);
                json j3 = json::from_bon8(s);
                CHECK(j1 == j3);
            }
        }

        // check with different start index
        packed.insert(packed.begin(), 5, 0xff);
        CHECK(j1 == json::from_bon8(packed.begin() + 5, packed.end()));
    }
}

TEST_CASE("Parse BON8 directly from a file using iterator and sentinel")
{
    std::string const filename = TEST_DATA_DIRECTORY "/json_testsuite/sample.json.bon8";
    std::ifstream file(filename, std::ios::binary);
    const std::istreambuf_iterator<char> first(file);
    const json parsed = json::from_bon8(first, utils::istreambuf_sentinel{});
    CHECK((parsed.is_object() || parsed.is_array()));
}

TEST_CASE("BON8 roundtrips" * doctest::skip())
{
    SECTION("input from HikoGUI")
    {
        // The .bon8 files were created with the BON8 encoder of HikoGUI
        // (https://github.com/hikoworks/hikogui), the reference implementation
        // of the format. Both implementations sort object keys, so the output
        // is compared byte for byte.
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
                    TEST_DATA_DIRECTORY "/json_tests/pass3.json",
                    TEST_DATA_DIRECTORY "/regression/floats.json",
                    TEST_DATA_DIRECTORY "/regression/signed_ints.json",
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
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_pos_exponent.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_underflow.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_simple_int.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_simple_real.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_too_big_neg_int.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_too_big_pos_int.json",
                    TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_very_big_negative_int.json",
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

            // parse JSON file
            std::ifstream f_json(filename);
            const json j1 = json::parse(f_json);

            // parse BON8 file
            const auto packed = utils::read_binary_file(filename + ".bon8");

            {
                INFO_WITH_TEMP(filename + ": std::vector<uint8_t>");
                json j2;
                CHECK_NOTHROW(j2 = json::from_bon8(packed));
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": std::ifstream");
                std::ifstream f_bon8(filename + ".bon8", std::ios::binary);
                json j2;
                CHECK_NOTHROW(j2 = json::from_bon8(f_bon8));
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": iterator pair");
                json j2;
                CHECK_NOTHROW(j2 = json::from_bon8(packed.begin(), packed.end()));
                CHECK(j1 == j2);
            }

            {
                INFO_WITH_TEMP(filename + ": output adapters: std::vector<uint8_t>");
                std::vector<uint8_t> vec;
                json::to_bon8(j1, vec);
                CHECK(vec == packed);
            }
        }
    }
}

#ifdef JSON_HAS_CPP_17
TEST_CASE("BON8 with std::byte")
{
    SECTION("vector roundtrip")
    {
        const json original =
        {
            {"name", "test"},
            {"value", 42},
            {"array", {1, 2, 3}}
        };

        const std::vector<uint8_t> temp = json::to_bon8(original);
        std::vector<std::byte> bon8_data(temp.size());
        for (size_t i = 0; i < temp.size(); ++i)
        {
            bon8_data[i] = std::byte(temp[i]);
        }

        json from_bytes;
        CHECK_NOTHROW(from_bytes = json::from_bon8(bon8_data));
        CHECK(from_bytes == original);
    }

    SECTION("empty vector")
    {
        const std::vector<std::byte> empty_data;
        CHECK_THROWS_WITH_AS([&]()
        {
            [[maybe_unused]] auto result = json::from_bon8(empty_data);
            return true;
        }
        (),
        "[json.exception.parse_error.110] parse error at byte 1: syntax error while parsing BON8 value: unexpected end of input",
        json::parse_error&);
    }
}
#endif
