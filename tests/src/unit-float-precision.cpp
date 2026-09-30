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

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace
{
template<typename BasicJsonType>
std::string dump_with_precision(const BasicJsonType& j, int precision, bool pretty_print = false)
{
    std::stringstream ss;
    nlohmann::detail::output_stream_adapter<char> adapter(ss);
    nlohmann::detail::serializer<BasicJsonType> s(adapter, ' ', pretty_print, false, pretty_print ? 2 : 0,
            nlohmann::detail::error_handler_t::strict, precision);
    s.dump(j);
    return ss.str();
}

// what an ostream writes with std::setprecision, which is specified as
// printf("%.*g"), plus the ".0" that marks a floating-point number in JSON
std::string expected_with_precision(double v, int precision)
{
    std::ostringstream ss;
    ss.imbue(std::locale::classic());
    ss << std::setprecision(precision) << v;
    std::string s = ss.str();

    // "%g" removes trailing zeros of the fraction, but macOS's printf keeps
    // them on exact ties in exponent notation ("5.40e+06" for 5405000)
    const auto dot = s.find('.');
    if (dot != std::string::npos)
    {
        const auto exp = (std::min)(s.find('e'), s.size());
        auto last = exp;
        while (s[last - 1] == '0')
        {
            --last;
        }
        if (last - 1 == dot)
        {
            --last;
        }
        s.erase(last, exp - last);
    }

    if (s.find_first_of(".e") == std::string::npos)
    {
        s += ".0";
    }
    return s;
}
} // namespace

TEST_CASE("serializer with float precision")
{
    SECTION("significant digits, rounded as by %.*g")
    {
        CHECK(dump_with_precision(json(3.141592653589793), 3) == "3.14");
        CHECK(dump_with_precision(json(3.141592653589793), 1) == "3.0");
        CHECK(dump_with_precision(json(1.9999), 3) == "2.0");
        CHECK(dump_with_precision(json(-1.9999), 3) == "-2.0");
        CHECK(dump_with_precision(json(0.000123456), 3) == "0.000123");
        CHECK(dump_with_precision(json(12345.678), 3) == "1.23e+04");
        CHECK(dump_with_precision(json(12345.678), 5) == "12346.0");
        CHECK(dump_with_precision(json(1.23456e30), 3) == "1.23e+30");
        CHECK(dump_with_precision(json(1.23456e-30), 3) == "1.23e-30");
        CHECK(dump_with_precision(json(0.0000123456), 2) == "1.2e-05");
        CHECK(dump_with_precision(json(42.0), 3) == "42.0");
        CHECK(dump_with_precision(json(100.0), 1) == "1e+02");
        CHECK(dump_with_precision(json(0.0), 3) == "0.0");
        CHECK(dump_with_precision(json(-0.0), 3) == "-0.0");
    }

    SECTION("the carry propagates")
    {
        CHECK(dump_with_precision(json(9.99), 2) == "10.0");
        CHECK(dump_with_precision(json(99.5), 2) == "1e+02");
        CHECK(dump_with_precision(json(0.0999), 2) == "0.1");
        CHECK(dump_with_precision(json(-0.0999), 2) == "-0.1");
        CHECK(dump_with_precision(json(9.99e15), 2) == "1e+16");
    }

    SECTION("ties are decided on the exact value, as by %.*g")
    {
        // 0.15 and 2.675 are stored slightly below the written value
        CHECK(dump_with_precision(json(0.15), 1) == "0.1");
        CHECK(dump_with_precision(json(2.675), 3) == "2.67");
        CHECK(dump_with_precision(json(-2.675), 3) == "-2.67");
        // exact ties round to even, and trailing zeros are removed
        CHECK(dump_with_precision(json(0.125), 2) == "0.12");
        CHECK(dump_with_precision(json(5405000.0), 3) == "5.4e+06");
        CHECK(dump_with_precision(json(9905.0), 3) == "9.9e+03");
        CHECK(dump_with_precision(json(9915.0), 3) == "9.92e+03");
    }

    SECTION("the digits match std::setprecision (and so printf's %.*g)")
    {
        std::mt19937_64 gen(42); // NOLINT(cert-msc32-c,cert-msc51-cpp)
        std::uniform_real_distribution<double> mantissa(1.0, 10.0);
        std::uniform_int_distribution<int> exponent(-30, 30);
        std::uniform_int_distribution<int> digits(1, 20);
        for (int i = 0; i < 100000; ++i)
        {
            // half of the values are short decimals, whose ties are the tricky case
            double v = mantissa(gen) * std::pow(10.0, exponent(gen));
            if (i % 2 == 0)
            {
                v = std::stod(expected_with_precision(v, 4));
            }
            const int p = digits(gen);
            CAPTURE(v);
            CAPTURE(p);
            CHECK(dump_with_precision(json(v), p) == expected_with_precision(v, p));
        }
    }

    SECTION("precision 0 is treated as 1, as by %.*g")
    {
        CHECK(dump_with_precision(json(3.141592653589793), 0) == "3.0");
        CHECK(dump_with_precision(json(0.000123456), 0) == "0.0001");
    }

    SECTION("large precisions write the exact value")
    {
        CHECK(dump_with_precision(json(0.1), 17) == "0.10000000000000001");
        CHECK(dump_with_precision(json(0.1), 20) == "0.10000000000000000555");
        CHECK(dump_with_precision(json(0.1), 1000) == "0.1000000000000000055511151231257827021181583404541015625");
        CHECK(dump_with_precision(json(0.1), (std::numeric_limits<int>::max)()) == "0.1000000000000000055511151231257827021181583404541015625");

        // the longest exact double: 751 significant digits
        const std::string denorm_min = dump_with_precision(json((std::numeric_limits<double>::denorm_min)()), 1000);
        CHECK(denorm_min.size() == 757);
        CHECK(denorm_min.substr(0, 20) == "4.940656458412465441");
        CHECK(denorm_min.substr(denorm_min.size() - 11) == "265625e-324");
        CHECK(json::parse(denorm_min).get<double>() == (std::numeric_limits<double>::denorm_min)());
    }

    SECTION("a negative precision keeps the default output")
    {
        for (const double v :
                {
                    0.0, -0.0, 1.0, 0.1, 0.15, 3.141592653589793, 1e-7, 1e21, 12345.678,
                    (std::numeric_limits<double>::max)(), (std::numeric_limits<double>::min)(),
                    (std::numeric_limits<double>::denorm_min)()
                })
        {
            CAPTURE(v);
            CHECK(dump_with_precision(json(v), -1) == json(v).dump());
            CHECK(dump_with_precision(json(v), -42) == json(v).dump());
        }
    }

    SECTION("integers are written exactly")
    {
        CHECK(dump_with_precision(json(123456789), 3) == "123456789");
        CHECK(dump_with_precision(json(-123456789), 3) == "-123456789");
        CHECK(dump_with_precision(json((std::numeric_limits<std::uint64_t>::max)()), 3) == "18446744073709551615");
    }

    SECTION("NaN and infinity are still written as null")
    {
        CHECK(dump_with_precision(json(std::numeric_limits<double>::quiet_NaN()), 3) == "null");
        CHECK(dump_with_precision(json(std::numeric_limits<double>::infinity()), 3) == "null");
        CHECK(dump_with_precision(json(-std::numeric_limits<double>::infinity()), 3) == "null");
    }

    SECTION("applies to every number in a structure")
    {
        const json j = {{"pi", 3.141592653589793}, {"n", 12345}, {"a", {1.9999, 0.5, "2.71828"}}};
        CHECK(dump_with_precision(j, 3) == R"({"a":[2.0,0.5,"2.71828"],"n":12345,"pi":3.14})");
        CHECK(dump_with_precision(j, 3, true) ==
              "{\n"
              "  \"a\": [\n"
              "    2.0,\n"
              "    0.5,\n"
              "    \"2.71828\"\n"
              "  ],\n"
              "  \"n\": 12345,\n"
              "  \"pi\": 3.14\n"
              "}");
    }

    SECTION("float as number_float_t")
    {
        // digits of the float's exact value
        using float_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;
        CHECK(dump_with_precision(float_json(3.14159265f), 3) == "3.14");
        CHECK(dump_with_precision(float_json(2.675f), 3) == "2.67");
        CHECK(dump_with_precision(float_json(0.1f), 9) == "0.100000001");
        CHECK(dump_with_precision(float_json(0.1f), 100) == "0.100000001490116119384765625");
        CHECK(dump_with_precision(float_json(0.1f), -1) == float_json(0.1f).dump());
    }

    SECTION("long double as number_float_t")
    {
        using long_double_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, long double>;
        CHECK(dump_with_precision(long_double_json(3.141592653589793238L), 3) == "3.14");
        CHECK(dump_with_precision(long_double_json(1.9999L), 3) == "2.0");
        CHECK(dump_with_precision(long_double_json(12345.678L), 3) == "1.23e+04");
        CHECK(dump_with_precision(long_double_json(0.5L), 1000) == "0.5");
        CHECK(dump_with_precision(long_double_json(0.1L), -1) == long_double_json(0.1L).dump());
    }
}
