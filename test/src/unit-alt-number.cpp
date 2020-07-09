/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.8.0
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2018 Vitaliy Manushkin <agri@akamo.info>.

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

TEST_CASE("Alternative number types")
{
    SECTION("8 bit integers")
    {
        using json8 = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int8_t, std::uint8_t>;

        SECTION("unsigned")
        {
            std::uint8_t unsigned_max = 255;
            json8 j_unsigned_max = json8::parse("255");
            CHECK(j_unsigned_max.is_number_unsigned());
            CHECK(j_unsigned_max.dump() == "255");
            CHECK((j_unsigned_max.get<std::uint8_t>() == unsigned_max));
            CHECK(json8::parse(j_unsigned_max.dump()) == j_unsigned_max);

            json8 j_overflow = json8::parse("256");
            CHECK(j_overflow.is_number_float());
            CHECK(j_overflow.dump() == "256.0");
        }

        SECTION("signed")
        {
            std::int8_t signed_min = -128;
            json8 j_signed_min = json8::parse("-128");
            CHECK(j_signed_min.is_number_integer());
            CHECK(j_signed_min.dump() == "-128");
            CHECK((j_signed_min.get<std::int8_t>() == signed_min));
            CHECK(json8::parse(j_signed_min.dump()) == j_signed_min);

            json8 j_underflow = json8::parse("-129");
            CHECK(j_underflow.is_number_float());
            CHECK(j_underflow.dump() == "-129.0");
        }
    }

    SECTION("16 bit integers")
    {
        using json16 = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int16_t, std::uint16_t>;

        SECTION("unsigned")
        {
            std::uint16_t unsigned_max = 65535;
            json16 j_unsigned_max = json16::parse("65535");
            CHECK(j_unsigned_max.is_number_unsigned());
            CHECK(j_unsigned_max.dump() == "65535");
            CHECK((j_unsigned_max.get<std::uint16_t>() == unsigned_max));
            CHECK(json16::parse(j_unsigned_max.dump()) == j_unsigned_max);

            json16 j_overflow = json16::parse("65536");
            CHECK(j_overflow.is_number_float());
            CHECK(j_overflow.dump() == "65536.0");
        }

        SECTION("signed")
        {
            std::int16_t signed_min = -32768;
            json16 j_signed_min = json16::parse("-32768");
            CHECK(j_signed_min.is_number_integer());
            CHECK(j_signed_min.dump() == "-32768");
            CHECK((j_signed_min.get<std::int16_t>() == signed_min));
            CHECK(json16::parse(j_signed_min.dump()) == j_signed_min);

            json16 j_underflow = json16::parse("-32769");
            CHECK(j_underflow.is_number_float());
            CHECK(j_underflow.dump() == "-32769.0");
        }
    }

#ifdef __SIZEOF_INT128__
    SECTION("128 bit integers")
    {
        using json128 = nlohmann::basic_json<std::map, std::vector, std::string, bool, __int128_t, __uint128_t>;

        SECTION("unsigned")
        {
            __uint128_t unsigned_max = (340282366920938463463.374607431768211455) * std::pow(10, 18);
            json128 j_unsigned_max = json128::parse("340282366920938463463374607431768211455");
            CHECK(j_unsigned_max.is_number_unsigned());
            CHECK(j_unsigned_max.dump() == "340282366920938463463374607431768211455");
            CHECK((j_unsigned_max.get<__uint128_t>() == unsigned_max));
            CHECK(json128::parse(j_unsigned_max.dump()) == j_unsigned_max);
        }

        SECTION("signed")
        {
            __int128_t signed_min = (-170141183460469231731.687303715884105728) * std::pow(10, 18);
            json128 j_signed_min = json128::parse("-170141183460469231731687303715884105728");
            CHECK(j_signed_min.is_number_integer());
            CHECK(j_signed_min.dump() == "-170141183460469231731687303715884105728");
            CHECK((j_signed_min.get<__int128_t>() == signed_min));
            CHECK(json128::parse(j_signed_min.dump()) == j_signed_min);
        }
    }
#endif
}
