/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.4
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2016 Niels Lohmann <http://nlohmann.me>.

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

TEST_CASE("compliance tests from json.org")
{
    // test cases are from http://json.org/JSON_checker/

    SECTION("expected failures")
    {
        for (auto filename :
                {
                    //"test/data/json_tests/fail1.json",
                    "test/data/json_tests/fail2.json",
                    "test/data/json_tests/fail3.json",
                    "test/data/json_tests/fail4.json",
                    "test/data/json_tests/fail5.json",
                    "test/data/json_tests/fail6.json",
                    "test/data/json_tests/fail7.json",
                    "test/data/json_tests/fail8.json",
                    "test/data/json_tests/fail9.json",
                    "test/data/json_tests/fail10.json",
                    "test/data/json_tests/fail11.json",
                    "test/data/json_tests/fail12.json",
                    "test/data/json_tests/fail13.json",
                    "test/data/json_tests/fail14.json",
                    "test/data/json_tests/fail15.json",
                    "test/data/json_tests/fail16.json",
                    "test/data/json_tests/fail17.json",
                    //"test/data/json_tests/fail18.json",
                    "test/data/json_tests/fail19.json",
                    "test/data/json_tests/fail20.json",
                    "test/data/json_tests/fail21.json",
                    "test/data/json_tests/fail22.json",
                    "test/data/json_tests/fail23.json",
                    "test/data/json_tests/fail24.json",
                    "test/data/json_tests/fail25.json",
                    "test/data/json_tests/fail26.json",
                    "test/data/json_tests/fail27.json",
                    "test/data/json_tests/fail28.json",
                    "test/data/json_tests/fail29.json",
                    "test/data/json_tests/fail30.json",
                    "test/data/json_tests/fail31.json",
                    "test/data/json_tests/fail32.json",
                    "test/data/json_tests/fail33.json"
                })
        {
            CAPTURE(filename);
            json j;
            std::ifstream f(filename);
            CHECK_THROWS_AS(j << f, std::invalid_argument);
        }
    }

    SECTION("expected passes")
    {
        for (auto filename :
                {
                    "test/data/json_tests/pass1.json",
                    "test/data/json_tests/pass2.json",
                    "test/data/json_tests/pass3.json"
                })
        {
            CAPTURE(filename);
            json j;
            std::ifstream f(filename);
            CHECK_NOTHROW(j << f);
        }
    }
}

TEST_CASE("compliance tests from nativejson-benchmark")
{
    // test cases from https://github.com/miloyip/nativejson-benchmark/blob/master/src/main.cpp

    SECTION("doubles")
    {
        auto TEST_DOUBLE = [](const std::string & json_string, const double expected)
        {
            CAPTURE(json_string);
            CAPTURE(expected);
            CHECK(json::parse(json_string)[0].get<double>() == Approx(expected));
        };

        TEST_DOUBLE("[0.0]", 0.0);
        TEST_DOUBLE("[-0.0]", -0.0);
        TEST_DOUBLE("[1.0]", 1.0);
        TEST_DOUBLE("[-1.0]", -1.0);
        TEST_DOUBLE("[1.5]", 1.5);
        TEST_DOUBLE("[-1.5]", -1.5);
        TEST_DOUBLE("[3.1416]", 3.1416);
        TEST_DOUBLE("[1E10]", 1E10);
        TEST_DOUBLE("[1e10]", 1e10);
        TEST_DOUBLE("[1E+10]", 1E+10);
        TEST_DOUBLE("[1E-10]", 1E-10);
        TEST_DOUBLE("[-1E10]", -1E10);
        TEST_DOUBLE("[-1e10]", -1e10);
        TEST_DOUBLE("[-1E+10]", -1E+10);
        TEST_DOUBLE("[-1E-10]", -1E-10);
        TEST_DOUBLE("[1.234E+10]", 1.234E+10);
        TEST_DOUBLE("[1.234E-10]", 1.234E-10);
        TEST_DOUBLE("[1.79769e+308]", 1.79769e+308);
        TEST_DOUBLE("[2.22507e-308]", 2.22507e-308);
        TEST_DOUBLE("[-1.79769e+308]", -1.79769e+308);
        TEST_DOUBLE("[-2.22507e-308]", -2.22507e-308);
        TEST_DOUBLE("[4.9406564584124654e-324]", 4.9406564584124654e-324); // minimum denormal
        TEST_DOUBLE("[2.2250738585072009e-308]", 2.2250738585072009e-308); // Max subnormal double
        TEST_DOUBLE("[2.2250738585072014e-308]", 2.2250738585072014e-308); // Min normal positive double
        TEST_DOUBLE("[1.7976931348623157e+308]", 1.7976931348623157e+308); // Max double
        TEST_DOUBLE("[1e-10000]", 0.0);                                   // must underflow
        TEST_DOUBLE("[18446744073709551616]",
                    18446744073709551616.0);    // 2^64 (max of uint64_t + 1, force to use double)
        TEST_DOUBLE("[-9223372036854775809]",
                    -9223372036854775809.0);    // -2^63 - 1(min of int64_t + 1, force to use double)
        TEST_DOUBLE("[0.9868011474609375]",
                    0.9868011474609375);          // https://github.com/miloyip/rapidjson/issues/120
        TEST_DOUBLE("[123e34]", 123e34);                                  // Fast Path Cases In Disguise
        TEST_DOUBLE("[45913141877270640000.0]", 45913141877270640000.0);
        TEST_DOUBLE("[2.2250738585072011e-308]",
                    2.2250738585072011e-308);
        //TEST_DOUBLE("[1e-00011111111111]", 0.0);
        //TEST_DOUBLE("[-1e-00011111111111]", -0.0);
        TEST_DOUBLE("[1e-214748363]", 0.0);
        TEST_DOUBLE("[1e-214748364]", 0.0);
        //TEST_DOUBLE("[1e-21474836311]", 0.0);
        TEST_DOUBLE("[0.017976931348623157e+310]", 1.7976931348623157e+308); // Max double in another form

        // Since
        // abs((2^-1022 - 2^-1074) - 2.2250738585072012e-308) = 3.109754131239141401123495768877590405345064751974375599... ¡Á 10^-324
        // abs((2^-1022) - 2.2250738585072012e-308) = 1.830902327173324040642192159804623318305533274168872044... ¡Á 10 ^ -324
        // So 2.2250738585072012e-308 should round to 2^-1022 = 2.2250738585072014e-308
        TEST_DOUBLE("[2.2250738585072012e-308]",
                    2.2250738585072014e-308);

        // More closer to normal/subnormal boundary
        // boundary = 2^-1022 - 2^-1075 = 2.225073858507201136057409796709131975934819546351645648... ¡Á 10^-308
        TEST_DOUBLE("[2.22507385850720113605740979670913197593481954635164564e-308]",
                    2.2250738585072009e-308);
        TEST_DOUBLE("[2.22507385850720113605740979670913197593481954635164565e-308]",
                    2.2250738585072014e-308);

        // 1.0 is in (1.0 - 2^-54, 1.0 + 2^-53)
        // 1.0 - 2^-54 = 0.999999999999999944488848768742172978818416595458984375
        TEST_DOUBLE("[0.999999999999999944488848768742172978818416595458984375]", 1.0); // round to even
        TEST_DOUBLE("[0.999999999999999944488848768742172978818416595458984374]",
                    0.99999999999999989); // previous double
        TEST_DOUBLE("[0.999999999999999944488848768742172978818416595458984376]", 1.0); // next double
        // 1.0 + 2^-53 = 1.00000000000000011102230246251565404236316680908203125
        TEST_DOUBLE("[1.00000000000000011102230246251565404236316680908203125]", 1.0); // round to even
        TEST_DOUBLE("[1.00000000000000011102230246251565404236316680908203124]", 1.0); // previous double
        TEST_DOUBLE("[1.00000000000000011102230246251565404236316680908203126]",
                    1.00000000000000022); // next double

        // Numbers from https://github.com/floitsch/double-conversion/blob/master/test/cctest/test-strtod.cc

        TEST_DOUBLE("[72057594037927928.0]", 72057594037927928.0);
        TEST_DOUBLE("[72057594037927936.0]", 72057594037927936.0);
        TEST_DOUBLE("[72057594037927932.0]", 72057594037927936.0);
        TEST_DOUBLE("[7205759403792793199999e-5]", 72057594037927928.0);
        TEST_DOUBLE("[7205759403792793200001e-5]", 72057594037927936.0);

        TEST_DOUBLE("[9223372036854774784.0]", 9223372036854774784.0);
        TEST_DOUBLE("[9223372036854775808.0]", 9223372036854775808.0);
        TEST_DOUBLE("[9223372036854775296.0]", 9223372036854775808.0);
        TEST_DOUBLE("[922337203685477529599999e-5]", 9223372036854774784.0);
        TEST_DOUBLE("[922337203685477529600001e-5]", 9223372036854775808.0);

        TEST_DOUBLE("[10141204801825834086073718800384]", 10141204801825834086073718800384.0);
        TEST_DOUBLE("[10141204801825835211973625643008]", 10141204801825835211973625643008.0);
        TEST_DOUBLE("[10141204801825834649023672221696]", 10141204801825835211973625643008.0);
        TEST_DOUBLE("[1014120480182583464902367222169599999e-5]", 10141204801825834086073718800384.0);
        TEST_DOUBLE("[1014120480182583464902367222169600001e-5]", 10141204801825835211973625643008.0);

        TEST_DOUBLE("[5708990770823838890407843763683279797179383808]",
                    5708990770823838890407843763683279797179383808.0);
        TEST_DOUBLE("[5708990770823839524233143877797980545530986496]",
                    5708990770823839524233143877797980545530986496.0);
        TEST_DOUBLE("[5708990770823839207320493820740630171355185152]",
                    5708990770823839524233143877797980545530986496.0);
        TEST_DOUBLE("[5708990770823839207320493820740630171355185151999e-3]",
                    5708990770823838890407843763683279797179383808.0);
        TEST_DOUBLE("[5708990770823839207320493820740630171355185152001e-3]",
                    5708990770823839524233143877797980545530986496.0);

        {
            char n1e308[312];   // '1' followed by 308 '0'
            n1e308[0] = '[';
            n1e308[1] = '1';
            for (int j = 2; j < 310; j++)
            {
                n1e308[j] = '0';
            }
            n1e308[310] = ']';
            n1e308[311] = '\0';
            TEST_DOUBLE(n1e308, 1E308);
        }

        // Cover trimming
        TEST_DOUBLE(
            "[2.22507385850720113605740979670913197593481954635164564802342610972482222202107694551652952390813508"
            "7914149158913039621106870086438694594645527657207407820621743379988141063267329253552286881372149012"
            "9811224514518898490572223072852551331557550159143974763979834118019993239625482890171070818506906306"
            "6665599493827577257201576306269066333264756530000924588831643303777979186961204949739037782970490505"
            "1080609940730262937128958950003583799967207254304360284078895771796150945516748243471030702609144621"
            "5722898802581825451803257070188608721131280795122334262883686223215037756666225039825343359745688844"
            "2390026549819838548794829220689472168983109969836584681402285424333066033985088644580400103493397042"
            "7567186443383770486037861622771738545623065874679014086723327636718751234567890123456789012345678901"
            "e-308]",
            2.2250738585072014e-308);
    }

    SECTION("strings")
    {
        auto TEST_STRING = [](const std::string & json_string, const std::string & expected)
        {
            CAPTURE(json_string);
            CAPTURE(expected);
            CHECK(json::parse(json_string)[0].get<std::string>() == expected);
        };

        TEST_STRING("[\"\"]", "");
        TEST_STRING("[\"Hello\"]", "Hello");
        TEST_STRING("[\"Hello\\nWorld\"]", "Hello\nWorld");
        //TEST_STRING("[\"Hello\\u0000World\"]", "Hello\0World");
        TEST_STRING("[\"\\\"\\\\/\\b\\f\\n\\r\\t\"]", "\"\\/\b\f\n\r\t");
        TEST_STRING("[\"\\u0024\"]", "\x24");         // Dollar sign U+0024
        TEST_STRING("[\"\\u00A2\"]", "\xC2\xA2");     // Cents sign U+00A2
        TEST_STRING("[\"\\u20AC\"]", "\xE2\x82\xAC"); // Euro sign U+20AC
        TEST_STRING("[\"\\uD834\\uDD1E\"]", "\xF0\x9D\x84\x9E");  // G clef sign U+1D11E
    }

    SECTION("roundtrip")
    {
        // test cases are from https://github.com/miloyip/nativejson-benchmark/tree/master/test/data/roundtrip

        for (auto filename :
                {
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
                    //"test/data/json_roundtrip/roundtrip24.json", // roundtrip error
                    //"test/data/json_roundtrip/roundtrip25.json", // roundtrip error
                    //"test/data/json_roundtrip/roundtrip26.json", // roundtrip error
                    //"test/data/json_roundtrip/roundtrip27.json", // roundtrip error
                    //"test/data/json_roundtrip/roundtrip28.json", // roundtrip error
                    "test/data/json_roundtrip/roundtrip29.json",
                    //"test/data/json_roundtrip/roundtrip30.json", // roundtrip error
                    //"test/data/json_roundtrip/roundtrip31.json", // roundtrip error
                    "test/data/json_roundtrip/roundtrip32.json"
                })
        {
            CAPTURE(filename);
            std::ifstream f(filename);
            std::string json_string( (std::istreambuf_iterator<char>(f) ),
                                     (std::istreambuf_iterator<char>()) );

            json j = json::parse(json_string);
            CHECK(j.dump() == json_string);
        }
    }
}

TEST_CASE("test suite from json-test-suite")
{
    SECTION("read all sample.json")
    {
        // read a file with all unicode characters stored as single-character
        // strings in a JSON array
        std::ifstream f("test/data/json_testsuite/sample.json");
        json j;
        CHECK_NOTHROW(j << f);

        // the array has 3 elements
        CHECK(j.size() == 3);
    }
}

TEST_CASE("json.org examples")
{
    // here, we list all JSON values from http://json.org/example

    SECTION("1.json")
    {
        std::ifstream f("test/data/json.org/1.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("2.json")
    {
        std::ifstream f("test/data/json.org/2.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("3.json")
    {
        std::ifstream f("test/data/json.org/3.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("4.json")
    {
        std::ifstream f("test/data/json.org/4.json");
        json j;
        CHECK_NOTHROW(j << f);
    }

    SECTION("5.json")
    {
        std::ifstream f("test/data/json.org/5.json");
        json j;
        CHECK_NOTHROW(j << f);
    }
}

TEST_CASE("RFC 7159 examples")
{
    // here, we list all JSON values from the RFC 7159 document

    SECTION("7. Strings")
    {
        CHECK(json::parse("\"\\u005C\"") == json("\\"));
        CHECK(json::parse("\"\\uD834\\uDD1E\"") == json("𝄞"));
        CHECK(json::parse("\"𝄞\"") == json("𝄞"));
    }

    SECTION("8.3 String Comparison")
    {
        CHECK(json::parse("\"a\\b\"") == json::parse("\"a\u005Cb\""));
    }

    SECTION("13 Examples")
    {
        {
            CHECK_NOTHROW(json(R"(
            {
                 "Image": {
                     "Width":  800,
                     "Height": 600,
                     "Title":  "View from 15th Floor",
                     "Thumbnail": {
                         "Url":    "http://www.example.com/image/481989943",
                         "Height": 125,
                         "Width":  100
                     },
                     "Animated" : false,
                     "IDs": [116, 943, 234, 38793]
                   }
               }
            )"));
        }

        {
            CHECK_NOTHROW(json(R"(
                [
                    {
                       "precision": "zip",
                       "Latitude":  37.7668,
                       "Longitude": -122.3959,
                       "Address":   "",
                       "City":      "SAN FRANCISCO",
                       "State":     "CA",
                       "Zip":       "94107",
                       "Country":   "US"
                    },
                    {
                       "precision": "zip",
                       "Latitude":  37.371991,
                       "Longitude": -122.026020,
                       "Address":   "",
                       "City":      "SUNNYVALE",
                       "State":     "CA",
                       "Zip":       "94085",
                       "Country":   "US"
                    }
            ])"));
        }

        CHECK(json::parse("\"Hello world!\"") == json("Hello world!"));
        CHECK(json::parse("42") == json(42));
        CHECK(json::parse("true") == json(true));
    }
}
