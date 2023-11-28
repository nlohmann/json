//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2023 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <fstream>
#include "make_test_data_available.hpp"

TEST_CASE("compliance tests from json.org")
{
    // test cases are from https://json.org/JSON_checker/

    SECTION("expected failures")
    {
        for (const auto* filename :
                {
                    //TEST_DATA_DIRECTORY "/json_tests/fail1.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail2.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail3.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail4.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail5.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail6.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail7.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail8.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail9.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail10.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail11.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail12.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail13.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail14.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail15.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail16.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail17.json",
                    //TEST_DATA_DIRECTORY "/json_tests/fail18.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail19.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail20.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail21.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail22.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail23.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail24.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail25.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail26.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail27.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail28.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail29.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail30.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail31.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail32.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail33.json"
                })
        {
            CAPTURE(filename)
            std::ifstream f(filename);
            json _;
            CHECK_THROWS_AS(_ = json::parse(f), json::parse_error&);
        }
    }

    SECTION("no failures with trailing literals (relaxed)")
    {
        // these tests fail above, because the parser does not end on EOF;
        // they succeed when the operator>> is used, because it does not
        // have this constraint
        for (const auto* filename :
                {
                    TEST_DATA_DIRECTORY "/json_tests/fail7.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail8.json",
                    TEST_DATA_DIRECTORY "/json_tests/fail10.json",
                })
        {
            CAPTURE(filename)
            std::ifstream f(filename);
            json j;
            CHECK_NOTHROW(f >> j);
        }
    }

    SECTION("expected passes")
    {
        for (const auto* filename :
                {
                    TEST_DATA_DIRECTORY "/json_tests/pass1.json",
                    TEST_DATA_DIRECTORY "/json_tests/pass2.json",
                    TEST_DATA_DIRECTORY "/json_tests/pass3.json"
                })
        {
            CAPTURE(filename)
            std::ifstream f(filename);
            json j;
            CHECK_NOTHROW(f >> j);
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
            CAPTURE(json_string)
            CAPTURE(expected)
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
            std::string n1e308(312, '0');   // '1' followed by 308 '0'
            n1e308[0] = '[';
            n1e308[1] = '1';
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
            CAPTURE(json_string)
            CAPTURE(expected)
            CHECK(json::parse(json_string)[0].get<std::string>() == expected);
        };

        TEST_STRING("[\"\"]", "");
        TEST_STRING("[\"Hello\"]", "Hello");
        TEST_STRING(R"(["Hello\nWorld"])", "Hello\nWorld");
        //TEST_STRING("[\"Hello\\u0000World\"]", "Hello\0World");
        TEST_STRING(R"(["\"\\/\b\f\n\r\t"])", "\"\\/\b\f\n\r\t");
        TEST_STRING(R"(["\u0024"])", "$");         // Dollar sign U+0024
        TEST_STRING(R"(["\u00A2"])", "\xC2\xA2");     // Cents sign U+00A2
        TEST_STRING(R"(["\u20AC"])", "\xE2\x82\xAC"); // Euro sign U+20AC
        TEST_STRING(R"(["\uD834\uDD1E"])", "\xF0\x9D\x84\x9E");  // G clef sign U+1D11E
    }

    SECTION("roundtrip")
    {
        // test cases are from https://github.com/miloyip/nativejson-benchmark/tree/master/test/data/roundtrip

        for (const auto* filename :
                {
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
                    //TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip28.json", // incompatible with roundtrip24
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip29.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip30.json",
                    TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip31.json"
                    //TEST_DATA_DIRECTORY "/json_roundtrip/roundtrip32.json" // same as roundtrip31
                })
        {
            CAPTURE(filename)
            std::ifstream f(filename);
            std::string json_string( (std::istreambuf_iterator<char>(f) ),
                                     (std::istreambuf_iterator<char>()) );

            CAPTURE(json_string)
            const json j = json::parse(json_string);
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
        std::ifstream f(TEST_DATA_DIRECTORY "/json_testsuite/sample.json");
        json j;
        CHECK_NOTHROW(f >> j);

        // the array has 3 elements
        CHECK(j.size() == 3);
    }
}

TEST_CASE("json.org examples")
{
    // here, we list all JSON values from https://json.org/example

    SECTION("1.json")
    {
        std::ifstream f(TEST_DATA_DIRECTORY "/json.org/1.json");
        json j;
        CHECK_NOTHROW(f >> j);
    }

    SECTION("2.json")
    {
        std::ifstream f(TEST_DATA_DIRECTORY "/json.org/2.json");
        json j;
        CHECK_NOTHROW(f >> j);
    }

    SECTION("3.json")
    {
        std::ifstream f(TEST_DATA_DIRECTORY "/json.org/3.json");
        json j;
        CHECK_NOTHROW(f >> j);
    }

    SECTION("4.json")
    {
        std::ifstream f(TEST_DATA_DIRECTORY "/json.org/4.json");
        json j;
        CHECK_NOTHROW(f >> j);
    }

    SECTION("5.json")
    {
        std::ifstream f(TEST_DATA_DIRECTORY "/json.org/5.json");
        json j;
        CHECK_NOTHROW(f >> j);
    }
    SECTION("FILE 1.json")
    {
        const std::unique_ptr<std::FILE, decltype(&std::fclose)> f(std::fopen(TEST_DATA_DIRECTORY "/json.org/1.json", "r"), &std::fclose);
        json _;
        CHECK_NOTHROW(_ = json::parse(f.get()));
    }

    SECTION("FILE 2.json")
    {
        const std::unique_ptr<std::FILE, decltype(&std::fclose)> f(std::fopen(TEST_DATA_DIRECTORY "/json.org/2.json", "r"), &std::fclose);
        json _;
        CHECK_NOTHROW(_ = json::parse(f.get()));
    }

    SECTION("FILE 3.json")
    {
        const std::unique_ptr<std::FILE, decltype(&std::fclose)> f(std::fopen(TEST_DATA_DIRECTORY "/json.org/3.json", "r"), &std::fclose);
        json _;
        CHECK_NOTHROW(_ = json::parse(f.get()));
    }

    SECTION("FILE 4.json")
    {
        const std::unique_ptr<std::FILE, decltype(&std::fclose)> f(std::fopen(TEST_DATA_DIRECTORY "/json.org/4.json", "r"), &std::fclose);
        json _;
        CHECK_NOTHROW(_ = json::parse(f.get()));
    }

    SECTION("FILE 5.json")
    {
        const std::unique_ptr<std::FILE, decltype(&std::fclose)> f(std::fopen(TEST_DATA_DIRECTORY "/json.org/5.json", "r"), &std::fclose);
        json _;
        CHECK_NOTHROW(_ = json::parse(f.get()));
    }
}

TEST_CASE("RFC 8259 examples")
{
    // here, we list all JSON values from the RFC 8259 document

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
            const auto* json_contents = R"(
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
            )";

            CHECK_NOTHROW(json(json_contents));
        }

        {
            const auto* json_contents = R"(
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
            ])";
            CHECK_NOTHROW(json(json_contents));
        }

        CHECK(json::parse("\"Hello world!\"") == json("Hello world!"));
        CHECK(json::parse("42") == json(42));
        CHECK(json::parse("true") == json(true));
    }
}

TEST_CASE("nst's JSONTestSuite")
{
    SECTION("test_parsing")
    {
        SECTION("y")
        {
            for (const auto* filename :
                    {
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
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json j;
                CHECK_NOTHROW(f >> j);
            }
        }

        SECTION("n")
        {
            for (const auto* filename :
                    {
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_1_true_without_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_a_invalid_utf8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_colon_instead_of_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_comma_after_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_comma_and_number.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_double_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_double_extra_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_extra_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_extra_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_incomplete.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_incomplete_invalid_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_inner_array_no_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_invalid_utf8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_items_separated_by_semicolon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_just_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_just_minus.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_missing_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_newlines_unclosed.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_number_and_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_number_and_several_commas.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_spaces_vertical_tab_formfeed.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_star_inside.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_unclosed.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_unclosed_trailing_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_unclosed_with_new_lines.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_unclosed_with_object_inside.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_incomplete_false.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_incomplete_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_incomplete_true.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_++.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_+1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_+Inf.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_-01.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_-1.0..json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_-2..json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_-NaN.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_.-1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_.2e-3.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_0.1.2.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_0.3e+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_0.3e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_0.e1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_0_capital_E+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_0_capital_E.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_0e+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_0e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_1.0e+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_1.0e-.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_1.0e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_1_000.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_1eE2.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_2.e+3.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_2.e-3.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_2.e3.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_9.e+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_Inf.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_NaN.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_U+FF11_fullwidth_digit_one.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_expression.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_hex_1_digit.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_hex_2_digits.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_infinity.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_invalid+-.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_invalid-negative-real.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_invalid-utf-8-in-bigger-int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_invalid-utf-8-in-exponent.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_invalid-utf-8-in-int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_minus_infinity.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_minus_sign_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_minus_space_1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_neg_int_starting_with_zero.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_neg_real_without_int_part.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_neg_with_garbage_at_end.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_real_garbage_after_e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_real_with_invalid_utf8_after_e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_real_without_fractional_part.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_starting_with_dot.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_then_00.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_with_alpha.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_with_alpha_char.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_number_with_leading_zero.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_bad_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_bracket_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_comma_instead_of_colon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_double_colon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_emoji.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_garbage_at_end.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_key_with_single_quotes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_missing_colon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_missing_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_missing_semicolon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_missing_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_no-colon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_non_string_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_non_string_key_but_huge_number_instead.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_pi_in_key_and_trailing_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_repeated_null_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_several_trailing_commas.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_single_quote.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comment.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comment_open.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comment_slash_open.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comment_slash_open_incomplete.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_two_commas_in_a_row.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_unquoted_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_unterminated-value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_with_single_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_single_space.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_1_surrogate_then_escape u.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_1_surrogate_then_escape u1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_1_surrogate_then_escape u1x.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_1_surrogate_then_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_UTF-16_incomplete_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_UTF8_surrogate_U+D800.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_accentuated_char_no_quotes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_backslash_00.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_escape_x.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_escaped_backslash_bad.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_escaped_ctrl_char_tab.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_escaped_emoji.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_incomplete_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_incomplete_escaped_character.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_incomplete_surrogate_escape_invalid.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_invalid-utf-8-in-escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_invalid_backslash_esc.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_invalid_unicode_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_invalid_utf-8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_invalid_utf8_after_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_iso_latin_1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_leading_uescaped_thinspace.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_lone_utf8_continuation_byte.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_no_quotes_with_bad_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_overlong_sequence_2_bytes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_overlong_sequence_6_bytes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_overlong_sequence_6_bytes_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_single_doublequote.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_single_quote.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_single_string_no_double_quotes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_start_escape_unclosed.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_unescaped_crtl_char.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_unescaped_newline.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_unescaped_tab.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_unicode_CapitalU.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_with_trailing_garbage.json",
                        //!TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_100000_opening_arrays.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_3C.3E.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_3Cnull3E.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_U+2060_word_joined.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_UTF8_BOM_no_data.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_array_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_array_with_extra_array_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_array_with_unclosed_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_ascii-unicode-identifier.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_capitalized_True.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_close_unopened_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_comma_instead_of_closing_brace.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_double_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_end_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_incomplete_UTF8_BOM.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_lone-invalid-utf-8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_lone-open-bracket.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_no_data.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_null-byte-outside-string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_number_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_object_followed_by_closing_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_object_unclosed_no_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_object_with_comment.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_object_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_array_apostrophe.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_array_comma.json",
                        //!TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_array_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_array_open_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_array_open_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_array_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_object_close_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_object_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_object_open_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_object_open_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_object_string_with_apostrophes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_open_open.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_single_point.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_single_star.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_trailing_#.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_uescaped_LF_before_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_unclosed_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_unclosed_array_partial_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_unclosed_array_unfinished_false.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_unclosed_array_unfinished_true.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_unclosed_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_unicode-identifier.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_whitespace_U+2060_word_joiner.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_whitespace_formfeed.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json _;
                CHECK_THROWS_AS(_ = json::parse(f), json::parse_error&);
            }
        }

        SECTION("n -> y (relaxed)")
        {
            // these tests fail above, because the parser does not end on EOF;
            // they succeed when the operator>> is used, because it does not
            // have this constraint
            for (const auto* filename :
                    {
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_comma_after_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_array_extra_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comment.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comment_open.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comment_slash_open.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_trailing_comment_slash_open_incomplete.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_object_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_string_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_array_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_array_with_extra_array_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_close_unopened_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_double_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_number_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_object_followed_by_closing_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_object_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/n_structure_trailing_#.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json j;
                CHECK_NOTHROW(f >> j);
            }
        }

        SECTION("i -> y")
        {
            for (const auto* filename :
                    {
                        // we do not pose a limit on nesting
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_structure_500_nested_arrays.json",
                        // we silently ignore BOMs
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_structure_UTF-8_BOM_empty_object.json",
                        // we accept and forward non-characters
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_unicode_U+10FFFE_nonchar.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_unicode_U+1FFFE_nonchar.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_unicode_U+FDD0_nonchar.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_unicode_U+FFFE_nonchar.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json j;
                CHECK_NOTHROW(f >> j);
            }
        }

        // numbers that overflow during parsing
        SECTION("i/y -> n (out of range)")
        {
            for (const auto* filename :
                    {
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_number_neg_int_huge_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_number_pos_double_huge_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_huge_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_neg_overflow.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/y_number_real_pos_overflow.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json j;
                CHECK_THROWS_AS(f >> j, json::out_of_range&);
            }
        }

        SECTION("i -> n")
        {
            for (const auto* filename :
                    {
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_object_key_lone_2nd_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_1st_surrogate_but_2nd_missing.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_1st_valid_surrogate_2nd_invalid.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_UTF-16_invalid_lonely_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_UTF-16_invalid_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_UTF-8_invalid_sequence.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_incomplete_surrogate_and_escape_valid.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_incomplete_surrogate_pair.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_incomplete_surrogates_escape_valid.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_inverted_surrogates_U+1D11E.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_lone_second_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_not_in_unicode_range.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite/test_parsing/i_string_truncated-utf-8.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json j;
                CHECK_THROWS_AS(f >> j, json::parse_error&);
            }
        }
    }
}

TEST_CASE("nst's JSONTestSuite (2)")
{
    SECTION("test_parsing")
    {
        SECTION("y")
        {
            for (const auto* filename :
                    {
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_arraysWithSpaces.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_empty-string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_empty.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_ending_with_newline.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_false.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_heterogeneous.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_with_1_and_newline.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_with_leading_space.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_with_several_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_array_with_trailing_space.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_0e+1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_0e1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_after_space.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_double_close_to_zero.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_int_with_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_minus_zero.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_negative_int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_negative_one.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_negative_zero.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_real_capital_e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_real_capital_e_neg_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_real_capital_e_pos_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_real_exponent.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_real_fraction_exponent.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_real_neg_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_real_pos_exponent.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_simple_int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_number_simple_real.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_basic.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_duplicated_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_duplicated_key_and_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_empty.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_empty_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_escaped_null_in_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_extreme_numbers.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_long_strings.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_simple.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_string_unicode.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_object_with_newlines.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_1_2_3_bytes_UTF-8_sequences.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_accepted_surrogate_pair.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_accepted_surrogate_pairs.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_allowed_escapes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_backslash_and_u_escaped_zero.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_backslash_doublequotes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_comments.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_double_escape_a.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_double_escape_n.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_escaped_control_character.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_escaped_noncharacter.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_in_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_in_array_with_leading_space.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_last_surrogates_1_and_2.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_nbsp_uescaped.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_nonCharacterInUTF-8_U+10FFFF.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_nonCharacterInUTF-8_U+FFFF.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_null_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_one-byte-utf-8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_pi.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_reservedCharacterInUTF-8_U+1BFFF.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_simple_ascii.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_space.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_surrogates_U+1D11E_MUSICAL_SYMBOL_G_CLEF.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_three-byte-utf-8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_two-byte-utf-8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_u+2028_line_sep.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_u+2029_par_sep.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_uEscape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_uescaped_newline.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unescaped_char_delete.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicodeEscapedBackslash.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode_2.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode_U+10FFFE_nonchar.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode_U+1FFFE_nonchar.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode_U+200B_ZERO_WIDTH_SPACE.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode_U+2064_invisible_plus.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode_U+FDD0_nonchar.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode_U+FFFE_nonchar.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_unicode_escaped_double_quote.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_utf8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_string_with_del_character.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_lonely_false.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_lonely_int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_lonely_negative_real.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_lonely_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_lonely_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_lonely_true.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_string_empty.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_trailing_newline.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_true_in_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/y_structure_whitespace_array.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json _;
                CHECK_NOTHROW(_ = json::parse(f));
                std::ifstream f2(filename);
                CHECK(json::accept(f2));
            }
        }

        SECTION("n")
        {
            for (const auto* filename :
                    {
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_1_true_without_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_a_invalid_utf8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_colon_instead_of_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_comma_after_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_comma_and_number.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_double_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_double_extra_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_extra_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_extra_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_incomplete.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_incomplete_invalid_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_inner_array_no_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_invalid_utf8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_items_separated_by_semicolon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_just_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_just_minus.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_missing_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_newlines_unclosed.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_number_and_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_number_and_several_commas.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_spaces_vertical_tab_formfeed.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_star_inside.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_unclosed.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_unclosed_trailing_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_unclosed_with_new_lines.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_array_unclosed_with_object_inside.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_incomplete_false.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_incomplete_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_incomplete_true.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_multidigit_number_then_00.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_++.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_+1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_+Inf.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_-01.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_-1.0..json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_-2..json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_-NaN.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_.-1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_.2e-3.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_0.1.2.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_0.3e+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_0.3e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_0.e1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_0_capital_E+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_0_capital_E.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_0e+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_0e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_1.0e+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_1.0e-.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_1.0e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_1_000.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_1eE2.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_2.e+3.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_2.e-3.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_2.e3.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_9.e+.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_Inf.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_NaN.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_U+FF11_fullwidth_digit_one.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_expression.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_hex_1_digit.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_hex_2_digits.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_infinity.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_invalid+-.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_invalid-negative-real.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_invalid-utf-8-in-bigger-int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_invalid-utf-8-in-exponent.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_invalid-utf-8-in-int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_minus_infinity.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_minus_sign_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_minus_space_1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_neg_int_starting_with_zero.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_neg_real_without_int_part.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_neg_with_garbage_at_end.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_real_garbage_after_e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_real_with_invalid_utf8_after_e.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_real_without_fractional_part.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_starting_with_dot.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_with_alpha.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_with_alpha_char.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_number_with_leading_zero.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_bad_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_bracket_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_comma_instead_of_colon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_double_colon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_emoji.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_garbage_at_end.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_key_with_single_quotes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_lone_continuation_byte_in_key_and_trailing_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_missing_colon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_missing_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_missing_semicolon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_missing_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_no-colon.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_non_string_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_non_string_key_but_huge_number_instead.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_repeated_null_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_several_trailing_commas.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_single_quote.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_trailing_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_trailing_comment.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_trailing_comment_open.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_trailing_comment_slash_open.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_trailing_comment_slash_open_incomplete.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_two_commas_in_a_row.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_unquoted_key.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_unterminated-value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_with_single_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_object_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_single_space.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_1_surrogate_then_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_1_surrogate_then_escape_u.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_1_surrogate_then_escape_u1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_1_surrogate_then_escape_u1x.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_accentuated_char_no_quotes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_backslash_00.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_escape_x.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_escaped_backslash_bad.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_escaped_ctrl_char_tab.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_escaped_emoji.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_incomplete_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_incomplete_escaped_character.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_incomplete_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_incomplete_surrogate_escape_invalid.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_invalid-utf-8-in-escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_invalid_backslash_esc.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_invalid_unicode_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_invalid_utf8_after_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_leading_uescaped_thinspace.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_no_quotes_with_bad_escape.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_single_doublequote.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_single_quote.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_single_string_no_double_quotes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_start_escape_unclosed.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_unescaped_crtl_char.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_unescaped_newline.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_unescaped_tab.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_unicode_CapitalU.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_string_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_U+2060_word_joined.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_UTF8_BOM_no_data.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_angle_bracket_..json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_angle_bracket_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_array_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_array_with_extra_array_close.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_array_with_unclosed_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_ascii-unicode-identifier.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_capitalized_True.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_close_unopened_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_comma_instead_of_closing_brace.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_double_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_end_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_incomplete_UTF8_BOM.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_lone-invalid-utf-8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_lone-open-bracket.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_no_data.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_null-byte-outside-string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_number_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_object_followed_by_closing_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_object_unclosed_no_value.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_object_with_comment.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_object_with_trailing_garbage.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_array_apostrophe.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_array_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_array_open_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_array_open_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_array_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_object_close_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_object_comma.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_object_open_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_object_open_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_object_string_with_apostrophes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_open.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_single_eacute.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_single_star.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_trailing_#.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_uescaped_LF_before_string.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_unclosed_array.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_unclosed_array_partial_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_unclosed_array_unfinished_false.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_unclosed_array_unfinished_true.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_unclosed_object.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_unicode-identifier.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_whitespace_U+2060_word_joiner.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_whitespace_formfeed.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json _;
                CHECK_THROWS_AS(_ = json::parse(f), json::parse_error&);
                std::ifstream f2(filename);
                CHECK(!json::accept(f2));
            }
        }

        SECTION("n (previously overflowed)")
        {
            for (const auto* filename :
                    {
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_100000_opening_arrays.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/n_structure_open_array_object.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                CHECK(!json::accept(f));
            }
        }

        SECTION("i -> y")
        {
            for (const auto* filename :
                    {
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_double_huge_neg_exp.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_huge_exp.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_neg_int_huge_exp.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_pos_double_huge_exp.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_real_neg_overflow.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_real_pos_overflow.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_real_underflow.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_too_big_neg_int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_too_big_pos_int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_very_big_negative_int.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_object_key_lone_2nd_surrogate.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_1st_surrogate_but_2nd_missing.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_1st_valid_surrogate_2nd_invalid.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_UTF-16LE_with_BOM.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_UTF-8_invalid_sequence.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_UTF8_surrogate_U+D800.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_incomplete_surrogate_and_escape_valid.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_incomplete_surrogate_pair.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_incomplete_surrogates_escape_valid.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_invalid_lonely_surrogate.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_invalid_surrogate.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_invalid_utf-8.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_inverted_surrogates_U+1D11E.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_iso_latin_1.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_lone_second_surrogate.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_lone_utf8_continuation_byte.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_not_in_unicode_range.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_overlong_sequence_2_bytes.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_overlong_sequence_6_bytes.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_overlong_sequence_6_bytes_null.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_truncated-utf-8.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_utf16BE_no_BOM.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_utf16LE_no_BOM.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_structure_500_nested_arrays.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_structure_UTF-8_BOM_empty_object.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json _;
                CHECK_NOTHROW(_ = json::parse(f));
                std::ifstream f2(filename);
                CHECK(json::accept(f2));
            }
        }

        SECTION("i -> n")
        {
            for (const auto* filename :
                    {
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_double_huge_neg_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_huge_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_neg_int_huge_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_pos_double_huge_exp.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_real_neg_overflow.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_real_pos_overflow.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_real_underflow.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_too_big_neg_int.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_too_big_pos_int.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_number_very_big_negative_int.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_object_key_lone_2nd_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_1st_surrogate_but_2nd_missing.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_1st_valid_surrogate_2nd_invalid.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_UTF-16LE_with_BOM.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_UTF-8_invalid_sequence.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_UTF8_surrogate_U+D800.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_incomplete_surrogate_and_escape_valid.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_incomplete_surrogate_pair.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_incomplete_surrogates_escape_valid.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_invalid_lonely_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_invalid_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_invalid_utf-8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_inverted_surrogates_U+1D11E.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_iso_latin_1.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_lone_second_surrogate.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_lone_utf8_continuation_byte.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_not_in_unicode_range.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_overlong_sequence_2_bytes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_overlong_sequence_6_bytes.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_overlong_sequence_6_bytes_null.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_truncated-utf-8.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_utf16BE_no_BOM.json",
                        TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_string_utf16LE_no_BOM.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_structure_500_nested_arrays.json",
                        //TEST_DATA_DIRECTORY "/nst_json_testsuite2/test_parsing/i_structure_UTF-8_BOM_empty_object.json"
                    }
                )
            {
                CAPTURE(filename)
                std::ifstream f(filename);
                json _;
                CHECK_THROWS_AS(_ = json::parse(f), json::exception&); // could be parse_error or out_of_range
                std::ifstream f2(filename);
                CHECK(!json::accept(f2));
            }
        }
    }
}

namespace
{
std::string trim(const std::string& str);

// from https://stackoverflow.com/a/25829178/266378
std::string trim(const std::string& str)
{
    const size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first)
    {
        return str;
    }
    const size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}
} // namespace

TEST_CASE("Big List of Naughty Strings")
{
    // test from https://github.com/minimaxir/big-list-of-naughty-strings
    SECTION("parsing blns.json")
    {
        std::ifstream f(TEST_DATA_DIRECTORY "/big-list-of-naughty-strings/blns.json");
        json j;
        CHECK_NOTHROW(f >> j);
    }

    // check if parsed strings roundtrip
    // https://www.reddit.com/r/cpp/comments/5qpbie/json_form_modern_c_version_210/dd12mpq/
    SECTION("roundtripping")
    {
        std::ifstream f(TEST_DATA_DIRECTORY "/big-list-of-naughty-strings/blns.json");
        std::string line;

        // read lines one by one, bail out on error or eof
        while (getline(f, line))
        {
            // trim whitespace
            line = trim(line);

            // remove trailing comma
            line = line.substr(0, line.find_last_of(','));

            // discard lines without at least two characters (quotes)
            if (line.size() < 2)
            {
                continue;
            }

            // check roundtrip
            CAPTURE(line)
            const json j = json::parse(line);
            CHECK(j.dump() == line);
        }
    }
}
