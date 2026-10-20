//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <cmath>
#include <sstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using nlohmann::json;
using nlohmann::ordered_json;

TEST_CASE("canonical JSON serialization (RFC 8785 / JCS)")
{
    SECTION("primitives and literals")
    {
        CHECK(json(nullptr).dump_canonical() == "null");
        CHECK(json(true).dump_canonical() == "true");
        CHECK(json(false).dump_canonical() == "false");
        CHECK(json(0).dump_canonical() == "0");
        CHECK(json(42).dump_canonical() == "42");
        CHECK(json(-42).dump_canonical() == "-42");
        CHECK(json("").dump_canonical() == "\"\"");
        CHECK(json("hello").dump_canonical() == "\"hello\"");
    }

    SECTION("empty containers")
    {
        CHECK(json::object().dump_canonical() == "{}");
        CHECK(json::array().dump_canonical() == "[]");
        CHECK(json({{"empty_obj", json::object()}, {"empty_arr", json::array()}}).dump_canonical()
              == "{\"empty_arr\":[],\"empty_obj\":{}}");
    }

    SECTION("string escaping according to RFC 8785")
    {
        // Minimal escapes: \", \\, \b, \f, \n, \r, \t, and \u0000..\u001f
        CHECK(json("\"").dump_canonical() == "\"\\\"\"");
        CHECK(json("\\").dump_canonical() == "\"\\\\\"");
        CHECK(json("\b").dump_canonical() == "\"\\b\"");
        CHECK(json("\f").dump_canonical() == "\"\\f\"");
        CHECK(json("\n").dump_canonical() == "\"\\n\"");
        CHECK(json("\r").dump_canonical() == "\"\\r\"");
        CHECK(json("\t").dump_canonical() == "\"\\t\"");
        CHECK(json("\x01").dump_canonical() == "\"\\u0001\"");
        CHECK(json("\x1F").dump_canonical() == "\"\\u001f\"");

        // Forward slash MUST NOT be escaped
        CHECK(json("/").dump_canonical() == "\"/\"");
        CHECK(json("http://example.com/api").dump_canonical() == "\"http://example.com/api\"");

        // Unicode >= 0x20 MUST NOT be escaped (emitted as raw UTF-8)
        CHECK(json("€").dump_canonical() == "\"€\"");
        CHECK(json("ö").dump_canonical() == "\"ö\"");
        CHECK(json("Å").dump_canonical() == "\"Å\"");
    }

    SECTION("key sorting by UTF-16 code units")
    {
        // BMP characters sort by code point = code unit
        json j1 = {{"b", 2}, {"a", 1}, {"c", 3}};
        CHECK(j1.dump_canonical() == "{\"a\":1,\"b\":2,\"c\":3}");

        // Empty string sorts before non-empty
        json j2 = {{"a", 1}, {"", 0}};
        CHECK(j2.dump_canonical() == "{\"\":0,\"a\":1}");

        // Numeric string keys
        json j3 = {{"111", 3}, {"1", 1}, {"10", 2}};
        CHECK(j3.dump_canonical() == "{\"1\":1,\"10\":2,\"111\":3}");

        // UTF-16 surrogate pairs sort before U+E000..U+FFFF BMP characters
        // 😂 (U+1F602, UTF-16: D83D DE02) vs דּ (U+FB33, UTF-16: FB33)
        // In UTF-8 bytes: דּ (EF AC B3) < 😂 (F0 9F 98 82)
        // In UTF-16 code units: 😂 (0xD83D) < דּ (0xFB33)
        json j_surrogate = {{"\xEF\xAC\xB3", "Hebrew"}, {"\xF0\x9F\x98\x82", "Smiley"}};
        CHECK(j_surrogate.dump_canonical() == "{\"😂\":\"Smiley\",\"דּ\":\"Hebrew\"}");

        // Works equally on ordered_json
        ordered_json oj = {{"z", 1}, {"a", 2}, {"m", 3}};
        CHECK(oj.dump_canonical() == "{\"a\":2,\"m\":3,\"z\":1}");
    }

    SECTION("number formatting (RFC 8785 Appendix B)")
    {
        // Zero and minus zero
        CHECK(json(0.0).dump_canonical() == "0");
        CHECK(json(-0.0).dump_canonical() == "0");

        // Integers stored as float without trailing .0
        CHECK(json(56.0).dump_canonical() == "56");
        CHECK(json(-42.0).dump_canonical() == "-42");

        // Plain decimal range: 1e-6 <= |x| < 1e21
        CHECK(json(4.5).dump_canonical() == "4.5");
        CHECK(json(0.002).dump_canonical() == "0.002");
        CHECK(json(0.000001).dump_canonical() == "0.000001");
        CHECK(json(333333333.3333333).dump_canonical() == "333333333.3333333");
        CHECK(json(9007199254740992.0).dump_canonical() == "9007199254740992");
        CHECK(json(-9007199254740992.0).dump_canonical() == "-9007199254740992");

        // Exponential range: |x| < 1e-6 or |x| >= 1e21
        CHECK(json(9.999999999999997e-7).dump_canonical() == "9.999999999999997e-7");
        CHECK(json(1e21).dump_canonical() == "1e+21");
        CHECK(json(1e30).dump_canonical() == "1e+30");
        CHECK(json(1e-27).dump_canonical() == "1e-27");
        CHECK(json(5e-324).dump_canonical() == "5e-324");
        CHECK(json(-5e-324).dump_canonical() == "-5e-324");
        CHECK(json(1.7976931348623157e+308).dump_canonical() == "1.7976931348623157e+308");
        CHECK(json(-1.7976931348623157e+308).dump_canonical() == "-1.7976931348623157e+308");
    }

    SECTION("reproducible byte-identical output across different key insertion orders")
    {
        ordered_json doc1 = {
            {"user", {{"id", 101}, {"name", "Alice"}, {"role", "admin"}}},
            {"active", true},
            {"tags", {"security", "audit"}}
        };

        ordered_json doc2 = {
            {"tags", {"security", "audit"}},
            {"active", true},
            {"user", {{"role", "admin"}, {"id", 101}, {"name", "Alice"}}}
        };

        CHECK(doc1.dump_canonical() == doc2.dump_canonical());
    }

    SECTION("official RFC 8785 test vectors")
    {
        struct TestVector
        {
            const char* name;
            const char* input;
            const char* expected;
        };

        const std::vector<TestVector> test_vectors = {
            {
                "arrays",
                "[\n  56,\n  {\n    \"d\": true,\n    \"10\": null,\n    \"1\": [ ]\n  }\n]\n",
                "[56,{\"1\":[],\"10\":null,\"d\":true}]"
            },
            {
                "french",
                "{\n  \"peach\": \"This sorting order\",\n  \"p\xC3\xA9\x63\x68\xC3\xA9\": \"is wrong according to French\",\n  \"p\xC3\xAA\x63\x68\x65\": \"but canonicalization MUST\",\n  \"sin\":   \"ignore locale\"\n}\n",
                "{\"peach\":\"This sorting order\",\"p\xC3\xA9\x63\x68\xC3\xA9\":\"is wrong according to French\",\"p\xC3\xAA\x63\x68\x65\":\"but canonicalization MUST\",\"sin\":\"ignore locale\"}"
            },
            {
                "structures",
                "{\n  \"1\": {\"f\": {\"f\": \"hi\",\"F\": 5} ,\"\\n\": 56.0},\n  \"10\": { },\n  \"\": \"empty\",\n  \"a\": { },\n  \"111\": [ {\"e\": \"yes\",\"E\": \"no\" } ],\n  \"A\": { }\n}",
                "{\"\":\"empty\",\"1\":{\"\\n\":56,\"f\":{\"F\":5,\"f\":\"hi\"}},\"10\":{},\"111\":[{\"E\":\"no\",\"e\":\"yes\"}],\"A\":{},\"a\":{}}"
            },
            {
                "unicode",
                "{\n  \"Unnormalized Unicode\":\"A\\u030a\"\n}\n",
                "{\"Unnormalized Unicode\":\"A\xCC\x8A\"}"
            },
            {
                "values",
                "{\n  \"numbers\": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],\n  \"string\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n  \"literals\": [null, true, false]\n}",
                "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\xE2\x82\xAC$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
            },
            {
                "weird",
                "{\n  \"\\u20ac\": \"Euro Sign\",\n  \"\\r\": \"Carriage Return\",\n  \"\\u000a\": \"Newline\",\n  \"1\": \"One\",\n  \"\\u0080\": \"Control\\u007f\",\n  \"\\ud83d\\ude02\": \"Smiley\",\n  \"\\u00f6\": \"Latin Small Letter O With Diaeresis\",\n  \"\\ufb33\": \"Hebrew Letter Dalet With Dagesh\",\n  \"</script>\": \"Browser Challenge\"\n}\n",
                "{\"\\n\":\"Newline\",\"\\r\":\"Carriage Return\",\"1\":\"One\",\"</script>\":\"Browser Challenge\",\"\xC2\x80\":\"Control\x7F\",\"\xC3\xB6\":\"Latin Small Letter O With Diaeresis\",\"\xE2\x82\xAC\":\"Euro Sign\",\"\xF0\x9F\x98\x82\":\"Smiley\",\"\xEF\xAC\xB3\":\"Hebrew Letter Dalet With Dagesh\"}"
            }
        };

        for (const auto& vec : test_vectors)
        {
            CAPTURE(vec.name);
            json j = json::parse(vec.input);
            CHECK(j.dump_canonical() == vec.expected);

            ordered_json oj = ordered_json::parse(vec.input);
            CHECK(oj.dump_canonical() == vec.expected);
        }
    }

    SECTION("error handling")
    {
        // NaN is rejected
        json j_nan = std::numeric_limits<double>::quiet_NaN();
        CHECK_THROWS_WITH_AS(j_nan.dump_canonical(),
                             "[json.exception.out_of_range.406] cannot serialize non-finite numbers in canonical mode",
                             json::out_of_range&);

        // Infinity is rejected
        json j_inf = std::numeric_limits<double>::infinity();
        CHECK_THROWS_WITH_AS(j_inf.dump_canonical(),
                             "[json.exception.out_of_range.406] cannot serialize non-finite numbers in canonical mode",
                             json::out_of_range&);

        json j_neg_inf = -std::numeric_limits<double>::infinity();
        CHECK_THROWS_WITH_AS(j_neg_inf.dump_canonical(),
                             "[json.exception.out_of_range.406] cannot serialize non-finite numbers in canonical mode",
                             json::out_of_range&);

        // Binary types are rejected
        json j_bin = json::binary({0x01, 0x02, 0x03});
        CHECK_THROWS_WITH_AS(j_bin.dump_canonical(),
                             "[json.exception.type_error.317] type cannot be serialized in canonical JSON (RFC 8785): binary",
                             json::type_error&);

        // Discarded values are rejected
        json j_disc = json::value_t::discarded;
        CHECK_THROWS_WITH_AS(j_disc.dump_canonical(),
                             "[json.exception.type_error.317] type cannot be serialized in canonical JSON (RFC 8785): discarded",
                             json::type_error&);
    }

    SECTION("static dump_canonical with output adapter")
    {
        json j = {{"b", 2}, {"a", 1}};
        std::string result;
        json::dump_canonical(j, result);
        CHECK(result == "{\"a\":1,\"b\":2}");

        std::ostringstream ss;
        json::dump_canonical(j, ss);
        CHECK(ss.str() == "{\"a\":1,\"b\":2}");
    }
}
