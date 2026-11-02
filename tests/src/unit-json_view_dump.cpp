//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json_view.hpp>
using nlohmann::json;
using nlohmann::ordered_json;
using nlohmann::json_document;
using nlohmann::ordered_json_editable_document;
using nlohmann::json_view;
using nlohmann::ordered_json_document;
using nlohmann::ordered_json_view;

#include "json_view_test_helpers.hpp"
using json_view_test::generator;
using json_view_test::has_duplicate_keys;

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// These tests were split off unit-json_view.cpp, whose object file got too large for the MinGW
// linker (see json_view_test_helpers.hpp). Like that file, this one is also built
// with C++17, as it mentions JSON_HAS_CPP_17.

TEST_CASE("json_view dump")
{
    SECTION("the output of ordered_json::dump()")
    {
        generator g;
        for (int i = 0; i < 2000; ++i)
        {
            std::string text;
            g.value(text, 0);
            const ordered_json_document d = ordered_json_document::parse(text);
            if (has_duplicate_keys(d.root()))
            {
                continue;
            }
            CAPTURE(text)
            const ordered_json j = ordered_json::parse(text);
            for (const int indent :
                    {
                        -1, 0, 2
                    })
            {
                for (const bool ensure_ascii :
                        {
                            false, true
                        })
                {
                    CHECK(d.root().dump(indent, i % 2 == 0 ? ' ' : '\t', ensure_ascii) == j.dump(indent, i % 2 == 0 ? ' ' : '\t', ensure_ascii));
                }
            }
            // also of each element
            for (const ordered_json_view e : d.root())
            {
                CHECK(e.dump() == e.materialize().dump());
            }
        }
    }

    SECTION("strings")
    {
        const std::string text = R"(["plain", "\u0000\u0001\u001f\u007f\u0080é€￿😀", "\"\\\/\b\f\n\r\t", "aéあ😀b", "long text beyond the eight bytes of a word \n with an escape in the middle"])";
        const ordered_json_document d = ordered_json_document::parse(text);
        const ordered_json j = ordered_json::parse(text);
        CHECK(d.root().dump() == j.dump());
        CHECK(d.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
        CHECK(d.root().dump(4, ' ', true) == j.dump(4, ' ', true));
        const std::string key_text = R"({"é\n": {"\"": [], "": {}}})";
        const ordered_json_document keys = ordered_json_document::parse(key_text);
        const ordered_json key_json = ordered_json::parse(key_text);
        CHECK(keys.root().dump(2, ' ', true) == key_json.dump(2, ' ', true));
    }

    SECTION("numbers")
    {
        const std::string text = "[1.50, 1E2, -0, -0.0, 123456789012345678901234567890, 18446744073709551615, -9223372036854775808, 0.1, 1e-7, 5e-324]";
        const json_document d = json_document::parse(text);
        CHECK(d.root().dump() == json::parse(text).dump());
        CHECK(d.root().dump() == "[1.5,100.0,0,-0.0,1.2345678901234568e+29,18446744073709551615,-9223372036854775808,0.1,1e-07,5e-324]");
        CHECK(d.root().dump(-1, ' ', false, json_view::number_format::source) == "[1.50,1E2,-0,-0.0,123456789012345678901234567890,18446744073709551615,-9223372036854775808,0.1,1e-7,5e-324]");
        // also indented, and with ensure_ascii
        CHECK(d.root().dump(0, ' ', false, json_view::number_format::source) == "[\n1.50,\n1E2,\n-0,\n-0.0,\n123456789012345678901234567890,\n18446744073709551615,\n-9223372036854775808,\n0.1,\n1e-7,\n5e-324\n]");
        CHECK(d.root().dump(-1, ' ', true, json_view::number_format::source) == "[1.50,1E2,-0,-0.0,123456789012345678901234567890,18446744073709551615,-9223372036854775808,0.1,1e-7,5e-324]");

        // float tokens of up to 17 significant digits in every spelling: those
        // of at most 15 digits are written from their digits, the others
        // through the conversion; both as dump() writes them
        {
            std::mt19937_64 tokens(1170); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
            // a number below n; the remainder is a std::uint64_t, which is
            // std::size_t on some platforms and wider on others
            const auto draw = [&tokens](std::size_t n)
            {
                const std::uint64_t r = tokens() % n;
                return static_cast<std::size_t>(r);
            };
            std::string many_tokens = "[";
            for (int i = 0; i < 20000; ++i)
            {
                const std::size_t length = 1 + draw(17);
                std::string digits(1, static_cast<char>('1' + draw(9)));
                for (std::size_t k = 1; k < length; ++k)
                {
                    digits += static_cast<char>('0' + draw(10));
                }
                digits += std::string(draw(4), '0'); // trailing zeros
                std::string token = draw(3) == 0 ? "-" : "";
                const std::size_t point = draw(digits.size() + 1);
                if (point == 0)
                {
                    token += "0." + std::string(draw(5), '0') + digits;
                }
                else
                {
                    token += digits.substr(0, point) + (point < digits.size() ? "." + digits.substr(point) : "");
                }
                // an exponent that keeps the value between about 1e-320 and 1e300
                const int exponent = static_cast<int>(draw(600)) - 300 - static_cast<int>(point);
                if (draw(4) != 0)
                {
                    token += (draw(2) == 0 ? "e" : "E") + std::string(exponent >= 0 && draw(2) == 0 ? "+" : "") + std::to_string(exponent);
                }
                else if (point == digits.size())
                {
                    token += ".0"; // (a float, not an integer)
                }
                many_tokens += (i != 0 ? "," : "") + token;
            }
            many_tokens += ']';
            const json_document many_doc = json_document::parse(many_tokens);
            CHECK(many_doc.root().dump() == json::parse(many_tokens).dump());
        }

        // tokens of 16 and 17 digits without an exponent (like GeoJSON
        // coordinates), which dump() converts in batches: doubles exactly
        // halfway between two candidates for the shortest digits, random
        // digits, and digits near a shorter decimal (...99999997,
        // ...00000003), whose rounding carries; in pairs and among other
        // values, so that the batches are interrupted; the last token near the
        // end of the text
        {
            std::mt19937_64 tokens(5627); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
            const auto draw = [&tokens](std::size_t n)
            {
                const std::uint64_t r = tokens() % n;
                return static_cast<std::size_t>(r);
            };
            std::string coordinates = "[754570942.33984373,257769445.56835938,858106901.94921875,97944964.876953125,"
                                      "[0.5,1e-7],[1.5,-0.0,2.5],[1E2,12.5,0.1,3.25,4.5,5.75,6.125,7.0,8.5],[],[1.5],[1,2.5],[2.5,\"x\"],[[1.5],2.5],";
            for (int i = 0; i < 20000; ++i)
            {
                const std::size_t length = 16 + draw(2);
                std::string digits(1, static_cast<char>('1' + draw(9)));
                const std::size_t kept = draw(3) == 0 ? length : 2 + draw(length - 3);
                for (std::size_t k = 1; k < kept; ++k)
                {
                    digits += static_cast<char>('0' + draw(10));
                }
                digits += std::string(length - kept, draw(2) == 0 ? '9' : '0');
                digits.back() = static_cast<char>('0' + draw(10));
                const std::size_t point = 1 + draw(9);
                const std::string token = (draw(2) == 0 ? "-" : "") + digits.substr(0, point) + "." + digits.substr(point);
                if (i != 0)
                {
                    coordinates += ',';
                }
                if (draw(8) == 0)
                {
                    coordinates += R"({"x":)";
                    coordinates += token;
                    coordinates += R"(,"s":"a"})";
                }
                else
                {
                    coordinates += '[';
                    coordinates += token;
                    coordinates += ',';
                    coordinates += token;
                    coordinates += ']';
                }
            }
            coordinates += ",-65.613616999999977]";
            const json_document parsed = json_document::parse(coordinates);
            const ordered_json j = ordered_json::parse(coordinates);
            CHECK(parsed.root().dump() == j.dump());
            CHECK(parsed.root().dump(1) == j.dump(1));
            CHECK(parsed.root().dump(-1, ' ', true) == j.dump(-1, ' ', true));
            CHECK(parsed.root().back().get<double>() == j.back().get<double>());
            CHECK(parsed.root().back().dump() == "-65.61361699999998");
            std::size_t i = 0;
            for (const json_view v : parsed.root())
            {
                const ordered_json& e = j[i++];
                CHECK(v.dump() == e.dump());
                if (v.is_array() && !v.empty() && v[0].is_number())
                {
                    CHECK(v[0].get<double>() == e[0].get<double>());
                }
            }

            // an editable document: edits move some arrays, so that the walk
            // leaves the order of the parsed nodes
            ordered_json_editable_document editable = ordered_json_editable_document::parse(coordinates);
            ordered_json expected = j;
            for (std::size_t k = 0; k < 20000; k += 97)
            {
                if (expected[k].is_array())
                {
                    editable.push_back(editable.root()[k], ordered_json(1.5));
                    expected[k].push_back(1.5);
                }
            }
            CHECK(editable.root().dump() == expected.dump());
        }

        // random doubles, written as parse() and dump() would
        std::mt19937_64 rng(1170); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
        std::string many = "[";
        for (int i = 0; i < 5000; ++i)
        {
            const std::uint64_t bits = rng();
            double x = 0;
            std::memcpy(&x, &bits, sizeof(x));
            if (std::isfinite(x))
            {
                many += (many.size() > 1 ? "," : "") + json(x).dump();
            }
        }
        many += ']';
        const json_document many_document = json_document::parse(many);
        CHECK(many_document.root().dump() == json::parse(many).dump());

        using json_float = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;
        const nlohmann::basic_json_document<json_float> float_document = nlohmann::basic_json_document<json_float>::parse("[0.1, 1.5e10, 3.4028235e38]");
        CHECK(float_document.root().dump() == json_float::parse("[0.1, 1.5e10, 3.4028235e38]").dump());
    }
}
