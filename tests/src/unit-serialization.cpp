//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// capture whether JSON_DELETE_DEPRECATED_FUNCTIONS was enabled on the command
// line *before* including json.hpp, since the library #undefs it once the header
// has been fully processed (see include/nlohmann/detail/macro_unscope.hpp); the
// tests of deprecated functions are skipped if these functions are deleted
#if defined(JSON_DELETE_DEPRECATED_FUNCTIONS) && (JSON_DELETE_DEPRECATED_FUNCTIONS == 1)
    #define JSON_TEST_DEPRECATED_FUNCTIONS_DELETED
#endif

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <array>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>

#include "test_utils.hpp"

TEST_CASE("serialization")
{
    SECTION("operator<<")
    {
        SECTION("no given width")
        {
            std::stringstream ss;
            const json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss << j;
            CHECK(ss.str() == "[\"foo\",1,2,3,false,{\"one\":1}]");
        }

        SECTION("given width")
        {
            std::stringstream ss;
            const json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss << std::setw(4) << j;
            CHECK(ss.str() ==
                  "[\n    \"foo\",\n    1,\n    2,\n    3,\n    false,\n    {\n        \"one\": 1\n    }\n]");
        }

        SECTION("given fill")
        {
            std::stringstream ss;
            const json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss << std::setw(1) << std::setfill('\t') << j;
            CHECK(ss.str() ==
                  "[\n\t\"foo\",\n\t1,\n\t2,\n\t3,\n\tfalse,\n\t{\n\t\t\"one\": 1\n\t}\n]");
        }
    }

#ifndef JSON_TEST_DEPRECATED_FUNCTIONS_DELETED
    SECTION("operator>>")
    {
        SECTION("no given width")
        {
            std::stringstream ss;
            const json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            j >> ss;
            CHECK(ss.str() == "[\"foo\",1,2,3,false,{\"one\":1}]");
        }

        SECTION("given width")
        {
            std::stringstream ss;
            const json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss.width(4);
            j >> ss;
            CHECK(ss.str() ==
                  "[\n    \"foo\",\n    1,\n    2,\n    3,\n    false,\n    {\n        \"one\": 1\n    }\n]");
        }

        SECTION("given fill")
        {
            std::stringstream ss;
            const json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss.width(1);
            ss.fill('\t');
            j >> ss;
            CHECK(ss.str() ==
                  "[\n\t\"foo\",\n\t1,\n\t2,\n\t3,\n\tfalse,\n\t{\n\t\t\"one\": 1\n\t}\n]");
        }
    }
#endif

    SECTION("dump")
    {
        SECTION("invalid character")
        {
            const json j = "ä\xA9ü";

            // dump() is nodiscard; the exception is thrown by dump() itself before it would return
            CHECK_THROWS_WITH_AS(utils::ignore_return_value(j.dump()), "[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9", json::type_error&);
            CHECK_THROWS_WITH_AS(utils::ignore_return_value(j.dump(1, ' ', false, json::error_handler_t::strict)), "[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9", json::type_error&);
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::ignore) == "\"äü\"");
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::replace) == "\"ä\xEF\xBF\xBDü\"");
            CHECK(j.dump(-1, ' ', true, json::error_handler_t::replace) == "\"\\u00e4\\ufffd\\u00fc\"");
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::keep) == "\"ä\xA9ü\"");
            CHECK(j.dump(-1, ' ', true, json::error_handler_t::keep) == "\"\\u00e4\xA9\\u00fc\"");
        }

        SECTION("invalid character (regression guard for shared UTF-8 decoder, see #5529)")
        {
            // dump_escaped_impl() now calls the UTF-8 decoder shared with the
            // binary readers (detail::decode() in string_utils.hpp) instead
            // of a private copy; the exact type_error.316 message/behavior
            // must stay byte-for-byte the same as before that extraction
            const json j = "ä\xA9ü";
            CHECK_THROWS_WITH_AS(utils::ignore_return_value(j.dump()), "[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9", json::type_error&);
        }

        SECTION("ending with incomplete character")
        {
            const json j = "123\xC2";

            // dump() is nodiscard; the exception is thrown by dump() itself before it would return
            CHECK_THROWS_WITH_AS(utils::ignore_return_value(j.dump()), "[json.exception.type_error.316] incomplete UTF-8 string; last byte: 0xC2", json::type_error&);
            CHECK_THROWS_AS(utils::ignore_return_value(j.dump(1, ' ', false, json::error_handler_t::strict)), json::type_error&);
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::ignore) == "\"123\"");
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::replace) == "\"123\xEF\xBF\xBD\"");
            CHECK(j.dump(-1, ' ', true, json::error_handler_t::replace) == "\"123\\ufffd\"");
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::keep) == "\"123\xC2\"");
            CHECK(j.dump(-1, ' ', true, json::error_handler_t::keep) == "\"123\xC2\"");
        }

        SECTION("unexpected character")
        {
            const json j = "123\xF1\xB0\x34\x35\x36";

            // dump() is nodiscard; the exception is thrown by dump() itself before it would return
            CHECK_THROWS_WITH_AS(utils::ignore_return_value(j.dump()), "[json.exception.type_error.316] invalid UTF-8 byte at index 5: 0x34", json::type_error&);
            CHECK_THROWS_AS(utils::ignore_return_value(j.dump(1, ' ', false, json::error_handler_t::strict)), json::type_error&);
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::ignore) == "\"123456\"");
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::replace) == "\"123\xEF\xBF\xBD\x34\x35\x36\"");
            CHECK(j.dump(-1, ' ', true, json::error_handler_t::replace) == "\"123\\ufffd456\"");
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::keep) == "\"123\xF1\xB0\x34\x35\x36\"");
            CHECK(j.dump(-1, ' ', true, json::error_handler_t::keep) == "\"123\xF1\xB0\x34\x35\x36\"");
        }

        SECTION("keep: valid characters are still escaped")
        {
            // an invalid byte followed by characters that must be escaped
            const json j = "\xC2\"\\\n\xFF\x05";
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::keep) == "\"\xC2\\\"\\\\\\n\xFF\\u0005\"");
            CHECK(j.dump(-1, ' ', true, json::error_handler_t::keep) == "\"\xC2\\\"\\\\\\n\xFF\\u0005\"");
        }

        SECTION("keep: truncated multibyte sequences")
        {
            CHECK(json("\xF0\x9F\x98").dump(-1, ' ', false, json::error_handler_t::keep) == "\"\xF0\x9F\x98\"");
            CHECK(json("\xF0\x9F\x98").dump(-1, ' ', true, json::error_handler_t::keep) == "\"\xF0\x9F\x98\"");
            CHECK(json("\xF0\x9F\x98" "a").dump(-1, ' ', false, json::error_handler_t::keep) == "\"\xF0\x9F\x98" "a\"");
            CHECK(json("\xF0\x9F\x98" "a").dump(-1, ' ', true, json::error_handler_t::keep) == "\"\xF0\x9F\x98" "a\"");
        }

        SECTION("keep: long string with many invalid bytes")
        {
            // exceeds the internal string buffer several times
            std::string input;
            std::string expected = "\"";
            for (int i = 0; i < 2000; ++i)
            {
                input += "\xFF\xE2\x82\n\xC3\xA4";
                expected += "\xFF\xE2\x82\\n\xC3\xA4";
            }
            expected += "\"";
            const json j = input;
            CHECK(j.dump(-1, ' ', false, json::error_handler_t::keep) == expected);
        }

        SECTION("U+FFFD Substitution of Maximal Subparts")
        {
            // Some tests (mostly) from
            // https://www.unicode.org/versions/Unicode11.0.0/ch03.pdf
            // Section 3.9 -- U+FFFD Substitution of Maximal Subparts

            auto test = [&](std::string const & input, std::string const & expected)
            {
                const json j = input;
                CHECK(j.dump(-1, ' ', true, json::error_handler_t::replace) == "\"" + expected + "\"");
            };

            test("\xC2", "\\ufffd");
            test("\xC2\x41\x42", "\\ufffd" "\x41" "\x42");
            test("\xC2\xF4", "\\ufffd" "\\ufffd");

            test("\xF0\x80\x80\x41", "\\ufffd" "\\ufffd" "\\ufffd" "\x41");
            test("\xF1\x80\x80\x41", "\\ufffd" "\x41");
            test("\xF2\x80\x80\x41", "\\ufffd" "\x41");
            test("\xF3\x80\x80\x41", "\\ufffd" "\x41");
            test("\xF4\x80\x80\x41", "\\ufffd" "\x41");
            test("\xF5\x80\x80\x41", "\\ufffd" "\\ufffd" "\\ufffd" "\x41");

            test("\xF0\x90\x80\x41", "\\ufffd" "\x41");
            test("\xF1\x90\x80\x41", "\\ufffd" "\x41");
            test("\xF2\x90\x80\x41", "\\ufffd" "\x41");
            test("\xF3\x90\x80\x41", "\\ufffd" "\x41");
            test("\xF4\x90\x80\x41", "\\ufffd" "\\ufffd" "\\ufffd" "\x41");
            test("\xF5\x90\x80\x41", "\\ufffd" "\\ufffd" "\\ufffd" "\x41");

            test("\xC0\xAF\xE0\x80\xBF\xF0\x81\x82\x41", "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\x41");
            test("\xED\xA0\x80\xED\xBF\xBF\xED\xAF\x41", "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\x41");
            test("\xF4\x91\x92\x93\xFF\x41\x80\xBF\x42", "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\x41" "\\ufffd""\\ufffd" "\x42");
            test("\xE1\x80\xE2\xF0\x91\x92\xF1\xBF\x41", "\\ufffd" "\\ufffd" "\\ufffd" "\\ufffd" "\x41");
        }
    }

    SECTION("to_string")
    {
        auto test = [&](std::string const & input, std::string const & expected)
        {
            using std::to_string;
            const json j = input;
            CHECK(to_string(j) == "\"" + expected + "\"");
        };

        test(R"({"x":5,"y":6})", R"({\"x\":5,\"y\":6})");
        test("{\"x\":[10,null,null,null]}", R"({\"x\":[10,null,null,null]})");
        test("test", "test");
        test("[3,\"false\",false]", R"([3,\"false\",false])");
    }
}

TEST_CASE_TEMPLATE("serialization for extreme integer values", T, int32_t, uint32_t, int64_t, uint64_t) // NOLINT(readability-math-missing-parentheses, bugprone-throwing-static-initialization)
{
    SECTION("minimum")
    {
        constexpr auto minimum = (std::numeric_limits<T>::min)();
        const json j = minimum;
        CHECK(j.dump() == std::to_string(minimum));
    }

    SECTION("maximum")
    {
        constexpr auto maximum = (std::numeric_limits<T>::max)();
        const json j = maximum;
        CHECK(j.dump() == std::to_string(maximum));
    }
}

TEST_CASE("dump with binary values")
{
    auto binary = json::binary({1, 2, 3, 4});
    auto binary_empty = json::binary({});
    auto binary_with_subtype = json::binary({1, 2, 3, 4}, 128);
    auto binary_empty_with_subtype = json::binary({}, 128);

    const json object = {{"key", binary}};
    const json object_empty = {{"key", binary_empty}};
    const json object_with_subtype = {{"key", binary_with_subtype}};
    const json object_empty_with_subtype = {{"key", binary_empty_with_subtype}};

    const json array = {"value", 1, binary};
    const json array_empty = {"value", 1, binary_empty};
    const json array_with_subtype = {"value", 1, binary_with_subtype};
    const json array_empty_with_subtype = {"value", 1, binary_empty_with_subtype};

    SECTION("normal")
    {
        CHECK(binary.dump() == "{\"bytes\":[1,2,3,4],\"subtype\":null}");
        CHECK(binary_empty.dump() == "{\"bytes\":[],\"subtype\":null}");
        CHECK(binary_with_subtype.dump() == "{\"bytes\":[1,2,3,4],\"subtype\":128}");
        CHECK(binary_empty_with_subtype.dump() == "{\"bytes\":[],\"subtype\":128}");

        CHECK(object.dump() == "{\"key\":{\"bytes\":[1,2,3,4],\"subtype\":null}}");
        CHECK(object_empty.dump() == "{\"key\":{\"bytes\":[],\"subtype\":null}}");
        CHECK(object_with_subtype.dump() == "{\"key\":{\"bytes\":[1,2,3,4],\"subtype\":128}}");
        CHECK(object_empty_with_subtype.dump() == "{\"key\":{\"bytes\":[],\"subtype\":128}}");

        CHECK(array.dump() == "[\"value\",1,{\"bytes\":[1,2,3,4],\"subtype\":null}]");
        CHECK(array_empty.dump() == "[\"value\",1,{\"bytes\":[],\"subtype\":null}]");
        CHECK(array_with_subtype.dump() == "[\"value\",1,{\"bytes\":[1,2,3,4],\"subtype\":128}]");
        CHECK(array_empty_with_subtype.dump() == "[\"value\",1,{\"bytes\":[],\"subtype\":128}]");
    }

    SECTION("pretty-printed")
    {
        CHECK(binary.dump(4) == "{\n"
              "    \"bytes\": [1, 2, 3, 4],\n"
              "    \"subtype\": null\n"
              "}");
        CHECK(binary_empty.dump(4) == "{\n"
              "    \"bytes\": [],\n"
              "    \"subtype\": null\n"
              "}");
        CHECK(binary_with_subtype.dump(4) == "{\n"
              "    \"bytes\": [1, 2, 3, 4],\n"
              "    \"subtype\": 128\n"
              "}");
        CHECK(binary_empty_with_subtype.dump(4) == "{\n"
              "    \"bytes\": [],\n"
              "    \"subtype\": 128\n"
              "}");

        CHECK(object.dump(4) == "{\n"
              "    \"key\": {\n"
              "        \"bytes\": [1, 2, 3, 4],\n"
              "        \"subtype\": null\n"
              "    }\n"
              "}");
        CHECK(object_empty.dump(4) == "{\n"
              "    \"key\": {\n"
              "        \"bytes\": [],\n"
              "        \"subtype\": null\n"
              "    }\n"
              "}");
        CHECK(object_with_subtype.dump(4) == "{\n"
              "    \"key\": {\n"
              "        \"bytes\": [1, 2, 3, 4],\n"
              "        \"subtype\": 128\n"
              "    }\n"
              "}");
        CHECK(object_empty_with_subtype.dump(4) == "{\n"
              "    \"key\": {\n"
              "        \"bytes\": [],\n"
              "        \"subtype\": 128\n"
              "    }\n"
              "}");

        CHECK(array.dump(4) == "[\n"
              "    \"value\",\n"
              "    1,\n"
              "    {\n"
              "        \"bytes\": [1, 2, 3, 4],\n"
              "        \"subtype\": null\n"
              "    }\n"
              "]");
        CHECK(array_empty.dump(4) == "[\n"
              "    \"value\",\n"
              "    1,\n"
              "    {\n"
              "        \"bytes\": [],\n"
              "        \"subtype\": null\n"
              "    }\n"
              "]");
        CHECK(array_with_subtype.dump(4) == "[\n"
              "    \"value\",\n"
              "    1,\n"
              "    {\n"
              "        \"bytes\": [1, 2, 3, 4],\n"
              "        \"subtype\": 128\n"
              "    }\n"
              "]");
        CHECK(array_empty_with_subtype.dump(4) == "[\n"
              "    \"value\",\n"
              "    1,\n"
              "    {\n"
              "        \"bytes\": [],\n"
              "        \"subtype\": 128\n"
              "    }\n"
              "]");
    }
}

TEST_CASE("dump for basic_json with long double number_float_t")
{
    // Custom basic_json instantiation with long double as NumberFloatType.
    // On platforms where long double is wider than double (e.g. GCC/Clang on
    // Linux/macOS x86_64), dump() goes through the snprintf path in
    // serializer::dump_float(x, std::false_type). That branch must use the
    // "%.*Lg" format specifier; using "%.*g" with a long double argument is
    // undefined behavior and corrupts the output.
    using long_double_json = nlohmann::json::with_float_t<long double>;

    SECTION("round-trip dump/parse")
    {
        constexpr std::array<long double, 13> values =
        {
            {
                0.0L, -0.0L, 1.0L, -1.0L,
                0.5L, -0.5L, 1.5L, -2.25L,
                1.23e45L, 1.23e-45L,
                (std::numeric_limits<long double>::min)(),
                std::numeric_limits<long double>::lowest(),
                (std::numeric_limits<long double>::max)()
            }
        };

        for (long double v : values)
        {
            const long_double_json j = v;
            const auto s = j.dump();
            const auto j2 = long_double_json::parse(s);
            CHECK(j2.template get<long double>() == v);
        }
    }

    SECTION("exact dump string for simple values")
    {
        CHECK(long_double_json(0.5L).dump()   == "0.5");
        CHECK(long_double_json(-0.5L).dump()  == "-0.5");
        CHECK(long_double_json(1.5L).dump()   == "1.5");
        CHECK(long_double_json(-2.25L).dump() == "-2.25");
        CHECK(long_double_json(0.0L).dump()   == "0.0");
        CHECK(long_double_json(1.0L).dump()   == "1.0");
        CHECK(long_double_json(-1.0L).dump()  == "-1.0");
        CHECK(long_double_json(100.0L).dump() == "100.0");
    }

    SECTION("NaN and infinity dump as null")
    {
        CHECK(long_double_json(std::numeric_limits<long double>::quiet_NaN()).dump() == "null");

        // Probe the platform's runtime behavior — `volatile` forces a runtime
        // call rather than constexpr-folding to a known answer at compile time.
        // Skip the infinity assertions if std::isfinite() doesn't actually
        // recognize long double infinity on this platform (notably, Valgrind
        // 3.22's x87 80-bit emulation reports +/-inf as a large finite value).
        // TODO(rusloker): remove this guard once Valgrind's 80-bit long double
        // support ships (Valgrind bug https://bugs.kde.org/show_bug.cgi?id=197915,
        // ASSIGNED since 2009 — the Valgrind project tracks its bugs on
        // bugs.kde.org) and the minimum supported Valgrind version contains it.
        const volatile long double inf_probe = std::numeric_limits<long double>::infinity();
        if (!std::isfinite(inf_probe))
        {
            CHECK(long_double_json(std::numeric_limits<long double>::infinity()).dump() == "null");
            CHECK(long_double_json(-std::numeric_limits<long double>::infinity()).dump() == "null");
        }
    }

    SECTION("dump output matches double for exactly-representable values")
    {
        auto check_same = [](long double v_ld, double v_d)
        {
            const long_double_json j_ld = v_ld;
            const json j_d = v_d;
            CHECK(j_ld.dump() == j_d.dump());
        };

        check_same(0.0L,    0.0);
        check_same(0.5L,    0.5);
        check_same(-0.5L,  -0.5);
        check_same(1.5L,    1.5);
        check_same(-2.25L, -2.25);
        check_same(1.0L,    1.0);
        check_same(100.0L,  100.0);
    }
}

TEST_CASE("serialization of strings (bulk fast path)")
{
    // These cases exercise the SWAR bulk-copy fast path in dump_escaped and the
    // internal write buffer: long runs, escapes interrupting runs, 0x7F/DEL,
    // multibyte UTF-8 under both ensure_ascii settings, and payloads larger than
    // the write buffer.

    SECTION("long unescaped ASCII exceeds the write buffer")
    {
        const std::string big(3000, 'a');
        const json j = big;
        CHECK(j.dump() == '"' + big + '"');
        CHECK(j.dump(-1, ' ', true) == '"' + big + '"');
        // round-trips
        CHECK(json::parse(j.dump()) == j);
    }

    SECTION("runs interrupted by escapes")
    {
        const json j = std::string(500, 'x') + "\n\"\\" + std::string(500, 'y');
        const std::string out = j.dump();
        CHECK(out == '"' + std::string(500, 'x') + "\\n\\\"\\\\" + std::string(500, 'y') + '"');
        CHECK(json::parse(out) == j);
    }

    SECTION("DEL (0x7F) depends on ensure_ascii")
    {
        const json j = std::string("a\x7f" "b");
        CHECK(j.dump(-1, ' ', false) == "\"a\x7f" "b\"");   // copied verbatim
        CHECK(j.dump(-1, ' ', true) == "\"a\\u007fb\"");    // escaped
    }

    SECTION("multibyte UTF-8 under both ensure_ascii settings")
    {
        const json j = std::string("A\xc3\xa9\xe4\xbd\xa0\xf0\x9f\x98\x80Z"); // A é 你 😀 Z
        // not escaping non-ASCII: bytes are copied through the bulk validator
        CHECK(j.dump(-1, ' ', false) == "\"A\xc3\xa9\xe4\xbd\xa0\xf0\x9f\x98\x80Z\"");
        // ensure_ascii: escaped (with a surrogate pair for the emoji)
        CHECK(j.dump(-1, ' ', true) == "\"A\\u00e9\\u4f60\\ud83d\\ude00Z\"");
        CHECK(json::parse(j.dump(-1, ' ', true)) == j);
    }

    SECTION("many small structural writes exceed the write buffer")
    {
        json arr = json::array();
        for (int i = 0; i < 2000; ++i)
        {
            arr.push_back(i);
        }
        const std::string out = arr.dump();
        CHECK(out.front() == '[');
        CHECK(out.back() == ']');
        CHECK(json::parse(out) == arr);

        json obj = json::object();
        for (int i = 0; i < 500; ++i)
        {
            obj["key" + std::to_string(i)] = i;
        }
        CHECK(json::parse(obj.dump()) == obj);
        CHECK(json::parse(obj.dump(2)) == obj);

        // an array of many empty strings emits a long run of single-character
        // writes ('"', '"', ',') at shallow nesting depth, so the write buffer
        // fills and flushes mid-run without the deep recursion that would
        // overflow the stack on some debug builds
        json many_empty = json::array();
        for (int i = 0; i < 500; ++i)
        {
            many_empty.push_back("");
        }
        const std::string out2 = many_empty.dump();
        CHECK(out2.size() > 1024); // spans multiple write-buffer flushes
        CHECK(out2.front() == '[');
        CHECK(out2.back() == ']');
        CHECK(json::parse(out2) == many_empty);
    }

    SECTION("invalid UTF-8 handling is unaffected by the fast path")
    {
        const json j = std::string("valid\xff" "more");
        CHECK_THROWS_WITH_AS(utils::ignore_return_value(j.dump()), "[json.exception.type_error.316] invalid UTF-8 byte at index 5: 0xFF", json::type_error&);
        CHECK(j.dump(-1, ' ', false, json::error_handler_t::replace) == "\"valid\xef\xbf\xbd" "more\"");
        CHECK(j.dump(-1, ' ', true, json::error_handler_t::replace) == "\"valid\\ufffdmore\"");
        CHECK(j.dump(-1, ' ', false, json::error_handler_t::ignore) == "\"validmore\"");
    }
}

TEST_CASE("indentation is written straight into the write buffer")
{
    // put_indent() memsets the indentation into the write buffer instead of
    // copying it out of a pre-grown indentation string. These cases cover an
    // indentation wider than the buffer, a non-space indentation character, and
    // nesting deep enough that the accumulated indentation spans several
    // buffer-fulls - the situations the old grow-a-string approach got wrong.

    SECTION("indent_step wider than the write buffer")
    {
        const json j = {{"a", 1}};
        // 2000 > the 1024-byte write buffer, and > the 512 the indentation
        // string used to start at
        CHECK(j.dump(2000) == "{\n" + std::string(2000, ' ') + "\"a\": 1\n}");
        // several whole buffer-fulls, so the buffer is refilled once and then
        // flushed repeatedly
        CHECK(j.dump(5000) == "{\n" + std::string(5000, ' ') + "\"a\": 1\n}");
        CHECK(j.dump(5000, '\t') == "{\n" + std::string(5000, '\t') + "\"a\": 1\n}");
        // an exact multiple of the buffer size
        CHECK(j.dump(4096) == "{\n" + std::string(4096, ' ') + "\"a\": 1\n}");
    }

    SECTION("a non-space indentation character is used throughout")
    {
        const json j = {{"a", 1}};
        // 600 is past the point where the indentation used to be grown, which
        // is where a hard-coded space would have shown up
        CHECK(j.dump(600, '\t') == "{\n" + std::string(600, '\t') + "\"a\": 1\n}");
        CHECK(j.dump(3, '.') == "{\n...\"a\": 1\n}");
    }

    SECTION("accumulated indentation spans several buffer-fulls")
    {
        // five levels deep at 400 per level: the innermost value is indented by
        // 2000 characters, reached in steps that each straddle the buffer end
        json j = json::array({1});
        for (int i = 0; i < 4; ++i)
        {
            j = json::array({j});
        }

        const std::string out = j.dump(400);
        CHECK(out.find(std::string("\n") + std::string(2000, ' ') + "1\n") != std::string::npos);
        CHECK(json::parse(out) == j);
    }

    SECTION("binary values are indented the same way")
    {
        // a binary value is serialized as an object with "bytes" and
        // "subtype" keys; the byte array itself is always written compactly
        // (see dump_byte()), so only the surrounding object's indentation
        // goes through put_indent()
        const json j = json::binary({1, 2, 3}, 128);
        CHECK(j.dump(2000) == "{\n" + std::string(2000, ' ') + "\"bytes\": [1, 2, 3],\n"
              + std::string(2000, ' ') + "\"subtype\": 128\n}");
        CHECK(j.dump(2000, '\t') == "{\n" + std::string(2000, '\t') + "\"bytes\": [1, 2, 3],\n"
              + std::string(2000, '\t') + "\"subtype\": 128\n}");
    }

    SECTION("indentation is unchanged for ordinary widths")
    {
        const json j = {{"a", {1, 2}}, {"b", nullptr}};
        CHECK(j.dump(2) == "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": null\n}");
        CHECK(j.dump(0) == "{\n\"a\": [\n1,\n2\n],\n\"b\": null\n}");
    }
}

TEST_CASE("serialization of deeply nested values")
{
    // dump() descends into a bounded number of levels and writes out whatever
    // is nested deeper than that without the call stack; see
    // https://github.com/nlohmann/json/issues/5387

    SECTION("nested deeper than the call stack could follow")
    {
        // parsing is iterative, so building these costs little
        const std::size_t depth = 100000;

        const std::string array_text = std::string(depth, '[') + '0' + std::string(depth, ']');
        CHECK(json::parse(array_text).dump() == array_text);

        std::string object_text;
        object_text.reserve((6 * depth) + 1);
        for (std::size_t i = 0; i < depth; ++i)
        {
            object_text += "{\"a\":";
        }
        object_text += '1';
        object_text.append(depth, '}');
        CHECK(json::parse(object_text).dump() == object_text);
    }

    SECTION("depths around the bound of the descent")
    {
        // Cover every depth around the bound, so that the two ways of writing a
        // value are known to meet cleanly - wherever the bound is set.
        for (std::size_t d = 1; d <= 300; ++d)
        {
            CAPTURE(d)

            const std::string array_text = std::string(d, '[') + '7' + std::string(d, ']');
            CHECK(json::parse(array_text).dump() == array_text);

            std::string object_text;
            for (std::size_t i = 0; i < d; ++i)
            {
                object_text += "{\"k\":";
            }
            object_text += '7';
            object_text.append(d, '}');
            CHECK(json::parse(object_text).dump() == object_text);
        }
    }

    SECTION("pretty-printing across the bound")
    {
        for (std::size_t d = 120; d <= 140; ++d)
        {
            CAPTURE(d)

            const json j = json::parse(std::string(d, '[') + '7' + std::string(d, ']'));

            std::string expected;
            for (std::size_t i = 0; i < d; ++i)
            {
                expected += std::string(2 * i, ' ') + "[\n";
            }
            expected += std::string(2 * d, ' ') + '7';
            for (std::size_t i = d; i > 0; --i)
            {
                expected += '\n' + std::string(2 * (i - 1), ' ') + ']';
            }

            CHECK(j.dump(2) == expected);
        }
    }

    SECTION("an empty container below the bound")
    {
        // an empty container is written out in full and never descended into,
        // so it must not gain a newline when it is reached iteratively
        for (std::size_t d = 125; d <= 135; ++d)
        {
            CAPTURE(d)

            const std::string compact = std::string(d, '[') + "[]" + std::string(d, ']');
            CHECK(json::parse(compact).dump() == compact);

            const std::string with_object = std::string(d, '[') + "{}" + std::string(d, ']');
            CHECK(json::parse(with_object).dump() == with_object);
        }
    }
}

namespace
{
// wraps @a inner into @a depth single-element arrays
json wrap_in_arrays(const json& inner, const std::size_t depth)
{
    json j = inner;
    for (std::size_t i = 0; i < depth; ++i)
    {
        j = json::array({std::move(j)});
    }
    return j;
}

// what wrap_in_arrays(inner, depth).dump(2) is expected to be: the arrays
// around inner.dump(2), with inner's own lines indented by the depth
std::string expected_pretty_in_arrays(const json& inner, const std::size_t depth)
{
    std::string expected;
    for (std::size_t i = 0; i < depth; ++i)
    {
        expected += std::string(2 * i, ' ') + "[\n";
    }

    const std::string indent(2 * depth, ' ');
    expected += indent;
    for (const char c : inner.dump(2))
    {
        expected += c;
        if (c == '\n')
        {
            expected += indent;
        }
    }

    for (std::size_t i = depth; i > 0; --i)
    {
        expected += '\n' + std::string(2 * (i - 1), ' ') + ']';
    }
    return expected;
}
} // namespace

TEST_CASE("serialization of every kind of value below the bound of the descent")
{
    // Values nested deeper than the bound are written without the call stack,
    // by code of their own; each kind of value must come out the same there as
    // it does at the top level, compact and pretty-printed.
    std::vector<json> values =
    {
        json::parse(R"({"a": 1, "b": [1, 2, {"c": "x"}], "d": {}, "e": []})"),
        json::parse(R"([1, [2, 3], {"k": null}, "s"])"),
        json::object(),
        json::array(),
        json::binary({1, 2, 3}, 42),
        json::binary({1, 2, 3}),
        json::binary({}, 7),
        json::binary({}),
        "a string with \"escapes\"\n",
        true,
        false,
        -42,
        42u,
        1.5,
        nullptr,
        json(json::value_t::discarded),
    };
    // a pretty-printed object whose members are themselves deep
    values.push_back({{"x", wrap_in_arrays(1, 5)}, {"y", {{"z", 2}}}});

    for (const std::size_t depth : std::vector<std::size_t> {1, 200})
    {
        CAPTURE(depth)
        for (const auto& inner : values)
        {
            CAPTURE(inner.dump())
            const json j = wrap_in_arrays(inner, depth);
            CHECK(j.dump() == std::string(depth, '[') + inner.dump() + std::string(depth, ']'));
            CHECK(j.dump(2) == expected_pretty_in_arrays(inner, depth));
        }
    }

    SECTION("pretty-printed objects across the bound")
    {
        for (std::size_t d = 120; d <= 140; ++d)
        {
            CAPTURE(d)

            // built from the inside out: {"k": <level below>, "n": <level>}
            json j = 7;
            std::string expected = "7";
            for (std::size_t i = d; i > 0; --i)
            {
                j = json({{"k", std::move(j)}, {"n", i}});

                const std::string indent(2 * i, ' ');
                const std::string outer_indent(2 * (i - 1), ' ');
                std::string next = "{\n";
                next += indent;
                next += "\"k\": ";
                next += expected;
                next += ",\n";
                next += indent;
                next += "\"n\": ";
                next += std::to_string(i);
                next += '\n';
                next += outer_indent;
                next += '}';
                expected = std::move(next);
            }

            CHECK(j.dump(2) == expected);
            CHECK(json::parse(j.dump(2)) == j);
            CHECK(json::parse(j.dump()) == j);
        }
    }
}

TEST_CASE("serializer buffers are flushed mid-string and mid-binary")
{
    SECTION("a long run of escaped characters")
    {
        // each character is escaped on its own, so the escape buffer fills up
        const json newlines = std::string(600, '\n');
        std::string expected = "\"";
        for (int i = 0; i < 600; ++i)
        {
            expected += "\\n";
        }
        expected += '"';
        CHECK(newlines.dump() == expected);

        // every character is \u-escaped under ensure_ascii
        std::string umlauts;
        std::string escaped_umlauts = "\"";
        for (int i = 0; i < 300; ++i)
        {
            umlauts += "\xC3\xA4";
            escaped_umlauts += "\\u00e4";
        }
        escaped_umlauts += '"';
        CHECK(json(umlauts).dump(-1, ' ', true) == escaped_umlauts);
    }

    SECTION("a large binary value")
    {
        std::vector<std::uint8_t> bytes(3000);
        std::string expected_bytes;
        std::string expected_pretty_bytes;
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            bytes[i] = static_cast<std::uint8_t>(i % 256);
            expected_bytes += (i == 0 ? "" : ",") + std::to_string(i % 256);
            expected_pretty_bytes += (i == 0 ? "" : ", ") + std::to_string(i % 256);
        }
        const json j = json::binary(bytes);
        CHECK(j.dump() == "{\"bytes\":[" + expected_bytes + "],\"subtype\":null}");
        CHECK(j.dump(2) == "{\n  \"bytes\": [" + expected_pretty_bytes + "],\n  \"subtype\": null\n}");
    }
}

TEST_CASE("serialization boundary values for the write buffer")
{
    // write_buffer is a std::array<char, 1024> (write_buffer_size). put_string()
    // guards it with two checks, and each must be exercised exactly on and one
    // past its own boundary: a heap overflow in a different manual buffer path
    // (the dump(1100) indent buffer) once survived 100% line coverage because
    // every test that touched it only ever grew the buffer by a single step,
    // never landing on the exact edge of the comparison that protects it.
    //
    // - straight-through: put_string() bypasses write_buffer entirely and
    //   writes directly to the output adapter once `length >= write_buffer.size()`.
    // - flush-then-copy: otherwise, if `write_buffer_pos + length > write_buffer.size()`,
    //   put_string() flushes what is pending and then memcpy's the new run into
    //   the freshly emptied buffer.

    SECTION("top-level string exercises the straight-through guard (length >= 1024)")
    {
        // dump() of a bare string writes the opening quote with put_char()
        // (write_buffer_pos: 0 -> 1), then the body with put_string(). With
        // write_buffer_pos == 1, `1 + length > 1024` and `length >= 1024` flip
        // together at length 1024, so 1023/1024/1025 cover "just under",
        // "exactly at" and "just over" the guard in one move: 1023 is copied
        // into the buffer (filling it exactly), 1024 and 1025 bypass it.
        for (const std::size_t len :
                {
                    std::size_t{1023}, std::size_t{1024}, std::size_t{1025}
                })
        {
            CAPTURE(len)
            const std::string body(len, 'a');
            const json j = body;
            const std::string expected = '"' + body + '"';

            CHECK(j.dump() == expected);

            std::ostringstream o;
            o << j;
            CHECK(o.str() == expected);
        }
    }

    SECTION("string nested in an array exercises the flush-then-copy guard")
    {
        // json::array({body}) writes '[' then '"' before the body, so
        // write_buffer_pos == 2 when put_string() is entered for it. The
        // body's last byte then lands at logical offset 2 + len: len == 1022
        // lands exactly on offset 1024 (2 + 1022 == write_buffer.size(), so the
        // strict "> " guard does not fire and the body fits snugly), while
        // len == 1023 lands one past it at offset 1025 (2 + 1023 > 1024),
        // which must flush what's pending before copying the body in.
        for (const std::size_t len :
                {
                    std::size_t{1022}, std::size_t{1023}
                })
        {
            CAPTURE(len)
            const std::string body(len, 'a');
            const json j = json::array({body});
            const std::string expected = "[\"" + body + "\"]";

            CHECK(j.dump() == expected);

            std::ostringstream o;
            o << j;
            CHECK(o.str() == expected);

            CHECK(json::parse(j.dump()) == j);
        }
    }
}

TEST_CASE("serialization boundary values for the string buffer")
{
    // string_buffer is a std::array<char, 512>. dump_escaped_impl() flushes it
    // mid-string once fewer than 13 bytes remain (`string_buffer.size() - bytes
    // < 13`), 13 being one more than the most a single code point can ever
    // write at once (a surrogate pair: two back-to-back "\uXXXX" escapes, 12
    // bytes). Characters below 0x60 (control characters, '"' and '\\') are
    // escaped straight into the write buffer and never reach string_buffer, so
    // under ensure_ascii it fills in steps of 6 (one "\uXXXX" unit for a
    // character below U+10000) or 12 (a surrogate pair). With 2-byte characters
    // such as U+00E4, `bytes` takes multiples of 6 at the point the check runs;
    // the tightest values reachable are therefore 498 (512 - 498 == 14, after
    // 83 characters) and 504 (512 - 504 == 8, after 84 characters, where the
    // flush fires immediately and resets bytes to 0).

    SECTION("a run of 6-byte escapes lands bytes on, and one step past, the flush threshold")
    {
        for (const int count :
                {
                    83, 84, 85
                })
        {
            CAPTURE(count)
            std::string umlauts;
            std::string expected = "\"";
            for (int i = 0; i < count; ++i)
            {
                umlauts += "\xC3\xA4";
                expected += "\\u00e4";
            }
            expected += '"';
            CHECK(json(umlauts).dump(-1, ' ', true) == expected);
        }
    }

    SECTION("a prefix leaves the tightest reachable margin before a 12-byte surrogate pair")
    {
        // U+1F600 (the "\xF0\x9F\x98\x80" UTF-8 bytes) is dumped under
        // ensure_ascii as the 12-byte surrogate pair "\ud83d\ude00"; that
        // write happens in a single step with no intermediate flush check, so
        // it is the write most exposed by an off-by-one in the "< 13" guard.
        // A prefix of 83 U+00E4 characters leaves exactly 14 bytes of headroom
        // (512 - 498), the smallest margin the guard ever actually allows
        // into a new code point; 84 characters instead trigger the guard's own
        // flush first, so the emoji starts from a freshly emptied (512-byte)
        // buffer, and 85 repeats that with one more escape already past the
        // reset. Together they cover the margin the guard allows landing on,
        // one step before, and one step after - all must still produce the
        // identical, correct escapes.
        for (const int prefix_count :
                {
                    83, 84, 85
                })
        {
            CAPTURE(prefix_count)
            std::string prefix;
            std::string expected_prefix;
            for (int i = 0; i < prefix_count; ++i)
            {
                prefix += "\xC3\xA4";
                expected_prefix += "\\u00e4";
            }
            const std::string emoji = "\xF0\x9F\x98\x80";
            const json j = prefix + emoji;

            // without ensure_ascii, the whole string is copied unchanged
            std::string expected_raw = "\"";
            expected_raw += prefix;
            expected_raw += emoji;
            expected_raw += '"';
            std::string expected_ascii = "\"";
            expected_ascii += expected_prefix;
            expected_ascii += R"(\ud83d\ude00")";
            CHECK(j.dump(-1, ' ', false) == expected_raw);
            CHECK(j.dump(-1, ' ', true) == expected_ascii);
            CHECK(json::parse(j.dump(-1, ' ', true)) == j);
            CHECK(json::parse(j.dump(-1, ' ', false)) == j);
        }
    }

    SECTION("SWAR bulk-copy stride: k plain bytes followed by a byte handled individually")
    {
        // string_bulk_run()/find_ascii_copyable_run() (string_scan.hpp) scan 8
        // bytes at a time and fall back to a byte-at-a-time tail scan for
        // what is left over. k from 0 to 17 spans zero, one and two full
        // 8-byte strides plus a 1-byte tail, so every possible stopping point
        // within and right after the SIMD stride is covered.
        for (std::size_t k = 0; k <= 17; ++k)
        {
            CAPTURE(k)
            const std::string prefix(k, 'a');

            // (a) the run is stopped by a quote that must itself be escaped
            {
                const json j = prefix + "\"";
                CHECK(j.dump() == '"' + prefix + "\\\"" + '"');
            }

            // (b) the run is stopped by a control character
            {
                const json j = prefix + "\x01";
                CHECK(j.dump() == '"' + prefix + "\\u0001" + '"');
            }

            // (c) the run is stopped by a non-ASCII byte under ensure_ascii
            {
                const json j = prefix + "\xC3\xA9"; // prefix + 'é'
                CHECK(j.dump(-1, ' ', true) == '"' + prefix + "\\u00e9" + '"');
            }
        }
    }
}

namespace
{
// appends the escaped form of the ASCII character c to out; written
// independently of the table in serializer::ascii_escapes()
void append_escaped_ascii(std::string& out, const char c, const bool ensure_ascii)
{
    const auto byte = static_cast<unsigned char>(c);
    switch (byte)
    {
        case '\b':
            out += "\\b";
            break;
        case '\t':
            out += "\\t";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\r':
            out += "\\r";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        default:
            if (byte < 0x20 || (ensure_ascii && byte == 0x7F))
            {
                // byte < 0x80, so the first two hex digits are 0
                const char* const hex = "0123456789abcdef";
                out += "\\u00";
                out += hex[byte >> 4U];
                out += hex[byte & 0x0FU];
            }
            else
            {
                out += c;
            }
            break;
    }
}

// reference escaper for ASCII strings
std::string reference_escape_ascii(const std::string& s, const bool ensure_ascii)
{
    std::string result = "\"";
    for (const char c : s)
    {
        append_escaped_ascii(result, c, ensure_ascii);
    }
    result += '"';
    return result;
}
} // namespace

TEST_CASE("characters below 0x60 are escaped from a table straight into the write buffer")
{
    SECTION("every ASCII character at every position")
    {
        // lengths up to 17 cover the 8-byte strides of the bulk scanner on
        // both sides of the character, so the scanner stops at it from every
        // offset
        for (std::size_t length = 1; length <= 17; ++length)
        {
            for (std::size_t pos = 0; pos < length; ++pos)
            {
                for (unsigned int c = 0; c < 0x80; ++c)
                {
                    std::string s(length, 'a');
                    s[pos] = static_cast<char>(c);
                    CAPTURE(length)
                    CAPTURE(pos)
                    CAPTURE(c)
                    const json j = s;
                    CHECK(j.dump(-1, ' ', false) == reference_escape_ascii(s, false));
                    CHECK(j.dump(-1, ' ', true) == reference_escape_ascii(s, true));
                }
            }
        }
    }

    SECTION("runs of escaped characters")
    {
        std::string s;
        for (unsigned int c = 0; c < 0x20; ++c)
        {
            s += static_cast<char>(c);
        }
        s += R"("\"\)";
        CHECK(json(s).dump() == reference_escape_ascii(s, false));
        CHECK(json(s).dump(-1, ' ', true) == reference_escape_ascii(s, true));
    }

    SECTION("escapes straddle the end of the write buffer")
    {
        // the 8-byte store of a table entry needs room for all 8 bytes, even
        // when the escape itself is shorter; a prefix of k plain characters
        // shifts the 6-byte escapes across every offset of the 1024-byte
        // write buffer
        for (std::size_t k = 0; k < 8; ++k)
        {
            CAPTURE(k)
            const std::string s = std::string(k, 'a') + std::string(400, '\x01');
            CHECK(json(s).dump() == reference_escape_ascii(s, false));
            CHECK(json::array({s, s}).dump() == "[" + reference_escape_ascii(s, false) + "," + reference_escape_ascii(s, false) + "]");
        }
    }

    SECTION("pending \\u escapes of non-ASCII characters are written first")
    {
        // under ensure_ascii, U+00E4 is \u-escaped into the string buffer;
        // a following escape from the table must not overtake it
        const json j = "\xC3\xA4\n\xC3\xA4\"\xF0\x9F\x98\x80\\";
        CHECK(j.dump(-1, ' ', true) == "\"\\u00e4\\n\\u00e4\\\"\\ud83d\\ude00\\\\\"");
        CHECK(j.dump(-1, ' ', false) == "\"\xC3\xA4\\n\xC3\xA4\\\"\xF0\x9F\x98\x80\\\\\"");
    }

    SECTION("escapes after invalid UTF-8 for every error handler")
    {
        const json j = "a\xFF\n\xC3\"";
        CHECK_THROWS_WITH_AS(utils::ignore_return_value(j.dump()), "[json.exception.type_error.316] invalid UTF-8 byte at index 1: 0xFF", json::type_error&);
        CHECK(j.dump(-1, ' ', false, json::error_handler_t::ignore) == "\"a\\n\\\"\"");
        CHECK(j.dump(-1, ' ', true, json::error_handler_t::ignore) == "\"a\\n\\\"\"");
        CHECK(j.dump(-1, ' ', false, json::error_handler_t::replace) == "\"a\xEF\xBF\xBD\\n\xEF\xBF\xBD\\\"\"");
        CHECK(j.dump(-1, ' ', true, json::error_handler_t::replace) == "\"a\\ufffd\\n\\ufffd\\\"\"");
        CHECK(j.dump(-1, ' ', false, json::error_handler_t::keep) == "\"a\xFF\\n\xC3\\\"\"");
        CHECK(j.dump(-1, ' ', true, json::error_handler_t::keep) == "\"a\xFF\\n\xC3\\\"\"");
    }
}

namespace
{
// expected result of dumping a string: the output, or (with
// error_handler_t::strict) the message of the type_error.316 exception
struct expected_dump
{
    bool throws = false;
    std::string text{}; // NOLINT(readability-redundant-member-init)
};

std::string upper_hex_byte(const unsigned char byte)
{
    const char* const hex = "0123456789ABCDEF";
    return std::string(1, hex[byte >> 4U]) + hex[byte & 0x0FU];
}

void append_u_escape(std::string& out, const std::uint32_t code_unit)
{
    const char* const hex = "0123456789abcdef";
    out += "\\u";
    for (int shift = 12; shift >= 0; shift -= 4)
    {
        out += hex[(code_unit >> static_cast<unsigned int>(shift)) & 0x0FU];
    }
}

void append_replacement_character(std::string& out, const bool ensure_ascii)
{
    out += ensure_ascii ? "\\ufffd" : "\xEF\xBF\xBD";
}

// reference serializer for arbitrary byte strings, written from the documented
// behavior of dump() and independently of serializer::dump_escaped(): UTF-8 is
// decoded strictly (well-formed sequences as in Table 3-7 of the Unicode
// Standard), and each ill-formed sequence is handled as the error handler says
expected_dump reference_dump_string(const std::string& s, const bool ensure_ascii, const json::error_handler_t error_handler)
{
    expected_dump result;
    std::string& out = result.text;
    out = "\"";

    // handle the ill-formed bytes s[begin, end), of which s[index] is the byte
    // that could not be decoded; returns false if an exception is expected
    const auto ill_formed = [&](const std::size_t begin, const std::size_t end, const std::size_t index)
    {
        switch (error_handler)
        {
            case json::error_handler_t::strict:
                result.throws = true;
                out = "[json.exception.type_error.316] invalid UTF-8 byte at index " + std::to_string(index) + ": 0x" + upper_hex_byte(static_cast<unsigned char>(s[index]));
                return false;
            case json::error_handler_t::ignore:
                break;
            case json::error_handler_t::replace:
                append_replacement_character(out, ensure_ascii);
                break;
            case json::error_handler_t::keep:
            default:
                // kept as is, even with ensure_ascii
                out.append(s, begin, end - begin);
                break;
        }
        return true;
    };

    std::size_t i = 0;
    while (i < s.size())
    {
        const auto lead = static_cast<unsigned char>(s[i]);
        if (lead < 0x80)
        {
            append_escaped_ascii(out, s[i], ensure_ascii);
            ++i;
            continue;
        }

        // number of bytes of the sequence and the range of its second byte
        std::size_t length = 0;
        std::uint32_t code_point = 0;
        unsigned char lower = 0x80;
        unsigned char upper = 0xBF;
        if (lead >= 0xC2 && lead <= 0xDF)
        {
            length = 2;
            code_point = lead & 0x1FU;
        }
        else if (lead >= 0xE0 && lead <= 0xEF)
        {
            length = 3;
            code_point = lead & 0x0FU;
            lower = (lead == 0xE0) ? 0xA0 : 0x80; // no overlong encodings
            upper = (lead == 0xED) ? 0x9F : 0xBF; // no surrogates
        }
        else if (lead >= 0xF0 && lead <= 0xF4)
        {
            length = 4;
            code_point = lead & 0x07U;
            lower = (lead == 0xF0) ? 0x90 : 0x80; // no overlong encodings
            upper = (lead == 0xF4) ? 0x8F : 0xBF; // nothing above U+10FFFF
        }
        else
        {
            // a byte that cannot start a sequence is consumed
            if (!ill_formed(i, i + 1, i))
            {
                return result;
            }
            ++i;
            continue;
        }

        std::size_t j = i + 1;
        for (; j < i + length; ++j)
        {
            if (j == s.size())
            {
                // the string ends in the middle of the sequence
                switch (error_handler)
                {
                    case json::error_handler_t::strict:
                        result.throws = true;
                        out = "[json.exception.type_error.316] incomplete UTF-8 string; last byte: 0x" + upper_hex_byte(static_cast<unsigned char>(s.back()));
                        return result;
                    case json::error_handler_t::ignore:
                        break;
                    case json::error_handler_t::replace:
                        append_replacement_character(out, ensure_ascii);
                        break;
                    case json::error_handler_t::keep:
                    default:
                        out.append(s, i, s.size() - i);
                        break;
                }
                out += '"';
                return result;
            }

            const auto byte = static_cast<unsigned char>(s[j]);
            if (byte < lower || byte > upper)
            {
                break;
            }
            code_point = (code_point << 6U) | (byte & 0x3FU);
            lower = 0x80;
            upper = 0xBF;
        }

        if (j < i + length)
        {
            // the sequence was abandoned at s[j]; that byte is read again as
            // the start of a new character
            if (!ill_formed(i, j, j))
            {
                return result;
            }
            i = j;
            continue;
        }

        if (!ensure_ascii)
        {
            out.append(s, i, length);
        }
        else if (code_point <= 0xFFFF)
        {
            append_u_escape(out, code_point);
        }
        else
        {
            append_u_escape(out, 0xD800U + ((code_point - 0x10000U) >> 10U));
            append_u_escape(out, 0xDC00U + ((code_point - 0x10000U) & 0x3FFU));
        }
        i = j;
    }

    out += '"';
    return result;
}

std::string hex_dump(const std::string& s)
{
    std::string result;
    for (const char c : s)
    {
        result += upper_hex_byte(static_cast<unsigned char>(c));
        result += ' ';
    }
    return result;
}

// compares dump() of s with the reference for every error handler, with
// ensure_ascii on and off; CHECKs only on a mismatch to keep the sweep fast;
// error_handler_t::strict can be skipped where the position of the string
// buffer does not matter, as throwing is slow on some platforms
void check_dump_against_reference(const std::string& s, const bool with_strict = true)
{
    const json j = s;
    const std::array<json::error_handler_t, 4> error_handlers =
    {
        {
            json::error_handler_t::strict, json::error_handler_t::ignore,
            json::error_handler_t::replace, json::error_handler_t::keep
        }
    };
    for (const auto error_handler : error_handlers)
    {
#if defined(JSON_NOEXCEPTION)
        // a strict dump of invalid UTF-8 calls std::abort() instead of throwing
        static_cast<void>(with_strict);
        if (error_handler == json::error_handler_t::strict)
#else
        if (!with_strict && error_handler == json::error_handler_t::strict)
#endif
        {
            continue;
        }
        for (const bool ensure_ascii :
                {
                    false, true
                })
        {
            const expected_dump expected = reference_dump_string(s, ensure_ascii, error_handler);
            expected_dump actual;
            int id = 0;
            try
            {
                actual.text = j.dump(-1, ' ', ensure_ascii, error_handler);
            }
            catch (const json::exception& e)
            {
                actual.throws = true;
                actual.text = e.what();
                id = e.id;
            }
            if (actual.throws != expected.throws || actual.text != expected.text || (actual.throws && id != 316))
            {
                const std::string input = hex_dump(s);
                CAPTURE(input)
                CAPTURE(ensure_ascii)
                CAPTURE(static_cast<int>(error_handler))
                CHECK(actual.throws == expected.throws);
                CHECK(actual.text == expected.text);
                CHECK((!actual.throws || id == 316));
            }
        }
    }
}
} // namespace

TEST_CASE("invalid UTF-8 at every position is handled like the reference")
{
    // ill-formed byte sequences; those that end in a truncated sequence are
    // also cut short by the filler that follows, or by the end of the string
    const std::vector<std::string> patterns =
    {
        // stray continuation bytes
        "\x80", "\xBF",
        // bytes that cannot start a sequence
        "\xC0", "\xC1", "\xF5", "\xF6", "\xF7", "\xF8", "\xF9", "\xFA", "\xFB", "\xFC", "\xFD", "\xFE", "\xFF",
        // overlong encodings
        "\xC0\xAF", "\xE0\x80\x80", "\xF0\x80\x80\x80",
        // UTF-16 surrogates
        "\xED\xA0\x80", "\xED\xBF\xBF",
        // a code point above U+10FFFF
        "\xF4\x90\x80\x80",
        // sequences cut short by ASCII, a control character, a quote, a
        // backslash, DEL, or the lead byte of a well-formed character
        "\xC3" "a", "\xE2\x82" "\n", "\xE2\x82\"", "\xF0\x9F\x98\\", "\xC3\x7F", "\xC3\xC3\xA4", "\xE2\xF0\x9F\x98\x80", // NOLINT(bugprone-suspicious-missing-comma): "\xC3" "a" ends the hex escape
        // truncated sequences
        "\xC3", "\xE2\x82", "\xF0\x9F\x98"
    };

    // well-formed characters of 1, 2, 3, and 4 bytes
    const std::vector<std::string> fillers = {"a", "\xC3\xA4", "\xE2\x82\xAC", "\xF0\x9F\x98\x80"};

    const auto make_string = [](const std::string & filler, const std::size_t before, const std::string & pattern, const std::size_t after)
    {
        std::string s;
        for (std::size_t k = 0; k < before; ++k)
        {
            s += filler;
        }
        s += pattern;
        for (std::size_t k = 0; k < after; ++k)
        {
            s += filler;
        }
        return s;
    };

    SECTION("the reference")
    {
        // the reference itself, against hand-written results
        const std::string s = "a\xFF\n\xC3\"\xE0\x80\xF0\x9F\x98\x80\xE2\x82";
        CHECK(reference_dump_string(s, false, json::error_handler_t::strict).text == "[json.exception.type_error.316] invalid UTF-8 byte at index 1: 0xFF");
        CHECK(reference_dump_string(s.substr(2), false, json::error_handler_t::strict).text == "[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0x22");
        CHECK(reference_dump_string("\xF0\x9F\x98\x80\xE2\x82", true, json::error_handler_t::strict).text == "[json.exception.type_error.316] incomplete UTF-8 string; last byte: 0x82");
        CHECK(reference_dump_string(s, false, json::error_handler_t::ignore).text == "\"a\\n\\\"\xF0\x9F\x98\x80\"");
        CHECK(reference_dump_string(s, true, json::error_handler_t::ignore).text == "\"a\\n\\\"\\ud83d\\ude00\"");
        CHECK(reference_dump_string(s, false, json::error_handler_t::replace).text == "\"a\xEF\xBF\xBD\\n\xEF\xBF\xBD\\\"\xEF\xBF\xBD\xEF\xBF\xBD\xF0\x9F\x98\x80\xEF\xBF\xBD\"");
        CHECK(reference_dump_string(s, true, json::error_handler_t::replace).text == "\"a\\ufffd\\n\\ufffd\\\"\\ufffd\\ufffd\\ud83d\\ude00\\ufffd\"");
        CHECK(reference_dump_string(s, false, json::error_handler_t::keep).text == "\"" + std::string("a\xFF\\n\xC3\\\"\xE0\x80\xF0\x9F\x98\x80\xE2\x82") + "\"");
        CHECK(reference_dump_string(s, true, json::error_handler_t::keep).text == "\"" + std::string("a\xFF\\n\xC3\\\"\xE0\x80\\ud83d\\ude00\xE2\x82") + "\"");
        check_dump_against_reference(s);
    }

    SECTION("short strings")
    {
        // strings of up to 17 bytes put the pattern at every offset of an
        // 8-byte stride of the bulk scanners, with whole strides on both
        // sides; lengths around 24, 32, and 40 bytes cross the 16- and 32-byte
        // strides; error_handler_t::strict is checked for up to 17 bytes of
        // ASCII and 8 bytes of other characters only, as throwing is slow on
        // some platforms
        for (const auto& filler : fillers)
        {
            for (std::size_t length = 0; length * filler.size() <= 40; ++length)
            {
                const std::size_t bytes = length * filler.size();
                if (filler.size() == 1 && bytes > 17 && (bytes + 1) % 8 > 2)
                {
                    continue;
                }
                for (std::size_t pos = 0; pos <= length; ++pos)
                {
                    for (const auto& pattern : patterns)
                    {
                        check_dump_against_reference(make_string(filler, pos, pattern, length - pos), bytes <= (filler.size() == 1 ? 17u : 8u));
                    }
                }
            }
        }
    }

    SECTION("strings crossing the end of the string buffer")
    {
        // characters that are not copied in bulk go through a 512-byte string
        // buffer that is written out once fewer than 13 bytes are left; with
        // ensure_ascii, each 2-byte character takes 6 bytes of it and each
        // 4-byte character 12, so the pattern meets the end of the buffer after
        // about 84 or 42 characters (3-byte characters behave like 2-byte
        // ones); plain ASCII, copied in bulk, is checked around 512 bytes;
        // positions further away are sampled; error_handler_t::strict throws
        // at the first ill-formed byte, regardless of the string buffer, and is
        // covered above
        for (const auto& filler : fillers)
        {
            if (filler.size() == 3)
            {
                continue;
            }
            const std::size_t escaped_size = filler.size() == 1 ? 1 : filler.size() * 3;
            const std::size_t middle = 506 / escaped_size;
            const std::size_t window = filler.size() == 1 ? 8 : 16;
            for (std::size_t pos = 0; pos <= middle + window; pos += (pos + window >= middle) ? 1 : 29)
            {
                for (const std::size_t after :
                        {
                            std::size_t{0}, std::size_t{12}
                        })
                {
                    for (const auto& pattern : patterns)
                    {
                        check_dump_against_reference(make_string(filler, pos, pattern, after), false);
                    }
                }
            }
        }
    }

    SECTION("repeated invalid sequences at every offset of the string buffer")
    {
        // ill-formed sequences that are kept or replaced fill the string
        // buffer without a bulk copy in between; a prefix of 0 to 12 bytes
        // 0xFF (kept as 1 byte, replaced by 3 or 6) shifts them across every
        // offset of the end of the buffer
        for (const auto& pattern : patterns)
        {
            for (std::size_t shift = 0; shift <= 12; ++shift)
            {
                std::string s(shift, '\xFF');
                while (s.size() < 600)
                {
                    s += pattern;
                }
                check_dump_against_reference(s, shift == 0);
                check_dump_against_reference(s + "\xF0\x9F\x98\x80", false);
            }
        }
    }
}
