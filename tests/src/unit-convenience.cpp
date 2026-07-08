//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <sstream>

namespace
{
struct alt_string_iter
{
    alt_string_iter() = default;
    alt_string_iter(const char* cstr)
        : impl(cstr)
    {}

    void reserve(std::size_t s)
    {
        impl.reserve(s);
    }

    template<typename Iter>
    void append(Iter first, Iter last)
    {
        impl.append(first, last);
    }

    std::string::const_iterator begin() const noexcept
    {
        return impl.begin();
    }

    std::string::const_iterator end() const noexcept
    {
        return impl.end();
    }

    std::size_t size() const noexcept
    {
        return impl.size();
    }

    alt_string_iter& operator+=(const char c)
    {
        impl += c;
        return *this;
    }

    std::string impl{}; // NOLINT(readability-redundant-member-init)
};

struct alt_string_data
{
    alt_string_data() = default;
    alt_string_data(const char* cstr)
        : impl(cstr)
    {}

    void reserve(std::size_t s)
    {
        impl.reserve(s);
    }

    void append(const char* p, std::size_t s)
    {
        impl.append(p, s);
    }

    const char* data() const
    {
        return impl.data();
    }

    std::size_t size() const
    {
        return impl.size();
    }

    alt_string_data& operator+=(const char c)
    {
        impl += c;
        return *this;
    }

    std::string impl{}; // NOLINT(readability-redundant-member-init)
};

void check_escaped(const char* original, const char* escaped = "", bool ensure_ascii = false);
void check_escaped(const char* original, const char* escaped, const bool ensure_ascii)
{
    std::stringstream ss;
    json::serializer s(nlohmann::detail::output_adapter<char>(ss), ' ');
    s.dump_escaped(original, ensure_ascii);
    CHECK(ss.str() == escaped);
}
} // namespace

TEST_CASE("convenience functions")
{
    SECTION("type name as string")
    {
        CHECK(std::string(json(json::value_t::null).type_name()) == "null");
        CHECK(std::string(json(json::value_t::object).type_name()) == "object");
        CHECK(std::string(json(json::value_t::array).type_name()) == "array");
        CHECK(std::string(json(json::value_t::number_integer).type_name()) == "number");
        CHECK(std::string(json(json::value_t::number_unsigned).type_name()) == "number");
        CHECK(std::string(json(json::value_t::number_float).type_name()) == "number");
        CHECK(std::string(json(json::value_t::binary).type_name()) == "binary");
        CHECK(std::string(json(json::value_t::boolean).type_name()) == "boolean");
        CHECK(std::string(json(json::value_t::string).type_name()) == "string");
        CHECK(std::string(json(json::value_t::discarded).type_name()) == "discarded");
    }

    SECTION("string escape")
    {
        check_escaped("\"", "\\\"");
        check_escaped("\\", "\\\\");
        check_escaped("\b", "\\b");
        check_escaped("\f", "\\f");
        check_escaped("\n", "\\n");
        check_escaped("\r", "\\r");
        check_escaped("\t", "\\t");

        check_escaped("\x01", "\\u0001");
        check_escaped("\x02", "\\u0002");
        check_escaped("\x03", "\\u0003");
        check_escaped("\x04", "\\u0004");
        check_escaped("\x05", "\\u0005");
        check_escaped("\x06", "\\u0006");
        check_escaped("\x07", "\\u0007");
        check_escaped("\x08", "\\b");
        check_escaped("\x09", "\\t");
        check_escaped("\x0a", "\\n");
        check_escaped("\x0b", "\\u000b");
        check_escaped("\x0c", "\\f");
        check_escaped("\x0d", "\\r");
        check_escaped("\x0e", "\\u000e");
        check_escaped("\x0f", "\\u000f");
        check_escaped("\x10", "\\u0010");
        check_escaped("\x11", "\\u0011");
        check_escaped("\x12", "\\u0012");
        check_escaped("\x13", "\\u0013");
        check_escaped("\x14", "\\u0014");
        check_escaped("\x15", "\\u0015");
        check_escaped("\x16", "\\u0016");
        check_escaped("\x17", "\\u0017");
        check_escaped("\x18", "\\u0018");
        check_escaped("\x19", "\\u0019");
        check_escaped("\x1a", "\\u001a");
        check_escaped("\x1b", "\\u001b");
        check_escaped("\x1c", "\\u001c");
        check_escaped("\x1d", "\\u001d");
        check_escaped("\x1e", "\\u001e");
        check_escaped("\x1f", "\\u001f");

        // invalid UTF-8 characters
        CHECK_THROWS_WITH_AS(check_escaped("ä\xA9ü"), "[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9", json::type_error&);

        CHECK_THROWS_WITH_AS(check_escaped("\xC2"), "[json.exception.type_error.316] incomplete UTF-8 string; last byte: 0xC2", json::type_error&);
    }

    SECTION("string escape with ensure_ascii")
    {
        // control characters are escaped regardless of ensure_ascii
        check_escaped("\x01", "\\u0001", true);
        check_escaped("\x1f", "\\u001f", true);

        // non-ASCII code points in the Basic Multilingual Plane are emitted as
        // a single lowercase \uXXXX escape (exercises every nibble position)
        check_escaped("\xC2\x80", "\\u0080", true);         // U+0080
        check_escaped("\xC3\xBF", "\\u00ff", true);         // U+00FF (ÿ)
        check_escaped("\xDF\xBF", "\\u07ff", true);         // U+07FF
        check_escaped("\xE4\xBD\xA0", "\\u4f60", true);     // U+4F60 (你)
        check_escaped("\xEA\xAF\x8D", "\\uabcd", true);     // U+ABCD
        check_escaped("\xEF\xBF\xBD", "\\ufffd", true);     // U+FFFD (replacement char, all-f nibbles)

        // code points outside the BMP are emitted as a UTF-16 surrogate pair
        // of two lowercase \uXXXX escapes
        check_escaped("\xF0\x90\x80\x80", "\\ud800\\udc00", true); // U+10000 (lowest astral)
        check_escaped("\xF0\x9F\x98\x80", "\\ud83d\\ude00", true); // U+1F600 (😀)
        check_escaped("\xF4\x8F\xBF\xBF", "\\udbff\\udfff", true); // U+10FFFF (highest code point)

        // with ensure_ascii disabled, non-ASCII input is passed through verbatim
        check_escaped("\xE4\xBD\xA0", "\xE4\xBD\xA0", false);
        check_escaped("\xF0\x9F\x98\x80", "\xF0\x9F\x98\x80", false);
    }

    SECTION("string concat")
    {
        using nlohmann::detail::concat;

        const char* expected = "Hello, world!";
        alt_string_iter const hello_iter{"Hello, "};
        alt_string_data const hello_data{"Hello, "};
        std::string const world = "world";

        SECTION("std::string")
        {
            const std::string str1 = concat(hello_iter, world, '!');
            const std::string str2 = concat(hello_data, world, '!');
            const std::string str3 = concat("Hello, ", world, '!');

            CHECK(str1 == expected);
            CHECK(str2 == expected);
            CHECK(str3 == expected);
        }

        SECTION("alt_string_iter")
        {
            const alt_string_iter str = concat<alt_string_iter>(hello_iter, world, '!');

            CHECK(str.impl == expected);
        }

        SECTION("alt_string_data")
        {
            const alt_string_data str = concat<alt_string_data>(hello_data, world, '!');

            CHECK(str.impl == expected);
        }
    }
}
