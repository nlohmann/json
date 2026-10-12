//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++20-only part of unit-deserialization.cpp (char8_t support:
// _json with char8_t literals and char8_t input). It is kept in a separate translation
// unit so the (much larger) unit-deserialization.cpp is built for C++11 only and not
// rebuilt for every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#ifdef JSON_HAS_CPP_20
#include <string>
#include <vector>

#if defined(__cpp_char8_t) && (__cpp_char8_t >= 201811L)
namespace
{
// copy of SaxEventLogger from unit-deserialization.cpp (renamed to avoid clashes in unity builds)
struct SaxEventLoggerChar8 : public nlohmann::json_sax<json>
{
    bool null() override
    {
        events.emplace_back("null()");
        return true;
    }

    bool boolean(bool val) override
    {
        events.emplace_back(val ? "boolean(true)" : "boolean(false)");
        return true;
    }

    bool number_integer(json::number_integer_t val) override
    {
        events.push_back("number_integer(" + std::to_string(val) + ")");
        return true;
    }

    bool number_unsigned(json::number_unsigned_t val) override
    {
        events.push_back("number_unsigned(" + std::to_string(val) + ")");
        return true;
    }

    bool number_float(json::number_float_t /*val*/, const std::string& s) override
    {
        events.push_back("number_float(" + s + ")");
        return true;
    }

    bool string(std::string& val) override
    {
        events.push_back("string(" + val + ")");
        return true;
    }

    bool binary(json::binary_t& val) override
    {
        std::string binary_contents = "binary(";
        std::string comma_space;
        for (auto b : val)
        {
            binary_contents.append(comma_space);
            binary_contents.append(std::to_string(static_cast<int>(b)));
            comma_space = ", ";
        }
        binary_contents.append(")");
        events.push_back(binary_contents);
        return true;
    }

    bool start_object(std::size_t elements) override
    {
        if (elements == (std::numeric_limits<std::size_t>::max)())
        {
            events.emplace_back("start_object()");
        }
        else
        {
            events.push_back("start_object(" + std::to_string(elements) + ")");
        }
        return true;
    }

    bool key(std::string& val) override
    {
        events.push_back("key(" + val + ")");
        return true;
    }

    bool end_object() override
    {
        events.emplace_back("end_object()");
        return true;
    }

    bool start_array(std::size_t elements) override
    {
        if (elements == (std::numeric_limits<std::size_t>::max)())
        {
            events.emplace_back("start_array()");
        }
        else
        {
            events.push_back("start_array(" + std::to_string(elements) + ")");
        }
        return true;
    }

    bool end_array() override
    {
        events.emplace_back("end_array()");
        return true;
    }

    bool parse_error(std::size_t position, const std::string& /*last_token*/, const json::exception& /*ex*/) override
    {
        events.push_back("parse_error(" + std::to_string(position) + ")");
        return false;
    }

    std::vector<std::string> events {}; // NOLINT(readability-redundant-member-init)
};
} // namespace

TEST_CASE_TEMPLATE("deserialization of different character types (ASCII) (C++20)", T, char8_t) // NOLINT(readability-math-missing-parentheses, bugprone-throwing-static-initialization)
{
    std::vector<T> const v = {'t', 'r', 'u', 'e'};
    CHECK(json::parse(v) == json(true));
    CHECK(json::accept(v));

    SaxEventLoggerChar8 l;
    CHECK(json::sax_parse(v, &l));
    CHECK(l.events.size() == 1);
    CHECK(l.events == std::vector<std::string>({"boolean(true)"}));
}
#endif

TEST_CASE("deserialization (C++20)")
{
#if defined(__cpp_char8_t)
    SECTION("Using _json with char8_t literals #4945")
    {
        // Regular narrow string literal
        const auto j1 = R"({"key": "value", "num": 42})"_json;
        CHECK(j1["key"] == "value");
        CHECK(j1["num"] == 42);

        // UTF-8 prefixed literal (C++20 and later); the emoji is written as a
        // \U escape rather than a raw multibyte character so this does not
        // depend on the compiler's source-file encoding (e.g., MSVC without
        // /utf-8, or classic ICC, which does not encode non-ASCII narrow
        // string literals as UTF-8 - compare against a \x-escaped expectation
        // for the same reason)
        const auto j2 = u8"{\"emoji\": \"\U0001F600\", \"msg\": \"hello\"}"_json;
        CHECK(j2["emoji"] == "\xF0\x9F\x98\x80");
        CHECK(j2["msg"] == "hello");

        const auto j3 = u8R"({"key": "value", "num": 42})"_json;
        CHECK(j3["key"] == "value");
        CHECK(j3["num"] == 42);
    }
#endif
}

#endif
