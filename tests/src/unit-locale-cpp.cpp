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

#include <clocale>

struct ParserImpl final: public nlohmann::json_sax<json>
{
    bool null() override
    {
        return true;
    }
    bool boolean(bool /*val*/) override
    {
        return true;
    }
    bool number_integer(json::number_integer_t /*val*/) override
    {
        return true;
    }
    bool number_unsigned(json::number_unsigned_t /*val*/) override
    {
        return true;
    }
    bool number_float(json::number_float_t /*val*/, const json::string_t& s) override
    {
        float_string_copy = s;
        return true;
    }
    bool string(json::string_t& /*val*/) override
    {
        return true;
    }
    bool binary(json::binary_t& /*val*/) override
    {
        return true;
    }
    bool start_object(std::size_t /*val*/) override
    {
        return true;
    }
    bool key(json::string_t& /*val*/) override
    {
        return true;
    }
    bool end_object() override
    {
        return true;
    }
    bool start_array(std::size_t /*val*/) override
    {
        return true;
    }
    bool end_array() override
    {
        return true;
    }
    bool parse_error(std::size_t /*val*/, const std::string& /*val*/, const nlohmann::detail::exception& /*val*/) override
    {
        return false;
    }

    ~ParserImpl() override;

    ParserImpl()
        : float_string_copy("not set")
    {}

    ParserImpl(const ParserImpl& other)
        : float_string_copy(other.float_string_copy)
    {}

    ParserImpl(ParserImpl&& other) noexcept
        : float_string_copy(std::move(other.float_string_copy))
    {}

    ParserImpl& operator=(const ParserImpl& other)
    {
        if (this != &other)
        {
            float_string_copy = other.float_string_copy;
        }
        return *this;
    }

    ParserImpl& operator=(ParserImpl&& other) noexcept
    {
        if (this != &other)
        {
            float_string_copy = std::move(other.float_string_copy);
        }
        return *this;
    }

    json::string_t float_string_copy;
};

ParserImpl::~ParserImpl() = default;

TEST_CASE("locale-dependent test (LC_NUMERIC=C)")
{
    WARN_MESSAGE(std::setlocale(LC_NUMERIC, "C") != nullptr, "could not set locale");

    SECTION("check if locale is properly set")
    {
        std::array<char, 6> buffer = {};
        CHECK(std::snprintf(buffer.data(), buffer.size(), "%.2f", 12.34) == 5); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        CHECK(std::string(buffer.data()) == "12.34");
    }

    SECTION("parsing")
    {
        CHECK(json::parse("12.34").dump() == "12.34");
    }

    SECTION("SAX parsing")
    {
        ParserImpl sax {};
        json::sax_parse( "12.34", &sax );
        CHECK(sax.float_string_copy == "12.34");
    }
}

TEST_CASE("locale-dependent test (LC_NUMERIC=de_DE)")
{
    if (std::setlocale(LC_NUMERIC, "de_DE") != nullptr)
    {
        SECTION("check if locale is properly set")
        {
            std::array<char, 6> buffer = {};
            CHECK(std::snprintf(buffer.data(), buffer.size(), "%.2f", 12.34) == 5); // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
            const auto snprintf_result = std::string(buffer.data());
            if (snprintf_result != "12,34")
            {
                CAPTURE(snprintf_result)
                MESSAGE("To test if number parsing is locale-independent, we set the locale to de_DE. However, on this system, the decimal separator doesn't change to `,` potentially due to a known musl issue (https://github.com/nlohmann/json/issues/4767).");
            }
        }

        SECTION("parsing")
        {
            CHECK(json::parse("12.34").dump() == "12.34");
        }

        SECTION("SAX parsing")
        {
            ParserImpl sax{};
            json::sax_parse("12.34", &sax);
            CHECK(sax.float_string_copy == "12.34");
        }
    }
    else
    {
        MESSAGE("locale de_DE is not usable");
    }
}
