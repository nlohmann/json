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

#include <array>
#include <clocale>
#include <map>
#include <string>
#include <utility>
#include <vector>

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

        SECTION("serializing a long double")
        {
            // a floating-point type that is not a float or a double is written
            // with snprintf, whose locale-specific decimal point and thousands
            // separator are undone afterwards
            using long_double_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, long double>;
            CHECK(long_double_json(12345.5L).dump() == "12345.5");
            CHECK(long_double_json(1.0L).dump() == "1.0");
            CHECK(long_double_json(-0.25L).dump() == "-0.25");
        }
    }
    else
    {
        MESSAGE("locale de_DE is not usable");
    }
}

namespace
{
// records the numbers of a flat array and switches LC_NUMERIC to the given
// locale once the array opens - after the lexer was constructed, but before
// any number in the array is lexed
struct LocaleSwitchingSax final: public nlohmann::json_sax<json>
{
    explicit LocaleSwitchingSax(const char* switch_to)
        : locale_after_open(switch_to)
    {}

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
    bool number_float(json::number_float_t val, const json::string_t& s) override
    {
        values.push_back(val);
        strings.push_back(s);
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
        switched = std::setlocale(LC_NUMERIC, locale_after_open.c_str()) != nullptr;
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

    std::string locale_after_open;
    bool switched = false;
    std::vector<json::number_float_t> values {}; // NOLINT(readability-redundant-member-init)
    std::vector<json::string_t> strings {}; // NOLINT(readability-redundant-member-init)
};
} // namespace

TEST_CASE("locale changes between lexer construction and number conversion (#5198)")
{
    // The numbers are chosen so that the conversion also takes the strtod
    // fallback, which honors the locale that is current at conversion time:
    // too many significant digits for Clinger's fast path, an underflow that
    // std::from_chars rejects, and a plain value.
    const std::vector<std::string> numbers = {"3.14159265358979323846", "1.5e-400", "12.34", "-0.000123456789012345678"};
    std::string text = "[";
    for (const auto& n : numbers)
    {
        text += (text.size() == 1 ? "" : ",") + n;
    }
    text += "]";

    using long_double_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, long double>;

    // reference values, parsed without a locale switch
    REQUIRE(std::setlocale(LC_NUMERIC, "C") != nullptr);
    const json expected = json::parse(text);
    const long_double_json expected_ld = long_double_json::parse(text);

    const std::array<std::pair<const char*, const char*>, 2> transitions =
    {
        {
            {"C", "de_DE"},
            {"de_DE", "C"}
        }
    };

    for (const auto& transition : transitions)
    {
        CAPTURE(transition.first)
        CAPTURE(transition.second)

        if (std::setlocale(LC_NUMERIC, transition.first) == nullptr)
        {
            MESSAGE("locale is not usable");
            continue;
        }

        // SAX parsing
        {
            LocaleSwitchingSax sax(transition.second);
            CHECK(json::sax_parse(text, &sax));
            if (sax.switched)
            {
                CHECK(sax.values == expected.get<std::vector<json::number_float_t>>());
                CHECK(sax.strings == numbers);
            }
        }

        // DOM parsing with a callback
        {
            bool switched = false;
            const auto cb = [&](int /*depth*/, json::parse_event_t event, json& /*parsed*/) noexcept
            {
                if (event == json::parse_event_t::array_start)
                {
                    switched = std::setlocale(LC_NUMERIC, transition.second) != nullptr;
                }
                return true;
            };
            const json j = json::parse(text, cb);
            if (switched)
            {
                CHECK(j == expected);
            }
        }

        // a long double goes through std::strtold unless std::from_chars supports it
        {
            bool switched = false;
            const auto cb = [&](int /*depth*/, long_double_json::parse_event_t event, long_double_json& /*parsed*/) noexcept
            {
                if (event == long_double_json::parse_event_t::array_start)
                {
                    switched = std::setlocale(LC_NUMERIC, transition.second) != nullptr;
                }
                return true;
            };
            const long_double_json j = long_double_json::parse(text, cb);
            if (switched)
            {
                CHECK(j == expected_ld);
            }
        }
    }

    CHECK(std::setlocale(LC_NUMERIC, "C") != nullptr);
}

TEST_CASE("locale with a multi-byte decimal point")
{
    // Some locales use a decimal point that is not a single character, e.g.
    // U+066B ARABIC DECIMAL SEPARATOR (two bytes in UTF-8). It cannot be
    // substituted in place for '.', so the strtod fallback stops early. The
    // conversion must still terminate rather than retry forever.
    const std::array<const char*, 6> names = {{"ar_EG.UTF-8", "ar_SA.UTF-8", "fa_IR.UTF-8", "ps_AF.UTF-8", "ar_EG", "fa_IR"}};
    bool tested = false;
    for (const char* name : names)
    {
        if (std::setlocale(LC_NUMERIC, name) == nullptr)
        {
            continue;
        }
        const std::string decimal_point = std::localeconv()->decimal_point;
        if (decimal_point.size() < 2)
        {
            continue;
        }
        CAPTURE(name)
        tested = true;

        // too many significant digits for Clinger's fast path, and an underflow
        // that std::from_chars rejects: both reach the strtod fallback
        json j;
        CHECK_NOTHROW(j = json::parse("[3.14159265358979323846, 1.5e-400, -0.000123456789012345678]"));
        CHECK(j.is_array());
        CHECK(json::accept("3.14159265358979323846"));

        // a value the locale-independent paths convert is not affected
        CHECK(json::parse("12.5") == 12.5);
    }
    if (!tested)
    {
        MESSAGE("no locale with a multi-byte decimal point is usable");
    }

    CHECK(std::setlocale(LC_NUMERIC, "C") != nullptr);
}
