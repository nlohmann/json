//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint8_t (via json::binary_t)
#include <limits> // numeric_limits
#include <string> // string, to_string
#include <vector> // vector

#include <nlohmann/json.hpp>

namespace utils
{
/// a SAX event consumer that records every event it receives as a
/// human-readable string, used by the deserialization tests to check the
/// exact sequence of SAX events a parse run produces
struct SaxEventLogger : public nlohmann::json_sax<nlohmann::json>
{
    using json = nlohmann::json;

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
        for (const auto b : val)
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
        errored = true;
        events.push_back("parse_error(" + std::to_string(position) + ")");
        return false;
    }

    std::vector<std::string> events {}; // NOLINT(readability-redundant-member-init)
    bool errored = false;
};

struct SaxEventLoggerExitAfterStartObject : public SaxEventLogger
{
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
        return false;
    }
};

struct SaxEventLoggerExitAfterKey : public SaxEventLogger
{
    bool key(std::string& val) override
    {
        events.push_back("key(" + val + ")");
        return false;
    }
};

struct SaxEventLoggerExitAfterStartArray : public SaxEventLogger
{
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
        return false;
    }
};
} // namespace utils
