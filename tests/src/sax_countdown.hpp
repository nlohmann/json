//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace utils
{
/// a SAX event consumer that stops accepting events after a fixed count,
/// used by the binary-format tests to check behavior when the SAX consumer
/// rejects an event partway through parsing
class SaxCountdown
{
  public:
    using json = nlohmann::json;

    explicit SaxCountdown(const int count) : events_left(count)
    {}

    bool null()
    {
        return events_left-- > 0;
    }

    bool boolean(bool /*unused*/)
    {
        return events_left-- > 0;
    }

    bool number_integer(json::number_integer_t /*unused*/)
    {
        return events_left-- > 0;
    }

    bool number_unsigned(json::number_unsigned_t /*unused*/)
    {
        return events_left-- > 0;
    }

    bool number_float(json::number_float_t /*unused*/, const std::string& /*unused*/)
    {
        return events_left-- > 0;
    }

    bool string(std::string& /*unused*/)
    {
        return events_left-- > 0;
    }

    bool binary(std::vector<std::uint8_t>& /*unused*/)
    {
        return events_left-- > 0;
    }

    bool start_object(std::size_t /*unused*/)
    {
        return events_left-- > 0;
    }

    bool key(std::string& /*unused*/)
    {
        return events_left-- > 0;
    }

    bool end_object()
    {
        return events_left-- > 0;
    }

    bool start_array(std::size_t /*unused*/)
    {
        return events_left-- > 0;
    }

    bool end_array()
    {
        return events_left-- > 0;
    }

    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const json::exception& /*unused*/) // NOLINT(readability-convert-member-functions-to-static)
    {
        return false;
    }

  private:
    int events_left = 0;
};
} // namespace utils
