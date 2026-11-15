//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <limits> // numeric_limits
#include <string> // string
#include <vector> // vector

#include <nlohmann/json.hpp>

// helpers of the tests of the budget for the elements of UBJSON containers of
// a valueless type (unit-ubjson.cpp and unit-ubjson_valueless.cpp)
#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wweak-vtables"
#endif

namespace utils
{
/// SAX consumer that counts the values and keeps the id of a parse error
struct ValuelessEventCounter : public nlohmann::json_sax<nlohmann::json>
{
    bool null() override
    {
        return ++values < stop_after;
    }
    bool boolean(bool /*val*/) override
    {
        return ++values < stop_after;
    }
    bool number_integer(nlohmann::json::number_integer_t /*val*/) override
    {
        ++values;
        return true;
    }
    bool number_unsigned(nlohmann::json::number_unsigned_t /*val*/) override
    {
        ++values;
        return true;
    }
    bool number_float(nlohmann::json::number_float_t /*val*/, const std::string& /*s*/) override
    {
        ++values;
        return true;
    }
    bool string(std::string& /*val*/) override
    {
        ++values;
        return true;
    }
    bool binary(nlohmann::json::binary_t& /*val*/) override
    {
        ++values;
        return true;
    }
    bool start_object(std::size_t /*elements*/) override
    {
        return true;
    }
    bool key(std::string& /*val*/) override
    {
        return true;
    }
    bool end_object() override
    {
        return true;
    }
    bool start_array(std::size_t /*elements*/) override
    {
        return true;
    }
    bool end_array() override
    {
        return true;
    }
    bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const nlohmann::json::exception& ex) override
    {
        error_id = ex.id;
        return false;
    }

    /// the handler refuses the value that makes this many
    std::size_t stop_after = (std::numeric_limits<std::size_t>::max)();
    std::size_t values = 0;
    int error_id = 0;
};

/// appends `[$<marker>#l<count>` (nine bytes) to @a v
inline void append_valueless_array(std::vector<std::uint8_t>& v, const char marker, const std::uint32_t count)
{
    v.push_back('[');
    v.push_back('$');
    v.push_back(static_cast<std::uint8_t>(marker));
    v.push_back('#');
    v.push_back('l');
    v.push_back(static_cast<std::uint8_t>(count >> 24));
    v.push_back(static_cast<std::uint8_t>(count >> 16));
    v.push_back(static_cast<std::uint8_t>(count >> 8));
    v.push_back(static_cast<std::uint8_t>(count));
}

/// `[` followed by one `[$<marker>#l<count>` per entry of @a counts and `]`
inline std::vector<std::uint8_t> valueless_arrays(const char marker, const std::vector<std::uint32_t>& counts)
{
    std::vector<std::uint8_t> v = {'['};
    for (const auto count : counts)
    {
        append_valueless_array(v, marker, count);
    }
    v.push_back(']');
    return v;
}
} // namespace utils

#if defined(__clang__)
    #pragma clang diagnostic pop
#endif
