//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace
{
// a SAX parser that recovers from every error and checks that the events are
// balanced and that every key is followed by exactly one value
class recovering_checker : public nlohmann::json_sax<nlohmann::json>
{
  public:
    bool null() override
    {
        return value();
    }

    bool boolean(bool /*val*/) override
    {
        return value();
    }

    bool number_integer(number_integer_t /*val*/) override
    {
        return value();
    }

    bool number_unsigned(number_unsigned_t /*val*/) override
    {
        return value();
    }

    bool number_float(number_float_t /*val*/, const string_t& /*s*/) override
    {
        return value();
    }

    bool string(string_t& /*val*/) override
    {
        return value();
    }

    bool binary(binary_t& /*val*/) override
    {
        return value();
    }

    bool start_object(std::size_t /*elements*/) override
    {
        value();
        stack.push_back('o');
        return true;
    }

    bool key(string_t& /*val*/) override
    {
        ++events;
        assert(!stack.empty() && stack.back() == 'o');
        stack.back() = 'v';
        return true;
    }

    bool end_object() override
    {
        ++events;
        assert(!stack.empty() && stack.back() == 'o');
        stack.pop_back();
        return true;
    }

    bool start_array(std::size_t /*elements*/) override
    {
        value();
        stack.push_back('a');
        return true;
    }

    bool end_array() override
    {
        ++events;
        assert(!stack.empty() && stack.back() == 'a');
        stack.pop_back();
        return true;
    }

    bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const nlohmann::detail::exception& /*ex*/) override
    {
        ++errors;
        return true;
    }

    bool complete() const
    {
        return stack.empty();
    }

    std::size_t events = 0;
    std::size_t errors = 0;

  private:
    bool value()
    {
        ++events;
        if (!stack.empty())
        {
            // an array element, or the value of a key
            assert(stack.back() != 'o');
            if (stack.back() == 'v')
            {
                stack.back() = 'o';
            }
        }
        return true;
    }

    // 'a' for an array, 'o' for an object that expects a key, 'v' for an
    // object that expects the value of a key
    std::vector<char> stack {}; // NOLINT(readability-redundant-member-init)
};

/// parses @a data with a recovering_checker from memory and from a stream,
/// checks that both see the same, that the events are balanced, and that the
/// number of errors is bounded, and returns the checker (see #3989)
inline recovering_checker check_recovering_parse(const std::uint8_t* data, const std::size_t size, const nlohmann::json::input_format_t format)
{
    recovering_checker checker;
    const bool ok = nlohmann::json::sax_parse(data, data + size, &checker, format);
    assert(checker.complete());
    assert(checker.errors <= size + 1);
    assert(ok == (checker.errors == 0));

    std::istringstream stream(std::string(reinterpret_cast<const char*>(data), size));
    recovering_checker stream_checker;
    assert(nlohmann::json::sax_parse(stream, &stream_checker, format) == ok);
    assert(stream_checker.complete());
    assert(stream_checker.events == checker.events);
    assert(stream_checker.errors == checker.errors);

    return checker;
}
} // namespace
