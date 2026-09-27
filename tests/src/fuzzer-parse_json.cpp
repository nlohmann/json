//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

/*
This file implements a parser test suitable for fuzz testing. Given a byte
array data, it performs the following steps:

- j1 = parse(data)
- s1 = serialize(j1)
- j2 = parse(s1)
- s2 = serialize(j2)
- assert(s1 == s2)

Furthermore, it parses data with a SAX parser that recovers from every error
and checks that the events are balanced, that parsing ends, and that valid
input is parsed without errors (see #3989).

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.
*/

#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

// the round-trip checks below are assertions; NDEBUG would compile them away
#ifdef NDEBUG
    #error "the fuzzer drivers must be built without NDEBUG"
#endif

using json = nlohmann::json;

namespace
{
// a SAX parser that recovers from every error and checks that the events are
// balanced and that every key is followed by exactly one value
class recovering_checker : public nlohmann::json_sax<json>
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
    std::vector<char> stack;
};
} // namespace

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // step 0: recover from all errors, reading from memory and from a stream
    {
        recovering_checker checker;
        const bool ok = json::sax_parse(data, data + size, &checker);
        assert(checker.complete());
        assert(checker.errors <= size + 1);
        assert(checker.events <= (4 * size) + 4);
        assert(ok == json::accept(data, data + size));
        assert(ok == (checker.errors == 0));

        std::istringstream stream(std::string(reinterpret_cast<const char*>(data), size));
        recovering_checker stream_checker;
        assert(json::sax_parse(stream, &stream_checker) == ok);
        assert(stream_checker.complete());
        assert(stream_checker.events == checker.events);
        assert(stream_checker.errors == checker.errors);
    }

    try
    {
        // step 1: parse input
        json const j1 = json::parse(data, data + size);

        try
        {
            // step 2: round trip

            // first serialization
            std::string const s1 = j1.dump();

            // parse serialization
            json const j2 = json::parse(s1);

            // second serialization
            std::string const s2 = j2.dump();

            // serializations must match
            assert(s1 == s2);
        }
        catch (const json::parse_error&)
        {
            // parsing a JSON serialization must not fail
            assert(false);
        }
    }
    catch (const json::parse_error&)
    {
        // parse errors are ok, because input may be random bytes
    }
    catch (const json::out_of_range&)
    {
        // out of range errors may happen if provided sizes are excessive
    }

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
