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

- j1 = from_bon8(data)
- vec = to_bon8(j1)
- j2 = from_bon8(vec)
- assert(j1 == j2)

It also checks that reading the data from a stream, which reads strings byte by
byte, gives the same value or error as reading it from contiguous memory, which
copies strings in bulk.

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.
*/

#include <cassert>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

// the round-trip checks below are assertions; NDEBUG would compile them away
#ifdef NDEBUG
    #error "the fuzzer drivers must be built without NDEBUG"
#endif

using json = nlohmann::json;

namespace
{
// the serialization of the value read from @a input, or the error message
template<typename InputType>
std::string read_bon8(InputType&& input)
{
    try
    {
        const auto vec = json::to_bon8(json::from_bon8(std::forward<InputType>(input)));
        return {vec.begin(), vec.end()};
    }
    catch (const json::exception& e)
    {
        return e.what();
    }
}
} // namespace

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // contiguous and stream input must be read alike
    {
        std::istringstream stream(std::string(reinterpret_cast<const char*>(data), size));
        assert(read_bon8(std::vector<uint8_t>(data, data + size)) == read_bon8(stream));
    }

    try
    {
        // step 1: parse input
        std::vector<uint8_t> const vec1(data, data + size);
        json const j1 = json::from_bon8(vec1);

        try
        {
            // step 2: round trip
            std::vector<uint8_t> const vec2 = json::to_bon8(j1);

            // parse serialization
            json const j2 = json::from_bon8(vec2);

            // serializations must match
            assert(json::to_bon8(j2) == vec2);
        }
        catch (const json::parse_error&)
        {
            // parsing a BON8 serialization must not fail
            assert(false);
        }
    }
    catch (const json::parse_error&)
    {
        // parse errors are ok, because input may be random bytes
    }
    catch (const json::type_error&)
    {
        // type errors can occur during parsing, too
    }
    catch (const json::out_of_range&)
    {
        // out of range errors may happen if provided sizes are excessive
    }

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
