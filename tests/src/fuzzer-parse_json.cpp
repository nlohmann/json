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

- j0 = parse(data, allow_exceptions = false)
- j1 = parse(data)
- assert(j0 is discarded if parsing j1 fails, and j0 == j1 otherwise)
- s1 = serialize(j1)
- j2 = parse(s1)
- s2 = serialize(j2)
- assert(s1 == s2)

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.
*/

#include <cassert>
#include <nlohmann/json.hpp>
#include "fuzzer_common.hpp"

using nlohmann::json;

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // step 0: parse input without exceptions
    bool noexcept_threw = false;
    json const j_noexcept = parse_without_exceptions([&] { return json::parse(data, data + size, nullptr, false); }, noexcept_threw);
    // whether step 1 succeeded; if not, the catch blocks below check that
    // step 0 failed, too
    bool parsed = false;

    try
    {
        // step 1: parse input
        json const j1 = json::parse(data, data + size);
        parsed = true;

        // without exceptions, the same input must give the same value
        assert(!noexcept_threw && !j_noexcept.is_discarded() && same_value(j_noexcept, j1));

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
        assert(parsed || noexcept_threw || j_noexcept.is_discarded());
    }
    catch (const json::out_of_range&)
    {
        // out of range errors may happen if provided sizes are excessive
        assert(parsed || noexcept_threw || j_noexcept.is_discarded());
    }

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
