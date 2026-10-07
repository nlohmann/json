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

- j0 = from_bson(data, allow_exceptions = false)
- j1 = from_bson(data)
- assert(j0 is discarded if parsing j1 fails, and j0 == j1 otherwise)
- vec = to_bson(j1)
- j2 = from_bson(vec)
- assert(to_bson(j2) == vec)

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
    std::vector<uint8_t> const vec1(data, data + size);

    // step 0: parse input without exceptions
    bool noexcept_threw = false;
    json const j_noexcept = parse_without_exceptions([&] { return json::from_bson(vec1, true, false); }, noexcept_threw);
    // whether step 1 succeeded; if not, the catch blocks below check that
    // step 0 failed, too
    bool parsed = false;

    try
    {
        // step 1: parse input
        json const j1 = json::from_bson(vec1);
        parsed = true;

        // without exceptions, the same input must give the same value
        assert(!noexcept_threw && !j_noexcept.is_discarded() && same_value(j_noexcept, j1));

        try
        {
            // step 2: round trip
            std::vector<uint8_t> const vec2 = json::to_bson(j1);

            // parse serialization
            json const j2 = json::from_bson(vec2);

            // serializations must match
            assert(json::to_bson(j2) == vec2);
        }
        catch (const json::parse_error&)
        {
            // parsing a BSON serialization must not fail
            assert(false);
        }
    }
    catch (const json::parse_error&)
    {
        // parse errors are ok, because input may be random bytes
        assert(parsed || noexcept_threw || j_noexcept.is_discarded());
    }
    catch (const json::type_error&)
    {
        // type errors can occur during parsing, too
        assert(parsed || noexcept_threw || j_noexcept.is_discarded());
    }
    catch (const json::out_of_range&)
    {
        // out of range errors can occur during parsing, too
        assert(parsed || noexcept_threw || j_noexcept.is_discarded());
    }

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
