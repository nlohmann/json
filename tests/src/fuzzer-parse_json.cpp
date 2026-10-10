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

Furthermore, it parses data with a SAX parser that recovers from every error
and checks that the events are balanced, that parsing ends, and that valid
input is parsed without errors (see #3989).

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.
*/

#include <cassert>
#include <nlohmann/json.hpp>

// the round-trip checks below are assertions; NDEBUG would compile them away
#ifdef NDEBUG
    #error "the fuzzer drivers must be built without NDEBUG"
#endif

#include "fuzzer-recovering_checker.hpp"

using json = nlohmann::json;

// compares dumps rather than values, because NaN != NaN; keep writes strings
// byte for byte, so ill-formed UTF-8 that a binary reader accepts cannot throw
static bool same_value(const json& lhs, const json& rhs)
{
    return lhs.dump(-1, ' ', false, json::error_handler_t::keep) == rhs.dump(-1, ' ', false, json::error_handler_t::keep);
}

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // recover from all errors, reading from memory and from a stream
    {
        const auto checker = check_recovering_parse(data, size, json::input_format_t::json);
        assert(checker.events <= (4 * size) + 4);
        assert((checker.errors == 0) == json::accept(data, data + size));
    }

    // step 0: parse input without exceptions; a parse error must then be
    // reported as a discarded value, never thrown
    json j_noexcept;
    bool noexcept_threw = false;
    try
    {
        j_noexcept = json::parse(data, data + size, nullptr, false);
    }
    catch (const json::parse_error&)
    {
        assert(false);
    }
    catch (const json::exception&)
    {
        // type and out-of-range errors are not parse errors and still throw
        noexcept_threw = true;
    }
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
