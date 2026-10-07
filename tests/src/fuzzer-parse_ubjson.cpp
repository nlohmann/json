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

- j0 = from_ubjson(data, allow_exceptions = false)
- j1 = from_ubjson(data)
- assert(j0 is discarded if parsing j1 fails, and j0 == j1 otherwise)
- vec2 = to_ubjson(j1, use_size = false, use_type = false)
- vec3 = to_ubjson(j1, use_size = true, use_type = false)
- vec4 = to_ubjson(j1, use_size = true, use_type = true)
- j2 = from_ubjson(vec2)
- j3 = from_ubjson(vec3)
- j4 = from_ubjson(vec4)
- assert(to_ubjson(j2, use_size = false, use_type = false) == vec2)
- assert(to_ubjson(j3, use_size = true, use_type = false) == vec3)
- assert(to_ubjson(j4, use_size = true, use_type = true) == vec4)

The unit tests run the same checks on a fixed corpus (see the "UBJSON round-trip
invariants" test case), so keep both in sync.

Furthermore, it reads data with a SAX parser that recovers from every error
and checks that the events are balanced, that reading ends, and that it
reports an error exactly when from_ubjson() fails (see #3989).

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
    const bool recovered_without_errors = check_recovering_parse(data, size, json::input_format_t::ubjson).errors == 0;

    std::vector<uint8_t> const vec1(data, data + size);

    // step 0: parse input without exceptions; a parse error must then be
    // reported as a discarded value, never thrown
    json j_noexcept;
    bool noexcept_threw = false;
    try
    {
        j_noexcept = json::from_ubjson(vec1, true, false);
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
        json const j1 = json::from_ubjson(vec1);
        parsed = true;

        // without exceptions, the same input must give the same value
        assert(!noexcept_threw && !j_noexcept.is_discarded() && same_value(j_noexcept, j1));

        // the recovering parser must not have reported an error either
        assert(recovered_without_errors);

        try
        {
            // step 2.1: round trip without adding size annotations to container types
            std::vector<uint8_t> const vec2 = json::to_ubjson(j1, false, false);

            // step 2.2: round trip with adding size annotations but without adding type annotations to container types
            std::vector<uint8_t> const vec3 = json::to_ubjson(j1, true, false);

            // step 2.3: round trip with adding size as well as type annotations to container types
            std::vector<uint8_t> const vec4 = json::to_ubjson(j1, true, true);

            // parse serialization
            json const j2 = json::from_ubjson(vec2);
            json const j3 = json::from_ubjson(vec3);
            json const j4 = json::from_ubjson(vec4);

            // serializations must match
            assert(json::to_ubjson(j2, false, false) == vec2);
            assert(json::to_ubjson(j3, true, false) == vec3);
            assert(json::to_ubjson(j4, true, true) == vec4);
        }
        catch (const json::parse_error&)
        {
            // parsing a UBJSON serialization must not fail
            assert(false);
        }
    }
    catch (const json::parse_error&)
    {
        // parse errors are ok, because input may be random bytes
        assert(parsed || noexcept_threw || j_noexcept.is_discarded());
        assert(parsed || !recovered_without_errors);
    }
    catch (const json::type_error&)
    {
        // type errors can occur during parsing, too
        assert(parsed || noexcept_threw || j_noexcept.is_discarded());
    }
    catch (const json::out_of_range&)
    {
        // out of range errors may happen if provided sizes are excessive
        assert(parsed || noexcept_threw || j_noexcept.is_discarded());
        assert(parsed || !recovered_without_errors);
    }

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
