//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// code shared by the fuzzer drivers tests/src/fuzzer-parse_*.cpp

#pragma once

#include <cassert> // assert
#include <nlohmann/json.hpp>

// the round-trip checks of the drivers are assertions; NDEBUG would compile them away
#ifdef NDEBUG
    #error "the fuzzer drivers must be built without NDEBUG"
#endif

// compares dumps rather than values, because NaN != NaN; keep writes strings
// byte for byte, so ill-formed UTF-8 that a binary reader accepts cannot throw
inline bool same_value(const nlohmann::json& lhs, const nlohmann::json& rhs)
{
    return lhs.dump(-1, ' ', false, nlohmann::json::error_handler_t::keep) == rhs.dump(-1, ' ', false, nlohmann::json::error_handler_t::keep);
}

// step 0 of each driver: parse the input without exceptions; a parse error
// must then be reported as a discarded value, never thrown. Type and
// out-of-range errors are not parse errors and still throw; then @a threw is
// set and null is returned.
template<typename Parse>
nlohmann::json parse_without_exceptions(Parse parse, bool& threw)
{
    threw = false;
    try
    {
        return parse();
    }
    catch (const nlohmann::json::parse_error&)
    {
        assert(false);
    }
    catch (const nlohmann::json::exception&)
    {
        threw = true;
    }
    return {};
}
