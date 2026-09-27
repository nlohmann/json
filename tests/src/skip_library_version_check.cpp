//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Standalone compile-and-run check for the JSON_SKIP_LIBRARY_VERSION_CHECK
// configuration macro, which (per #5423) was never exercised anywhere in the
// test matrix.
//
// include/nlohmann/detail/abi_macros.hpp normally emits a #warning if
// NLOHMANN_JSON_VERSION_MAJOR/MINOR/PATCH are already defined (as they would
// be by an earlier inclusion of a different version of the library) with
// values that mismatch the version about to be defined -- unless
// JSON_SKIP_LIBRARY_VERSION_CHECK is defined, in which case the check (and
// that #warning) is skipped.
//
// This file deliberately is not named tests/src/unit-*.cpp: it is compiled
// directly (with a modest, non-strict warning set) by the dedicated
// ci_test_skiplibraryversioncheck target in cmake/ci.cmake, rather than being
// folded into the library's own -Weverything/-Werror unit test matrix. That
// is because the scenario simulated here -- mixing two different, already
// differently-versioned inclusions of the library in one translation unit --
// unavoidably also triggers the *compiler's own* "macro redefined" warning,
// independent of (and unaffected by) JSON_SKIP_LIBRARY_VERSION_CHECK, which
// only ever silences the library's own #warning. Building this file under
// -Weverything -Werror would therefore fail for a reason unrelated to the
// macro under test.
#define NLOHMANN_JSON_VERSION_MAJOR 0
#define NLOHMANN_JSON_VERSION_MINOR 0
#define NLOHMANN_JSON_VERSION_PATCH 0

#define JSON_SKIP_LIBRARY_VERSION_CHECK 1

#include <nlohmann/json.hpp>

int main()
{
    // reaching this point at all already proves that the mismatched,
    // pre-defined version macros above did not stop compilation -- which is
    // exactly what JSON_SKIP_LIBRARY_VERSION_CHECK is for. The library must
    // also still be fully usable.
    const nlohmann::json j = {{"a", 1}, {"b", {1, 2, 3}}};
    if (j.dump() != "{\"a\":1,\"b\":[1,2,3]}")
    {
        return 1;
    }

    // include/nlohmann/detail/abi_macros.hpp unconditionally (re)defines the
    // version macros to the library's real, current version right after the
    // (here, skipped) mismatch check, regardless of the deliberately wrong
    // stand-in values defined above.
    if (NLOHMANN_JSON_VERSION_MAJOR == 0 && NLOHMANN_JSON_VERSION_MINOR == 0 && NLOHMANN_JSON_VERSION_PATCH == 0)
    {
        return 1;
    }

    return 0;
}
