//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++20-only part of unit-regression2.cpp (std::span and ranges
// regression tests). It is kept in a separate translation unit so the (much larger) unit-
// regression2.cpp is built for C++11 only and not rebuilt for every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#ifdef JSON_HAS_CPP_20
#include <string>

#if __has_include(<span>)
    #include <span>
#endif

/////////////////////////////////////////////////////////////////////
// for #4440
/////////////////////////////////////////////////////////////////////
#if JSON_HAS_RANGES == 1
    #include <ranges>
#endif

TEST_CASE("regression tests 2 (C++20)")
{
#ifndef _LIBCPP_VERSION // see https://github.com/nlohmann/json/issues/4490
    // classic Intel ICC reports <span> as includable but cannot actually compile
    // std::span/std::as_bytes usage below
#if __has_include(<span>) && !defined(__ICC) && !defined(__INTEL_COMPILER)
    SECTION("issue #2546 - parsing containers of std::byte")
    {
        const char DATA[] = R"("Hello, world!")"; // NOLINT(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        // exclude the trailing '\0' that string-literal initialization adds to
        // DATA: std::span(DATA) would span the full array extent (including
        // that NUL), which is only silently accepted as end-of-input by default
        // and would fail under JSON_STRICT_NUL_HANDLING
        const auto s = std::as_bytes(std::span(DATA, sizeof(DATA) - 1));
        const json j = json::parse(s);
        CHECK(j.dump() == "\"Hello, world!\"");
    }
#endif
#endif

}

#endif
