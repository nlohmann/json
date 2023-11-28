//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2023 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include "doctest.h"

#include <iostream>
#include <regex>
#include <string>

#define STRINGIZE_EX(x) #x
#define STRINGIZE(x) STRINGIZE_EX(x)

template<typename T>
std::string namespace_name(std::string ns, T* /*unused*/ = nullptr) // NOLINT(performance-unnecessary-value-param)
{
#if DOCTEST_MSVC && !DOCTEST_CLANG
    ns = __FUNCSIG__;
#elif !DOCTEST_CLANG
    ns = __PRETTY_FUNCTION__;
#endif
    std::smatch m;

    // extract the true namespace name from the function signature
    CAPTURE(ns);
    CHECK(std::regex_search(ns, m, std::regex("nlohmann(::[a-zA-Z0-9_]+)*::basic_json")));

    return m.str();
}
