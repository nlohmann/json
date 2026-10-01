//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

// libc++ annotates std::mutex for Clang's thread safety analysis, so -Weverything
// reports -Wthread-safety-negative for the locks in doctest's reporters, which are
// only compiled in this file. __has_warning keeps older Clang versions from
// reporting an unknown warning group.
#if defined(__clang__) && defined(__has_warning)
    #if __has_warning("-Wthread-safety-negative")
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wthread-safety-negative"
    #endif
#endif

#include "doctest_compatibility.h"

#if defined(__clang__) && defined(__has_warning)
    #if __has_warning("-Wthread-safety-negative")
        #pragma clang diagnostic pop
    #endif
#endif
