//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// All other tests keep the library's macros (JSON_TEST_KEEP_MACROS). This one
// includes json_view.hpp as users do, so that json.hpp undefines its macros
// (JSON_HAS_CPP_17, JSON_STRICT_NUL_HANDLING, ...) before the view is compiled.
#undef JSON_TEST_KEEP_MACROS
#include <nlohmann/json_view.hpp>

#include <string>
#include <type_traits>

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
    #include <string_view>
    #define JSON_VIEW_TEST_HAS_STRING_VIEW 1
#else
    #define JSON_VIEW_TEST_HAS_STRING_VIEW 0
#endif

// the view's own macros do not leak
#if defined(NLOHMANN_VIEW_LIKELY) || defined(NLOHMANN_VIEW_UNLIKELY) || defined(NLOHMANN_VIEW_ALWAYS_INLINE) || defined(NLOHMANN_VIEW_NOINLINE) \
    || defined(NLOHMANN_VIEW_NODISCARD) || defined(NLOHMANN_VIEW_THROW) || defined(NLOHMANN_VIEW_HAS_CPP_17) || defined(NLOHMANN_VIEW_LITTLE_ENDIAN) \
    || defined(NLOHMANN_VIEW_REPEAT16)
    #error "json_view.hpp leaks a macro"
#endif

TEST_CASE("json_view without the library's macros")
{
    // (this file also gets C++17 builds: it mentions JSON_HAS_CPP_17)
#if JSON_VIEW_TEST_HAS_STRING_VIEW
    CHECK(std::is_same<nlohmann::json_view::string_view_t, std::string_view>::value);
#endif
    const std::string text = "[1, 2.5, \"x\"]";
    const nlohmann::json_document d = nlohmann::json_document::parse(text);
    CHECK(d.root().size() == 3);
    CHECK(d.root().materialize() == nlohmann::json::parse(text));
    // the NUL handling of the library's configuration
    const std::string with_nul("[1]\0x", 5);
    CHECK(nlohmann::json_document::accept(with_nul) == nlohmann::json::accept(with_nul));
}
