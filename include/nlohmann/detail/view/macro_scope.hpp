//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

// Macros of json_view.hpp and its detail headers. json.hpp undefines its own
// macros at its end (macro_unscope.hpp), so the view defines the few it needs
// under its own prefix; json_view.hpp undefines them all at its end
// (detail/view/macro_unscope.hpp). Configuration that json.hpp undefines is
// read from detail::abi_config instead.

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
    #define NLOHMANN_VIEW_HAS_CPP_17 1
#else
    #define NLOHMANN_VIEW_HAS_CPP_17 0
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define NLOHMANN_VIEW_LIKELY(x) __builtin_expect(!!(x), 1)
    #define NLOHMANN_VIEW_UNLIKELY(x) __builtin_expect(!!(x), 0)
    #define NLOHMANN_VIEW_ALWAYS_INLINE inline __attribute__((always_inline))
    #define NLOHMANN_VIEW_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
    #define NLOHMANN_VIEW_LIKELY(x) (x)
    #define NLOHMANN_VIEW_UNLIKELY(x) (x)
    #define NLOHMANN_VIEW_ALWAYS_INLINE __forceinline
    #define NLOHMANN_VIEW_NOINLINE __declspec(noinline)
#else
    #define NLOHMANN_VIEW_LIKELY(x) (x)
    #define NLOHMANN_VIEW_UNLIKELY(x) (x)
    #define NLOHMANN_VIEW_ALWAYS_INLINE inline
    #define NLOHMANN_VIEW_NOINLINE
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define NLOHMANN_VIEW_NODISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
    #define NLOHMANN_VIEW_NODISCARD _Check_return_
#else
    #define NLOHMANN_VIEW_NODISCARD
#endif

// exceptions as in json.hpp (JSON_NOEXCEPTION, JSON_THROW_USER)
#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) && !defined(JSON_NOEXCEPTION)
    #define NLOHMANN_VIEW_THROW(exception) throw exception
#else
    #include <cstdlib>
    // (the exception is built first, so that the arguments of the throwing
    // helpers count as used; the program ends anyway)
    #define NLOHMANN_VIEW_THROW(exception) (static_cast<void>(exception), std::abort())
#endif
#if defined(JSON_THROW_USER)
    #undef NLOHMANN_VIEW_THROW
    #define NLOHMANN_VIEW_THROW JSON_THROW_USER
#endif

// the parser stores a node's first word at once where the layout of `node` is
// known to be little-endian (MSVC targets are); elsewhere field by field
#if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_MSC_VER)
    #define NLOHMANN_VIEW_LITTLE_ENDIAN 1
#else
    #define NLOHMANN_VIEW_LITTLE_ENDIAN 0
#endif

/// sixteen checks at fixed offsets 0..15
#define NLOHMANN_VIEW_REPEAT16(X) X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15)
