
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_COMPILER_CAPABILITIES_HPP_INCLUDED
#define CATCH_COMPILER_CAPABILITIES_HPP_INCLUDED

// Detect a number of compiler features - by compiler
// The following features are defined:
//
// CATCH_CONFIG_COUNTER : is the __COUNTER__ macro supported?
// CATCH_CONFIG_WINDOWS_SEH : is Windows SEH supported?
// CATCH_CONFIG_POSIX_SIGNALS : are POSIX signals supported?
// CATCH_CONFIG_DISABLE_EXCEPTIONS : Are exceptions enabled?
// ****************
// Note to maintainers: if new toggles are added please document them
// in configuration.md, too
// ****************

// In general each macro has a _NO_<feature name> form
// (e.g. CATCH_CONFIG_NO_POSIX_SIGNALS) which disables the feature.
// Many features, at point of detection, define an _INTERNAL_ macro, so they
// can be combined, en-mass, with the _NO_ forms later.

#include <catch2/internal/catch_platform.hpp>

#ifdef __cplusplus

#  if (__cplusplus >= 201402L) || (defined(_MSVC_LANG) && _MSVC_LANG >= 201402L)
#    define CATCH_CPP14_OR_GREATER
#  endif

#  if (__cplusplus >= 201703L) || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
#    define CATCH_CPP17_OR_GREATER
#  endif

#endif

// We have to avoid both ICC and Clang, because they try to mask themselves
// as gcc, and we want only GCC in this block
#if defined(__GNUC__) && !defined(__clang__) && !defined(__ICC) && !defined(__CUDACC__)
#    define CATCH_INTERNAL_START_WARNINGS_SUPPRESSION _Pragma( "GCC diagnostic push" )
#    define CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION  _Pragma( "GCC diagnostic pop" )

// This only works on GCC 9+. so we have to also add a global suppression of Wparentheses
// for older versions of GCC.
#    define CATCH_INTERNAL_SUPPRESS_PARENTHESES_WARNINGS \
         _Pragma( "GCC diagnostic ignored \"-Wparentheses\"" )

#    define CATCH_INTERNAL_SUPPRESS_UNUSED_VARIABLE_WARNINGS \
         _Pragma( "GCC diagnostic ignored \"-Wunused-variable\"" )

#    define CATCH_INTERNAL_IGNORE_BUT_WARN(...) (void)__builtin_constant_p(__VA_ARGS__)

#endif

#if defined(__clang__)

#    define CATCH_INTERNAL_START_WARNINGS_SUPPRESSION _Pragma( "clang diagnostic push" )
#    define CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION  _Pragma( "clang diagnostic pop" )

// As of this writing, IBM XL's implementation of __builtin_constant_p has a bug
// which results in calls to destructors being emitted for each temporary,
// without a matching initialization. In practice, this can result in something
// like `std::string::~string` being called on an uninitialized value.
//
// For example, this code will likely segfault under IBM XL:
// ```
// REQUIRE(std::string("12") + "34" == "1234")
// ```
//
// Therefore, `CATCH_INTERNAL_IGNORE_BUT_WARN` is not implemented.
#  if !defined(__ibmxl__) && !defined(__CUDACC__)
#    define CATCH_INTERNAL_IGNORE_BUT_WARN(...) (void)__builtin_constant_p(__VA_ARGS__) /* NOLINT(cppcoreguidelines-pro-type-vararg, hicpp-vararg) */
#  endif


#    define CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS \
         _Pragma( "clang diagnostic ignored \"-Wexit-time-destructors\"" ) \
         _Pragma( "clang diagnostic ignored \"-Wglobal-constructors\"")

#    define CATCH_INTERNAL_SUPPRESS_PARENTHESES_WARNINGS \
         _Pragma( "clang diagnostic ignored \"-Wparentheses\"" )

#    define CATCH_INTERNAL_SUPPRESS_UNUSED_VARIABLE_WARNINGS \
         _Pragma( "clang diagnostic ignored \"-Wunused-variable\"" )

#    define CATCH_INTERNAL_SUPPRESS_ZERO_VARIADIC_WARNINGS \
         _Pragma( "clang diagnostic ignored \"-Wgnu-zero-variadic-macro-arguments\"" )

#    define CATCH_INTERNAL_SUPPRESS_UNUSED_TEMPLATE_WARNINGS \
         _Pragma( "clang diagnostic ignored \"-Wunused-template\"" )

#endif // __clang__


////////////////////////////////////////////////////////////////////////////////
// Assume that non-Windows platforms support posix signals by default
#if !defined(CATCH_PLATFORM_WINDOWS)
    #define CATCH_INTERNAL_CONFIG_POSIX_SIGNALS
#endif

////////////////////////////////////////////////////////////////////////////////
// We know some environments not to support full POSIX signals
#if defined(__CYGWIN__) || defined(__QNX__) || defined(__EMSCRIPTEN__) || defined(__DJGPP__)
    #define CATCH_INTERNAL_CONFIG_NO_POSIX_SIGNALS
#endif

#ifdef __OS400__
#       define CATCH_INTERNAL_CONFIG_NO_POSIX_SIGNALS
#       define CATCH_CONFIG_COLOUR_NONE
#endif

////////////////////////////////////////////////////////////////////////////////
// Android somehow still does not support std::to_string
#if defined(__ANDROID__)
#    define CATCH_INTERNAL_CONFIG_NO_CPP11_TO_STRING
#    define CATCH_INTERNAL_CONFIG_ANDROID_LOGWRITE
#endif

////////////////////////////////////////////////////////////////////////////////
// Not all Windows environments support SEH properly
#if defined(__MINGW32__)
#    define CATCH_INTERNAL_CONFIG_NO_WINDOWS_SEH
#endif

////////////////////////////////////////////////////////////////////////////////
// PS4
#if defined(__ORBIS__)
#    define CATCH_INTERNAL_CONFIG_NO_NEW_CAPTURE
#endif

////////////////////////////////////////////////////////////////////////////////
// Cygwin
#ifdef __CYGWIN__

// Required for some versions of Cygwin to declare gettimeofday
// see: http://stackoverflow.com/questions/36901803/gettimeofday-not-declared-in-this-scope-cygwin
#   define _BSD_SOURCE
// some versions of cygwin (most) do not support std::to_string. Use the libstd check.
// https://gcc.gnu.org/onlinedocs/gcc-4.8.2/libstdc++/api/a01053_source.html line 2812-2813
# if !((__cplusplus >= 201103L) && defined(_GLIBCXX_USE_C99) \
           && !defined(_GLIBCXX_HAVE_BROKEN_VSWPRINTF))

#    define CATCH_INTERNAL_CONFIG_NO_CPP11_TO_STRING

# endif
#endif // __CYGWIN__

////////////////////////////////////////////////////////////////////////////////
// Visual C++
#if defined(_MSC_VER)

#  define CATCH_INTERNAL_START_WARNINGS_SUPPRESSION __pragma( warning(push) )
#  define CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION  __pragma( warning(pop) )

// Universal Windows platform does not support SEH
// Or console colours (or console at all...)
#  if defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_APP)
#    define CATCH_CONFIG_COLOUR_NONE
#  else
#    define CATCH_INTERNAL_CONFIG_WINDOWS_SEH
#  endif

// MSVC traditional preprocessor needs some workaround for __VA_ARGS__
// _MSVC_TRADITIONAL == 0 means new conformant preprocessor
// _MSVC_TRADITIONAL == 1 means old traditional non-conformant preprocessor
#  if !defined(__clang__) // Handle Clang masquerading for msvc
#    if !defined(_MSVC_TRADITIONAL) || (defined(_MSVC_TRADITIONAL) && _MSVC_TRADITIONAL)
#      define CATCH_INTERNAL_CONFIG_TRADITIONAL_MSVC_PREPROCESSOR
#    endif // MSVC_TRADITIONAL
#  endif // __clang__

#endif // _MSC_VER

#if defined(_REENTRANT) || defined(_MSC_VER)
// Enable async processing, as -pthread is specified or no additional linking is required
# define CATCH_INTERNAL_CONFIG_USE_ASYNC
#endif // _MSC_VER

////////////////////////////////////////////////////////////////////////////////
// Check if we are compiled with -fno-exceptions or equivalent
#if defined(__EXCEPTIONS) || defined(__cpp_exceptions) || defined(_CPPUNWIND)
#  define CATCH_INTERNAL_CONFIG_EXCEPTIONS_ENABLED
#endif

////////////////////////////////////////////////////////////////////////////////
// DJGPP
#ifdef __DJGPP__
#  define CATCH_INTERNAL_CONFIG_NO_WCHAR
#endif // __DJGPP__

////////////////////////////////////////////////////////////////////////////////
// Embarcadero C++Build
#if defined(__BORLANDC__)
    #define CATCH_INTERNAL_CONFIG_POLYFILL_ISNAN
#endif

////////////////////////////////////////////////////////////////////////////////

// Use of __COUNTER__ is suppressed during code analysis in
// CLion/AppCode 2017.2.x and former, because __COUNTER__ is not properly
// handled by it.
// Otherwise all supported compilers support COUNTER macro,
// but user still might want to turn it off
#if ( !defined(__JETBRAINS_IDE__) || __JETBRAINS_IDE__ >= 20170300L )
    #define CATCH_INTERNAL_CONFIG_COUNTER
#endif


////////////////////////////////////////////////////////////////////////////////

// RTX is a special version of Windows that is real time.
// This means that it is detected as Windows, but does not provide
// the same set of capabilities as real Windows does.
#if defined(UNDER_RTSS) || defined(RTX64_BUILD)
    #define CATCH_INTERNAL_CONFIG_NO_WINDOWS_SEH
    #define CATCH_INTERNAL_CONFIG_NO_ASYNC
    #define CATCH_CONFIG_COLOUR_NONE
#endif

#if !defined(_GLIBCXX_USE_C99_MATH_TR1)
#define CATCH_INTERNAL_CONFIG_GLOBAL_NEXTAFTER
#endif

// Various stdlib support checks that require __has_include
#if defined(__has_include)
  // Check if string_view is available and usable
  #if __has_include(<string_view>) && defined(CATCH_CPP17_OR_GREATER)
  #    define CATCH_INTERNAL_CONFIG_CPP17_STRING_VIEW
  #endif

  // Check if optional is available and usable
  #  if __has_include(<optional>) && defined(CATCH_CPP17_OR_GREATER)
  #    define CATCH_INTERNAL_CONFIG_CPP17_OPTIONAL
  #  endif // __has_include(<optional>) && defined(CATCH_CPP17_OR_GREATER)

  // Check if byte is available and usable
  #  if __has_include(<cstddef>) && defined(CATCH_CPP17_OR_GREATER)
  #    include <cstddef>
  #    if __cpp_lib_byte > 0
  #      define CATCH_INTERNAL_CONFIG_CPP17_BYTE
  #    endif
  #  endif // __has_include(<cstddef>) && defined(CATCH_CPP17_OR_GREATER)

  // Check if variant is available and usable
  #  if __has_include(<variant>) && defined(CATCH_CPP17_OR_GREATER)
  #    if defined(__clang__) && (__clang_major__ < 8)
         // work around clang bug with libstdc++ https://bugs.llvm.org/show_bug.cgi?id=31852
         // fix should be in clang 8, workaround in libstdc++ 8.2
  #      include <ciso646>
  #      if defined(__GLIBCXX__) && defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE < 9)
  #        define CATCH_CONFIG_NO_CPP17_VARIANT
  #      else
  #        define CATCH_INTERNAL_CONFIG_CPP17_VARIANT
  #      endif // defined(__GLIBCXX__) && defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE < 9)
  #    else
  #      define CATCH_INTERNAL_CONFIG_CPP17_VARIANT
  #    endif // defined(__clang__) && (__clang_major__ < 8)
  #  endif // __has_include(<variant>) && defined(CATCH_CPP17_OR_GREATER)
#endif // defined(__has_include)


#if defined(CATCH_INTERNAL_CONFIG_COUNTER) && !defined(CATCH_CONFIG_NO_COUNTER) && !defined(CATCH_CONFIG_COUNTER)
#   define CATCH_CONFIG_COUNTER
#endif
#if defined(CATCH_INTERNAL_CONFIG_WINDOWS_SEH) && !defined(CATCH_CONFIG_NO_WINDOWS_SEH) && !defined(CATCH_CONFIG_WINDOWS_SEH) && !defined(CATCH_INTERNAL_CONFIG_NO_WINDOWS_SEH)
#   define CATCH_CONFIG_WINDOWS_SEH
#endif
// This is set by default, because we assume that unix compilers are posix-signal-compatible by default.
#if defined(CATCH_INTERNAL_CONFIG_POSIX_SIGNALS) && !defined(CATCH_INTERNAL_CONFIG_NO_POSIX_SIGNALS) && !defined(CATCH_CONFIG_NO_POSIX_SIGNALS) && !defined(CATCH_CONFIG_POSIX_SIGNALS)
#   define CATCH_CONFIG_POSIX_SIGNALS
#endif
// This is set by default, because we assume that compilers with no wchar_t support are just rare exceptions.
#if !defined(CATCH_INTERNAL_CONFIG_NO_WCHAR) && !defined(CATCH_CONFIG_NO_WCHAR) && !defined(CATCH_CONFIG_WCHAR)
#   define CATCH_CONFIG_WCHAR
#endif

#if !defined(CATCH_INTERNAL_CONFIG_NO_CPP11_TO_STRING) && !defined(CATCH_CONFIG_NO_CPP11_TO_STRING) && !defined(CATCH_CONFIG_CPP11_TO_STRING)
#    define CATCH_CONFIG_CPP11_TO_STRING
#endif

#if defined(CATCH_INTERNAL_CONFIG_CPP17_OPTIONAL) && !defined(CATCH_CONFIG_NO_CPP17_OPTIONAL) && !defined(CATCH_CONFIG_CPP17_OPTIONAL)
#  define CATCH_CONFIG_CPP17_OPTIONAL
#endif

#if defined(CATCH_INTERNAL_CONFIG_CPP17_STRING_VIEW) && !defined(CATCH_CONFIG_NO_CPP17_STRING_VIEW) && !defined(CATCH_CONFIG_CPP17_STRING_VIEW)
#  define CATCH_CONFIG_CPP17_STRING_VIEW
#endif

#if defined(CATCH_INTERNAL_CONFIG_CPP17_VARIANT) && !defined(CATCH_CONFIG_NO_CPP17_VARIANT) && !defined(CATCH_CONFIG_CPP17_VARIANT)
#  define CATCH_CONFIG_CPP17_VARIANT
#endif

#if defined(CATCH_INTERNAL_CONFIG_CPP17_BYTE) && !defined(CATCH_CONFIG_NO_CPP17_BYTE) && !defined(CATCH_CONFIG_CPP17_BYTE)
#  define CATCH_CONFIG_CPP17_BYTE
#endif


#if defined(CATCH_CONFIG_EXPERIMENTAL_REDIRECT)
#  define CATCH_INTERNAL_CONFIG_NEW_CAPTURE
#endif

#if defined(CATCH_INTERNAL_CONFIG_NEW_CAPTURE) && !defined(CATCH_INTERNAL_CONFIG_NO_NEW_CAPTURE) && !defined(CATCH_CONFIG_NO_NEW_CAPTURE) && !defined(CATCH_CONFIG_NEW_CAPTURE)
#  define CATCH_CONFIG_NEW_CAPTURE
#endif

#if !defined(CATCH_INTERNAL_CONFIG_EXCEPTIONS_ENABLED) && !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
#  define CATCH_CONFIG_DISABLE_EXCEPTIONS
#endif

#if defined(CATCH_INTERNAL_CONFIG_POLYFILL_ISNAN) && !defined(CATCH_CONFIG_NO_POLYFILL_ISNAN) && !defined(CATCH_CONFIG_POLYFILL_ISNAN)
#  define CATCH_CONFIG_POLYFILL_ISNAN
#endif

#if defined(CATCH_INTERNAL_CONFIG_USE_ASYNC)  && !defined(CATCH_INTERNAL_CONFIG_NO_ASYNC) && !defined(CATCH_CONFIG_NO_USE_ASYNC) && !defined(CATCH_CONFIG_USE_ASYNC)
#  define CATCH_CONFIG_USE_ASYNC
#endif

#if defined(CATCH_INTERNAL_CONFIG_ANDROID_LOGWRITE) && !defined(CATCH_CONFIG_NO_ANDROID_LOGWRITE) && !defined(CATCH_CONFIG_ANDROID_LOGWRITE)
#  define CATCH_CONFIG_ANDROID_LOGWRITE
#endif

#if defined(CATCH_INTERNAL_CONFIG_GLOBAL_NEXTAFTER) && !defined(CATCH_CONFIG_NO_GLOBAL_NEXTAFTER) && !defined(CATCH_CONFIG_GLOBAL_NEXTAFTER)
#  define CATCH_CONFIG_GLOBAL_NEXTAFTER
#endif


// Even if we do not think the compiler has that warning, we still have
// to provide a macro that can be used by the code.
#if !defined(CATCH_INTERNAL_START_WARNINGS_SUPPRESSION)
#   define CATCH_INTERNAL_START_WARNINGS_SUPPRESSION
#endif
#if !defined(CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION)
#   define CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION
#endif
#if !defined(CATCH_INTERNAL_SUPPRESS_PARENTHESES_WARNINGS)
#   define CATCH_INTERNAL_SUPPRESS_PARENTHESES_WARNINGS
#endif
#if !defined(CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS)
#   define CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS
#endif
#if !defined(CATCH_INTERNAL_SUPPRESS_UNUSED_VARIABLE_WARNINGS)
#   define CATCH_INTERNAL_SUPPRESS_UNUSED_VARIABLE_WARNINGS
#endif
#if !defined(CATCH_INTERNAL_SUPPRESS_ZERO_VARIADIC_WARNINGS)
#   define CATCH_INTERNAL_SUPPRESS_ZERO_VARIADIC_WARNINGS
#endif

// The goal of this macro is to avoid evaluation of the arguments, but
// still have the compiler warn on problems inside...
#if !defined(CATCH_INTERNAL_IGNORE_BUT_WARN)
#   define CATCH_INTERNAL_IGNORE_BUT_WARN(...)
#endif

#if defined(__APPLE__) && defined(__apple_build_version__) && (__clang_major__ < 10)
#   undef CATCH_INTERNAL_SUPPRESS_UNUSED_TEMPLATE_WARNINGS
#elif defined(__clang__) && (__clang_major__ < 5)
#   undef CATCH_INTERNAL_SUPPRESS_UNUSED_TEMPLATE_WARNINGS
#endif

#if !defined(CATCH_INTERNAL_SUPPRESS_UNUSED_TEMPLATE_WARNINGS)
#   define CATCH_INTERNAL_SUPPRESS_UNUSED_TEMPLATE_WARNINGS
#endif

#if defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
#define CATCH_TRY if ((true))
#define CATCH_CATCH_ALL if ((false))
#define CATCH_CATCH_ANON(type) if ((false))
#else
#define CATCH_TRY try
#define CATCH_CATCH_ALL catch (...)
#define CATCH_CATCH_ANON(type) catch (type)
#endif

#if defined(CATCH_INTERNAL_CONFIG_TRADITIONAL_MSVC_PREPROCESSOR) && !defined(CATCH_CONFIG_NO_TRADITIONAL_MSVC_PREPROCESSOR) && !defined(CATCH_CONFIG_TRADITIONAL_MSVC_PREPROCESSOR)
#define CATCH_CONFIG_TRADITIONAL_MSVC_PREPROCESSOR
#endif

#endif // CATCH_COMPILER_CAPABILITIES_HPP_INCLUDED
