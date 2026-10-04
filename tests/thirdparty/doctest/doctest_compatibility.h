#ifndef DOCTEST_COMPATIBILITY
#define DOCTEST_COMPATIBILITY

#define DOCTEST_CONFIG_VOID_CAST_EXPRESSIONS
#define DOCTEST_THREAD_LOCAL // make doctest itself avoid thread_local - https://github.com/onqtam/doctest/issues/172
                              // (Xcode 6/7, for which this define was originally added, is no longer
                              // supported, but the define must stay: it keeps doctest itself working the
                              // same way as JSON_NO_THREAD_LOCAL makes the library behave, for the same
                              // Clang/MinGW crash - see ci_test_no_thread_local in cmake/ci.cmake and
                              // include/nlohmann/detail/macro_scope.hpp)
#include "doctest.h"

// Catch doesn't require a semicolon after CAPTURE but doctest does
#undef CAPTURE
#define CAPTURE(x) DOCTEST_CAPTURE(x);

// Sections from Catch are called Subcases in doctest and don't work with std::string by default
#undef SUBCASE
#define SECTION(x) DOCTEST_SUBCASE(x)

// convenience macro around INFO since it doesn't support temporaries (it is optimized to avoid allocations for runtime speed)
#define INFO_WITH_TEMP_IMPL(x, var_name) const auto var_name = x; INFO(var_name) // lvalue!
#define INFO_WITH_TEMP(x) INFO_WITH_TEMP_IMPL(x, DOCTEST_ANONYMOUS(DOCTEST_STD_STRING_))

// doctest doesn't support THROWS_WITH for std::string out of the box (has to include <string>...)
#define CHECK_THROWS_WITH_STD_STR_IMPL(expr, str, var_name)                    \
    do {                                                                       \
        const std::string var_name = str;                                      \
        CHECK_THROWS_WITH(expr, var_name.c_str());                             \
    } while (false)
#define CHECK_THROWS_WITH_STD_STR(expr, str)                                   \
    CHECK_THROWS_WITH_STD_STR_IMPL(expr, str, DOCTEST_ANONYMOUS(DOCTEST_STD_STRING_))

// No test under tests/src still defines "private" as "public" (the last one was removed
// by #2352); this include predates that removal and stayed in case a test that does so
// is reintroduced, since it must come before <nlohmann/json.hpp> in that case (MSVC's STL
// errors that C++ keywords are being redefined if an STL header pulled in indirectly by
// the json include is the first one to see the #define). Keep it: dropping it would need
// the full CI matrix, including MSVC 2015+, to confirm nothing still depends on it.
#include <iosfwd>

// Catch does this by default
using doctest::Approx;

#endif
