#ifndef DOCTEST_COMPATIBILITY
#define DOCTEST_COMPATIBILITY

#define DOCTEST_THREAD_LOCAL // enable single-threaded builds on XCode 6/7 - https://github.com/onqtam/doctest/issues/172
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
        std::string var_name = str;                                            \
        CHECK_THROWS_WITH(expr, var_name.c_str());                             \
    } while (false)
#define CHECK_THROWS_WITH_STD_STR(expr, str)                                   \
    CHECK_THROWS_WITH_STD_STR_IMPL(expr, str, DOCTEST_ANONYMOUS(DOCTEST_STD_STRING_))

#undef CHECK_THROWS
#undef CHECK_THROWS_AS
#undef CHECK_THROWS_WITH
#undef CHECK_NOTHROW

#undef REQUIRE_THROWS
#undef REQUIRE_THROWS_AS
#undef REQUIRE_THROWS_WITH
#undef REQUIRE_NOTHROW

// doctest allows multiple statements in these macros (even blocks of code) but json
// tests rely on passing single function/constructor calls which have a [[nodiscard]]
// attribute so here we static_cast to void - just like Catch does
#define CHECK_THROWS(expr) DOCTEST_CHECK_THROWS(static_cast<void>(expr))
#define CHECK_THROWS_AS(expr, e) DOCTEST_CHECK_THROWS_AS(static_cast<void>(expr), e)
#define CHECK_THROWS_WITH(expr, e) DOCTEST_CHECK_THROWS_WITH(static_cast<void>(expr), e)
#define CHECK_NOTHROW(expr) DOCTEST_CHECK_NOTHROW(static_cast<void>(expr))

#define REQUIRE_THROWS(expr) DOCTEST_REQUIRE_THROWS(static_cast<void>(expr))
#define REQUIRE_THROWS_AS(expr, e) DOCTEST_REQUIRE_THROWS_AS(static_cast<void>(expr), e)
#define REQUIRE_THROWS_WITH(expr, e) DOCTEST_REQUIRE_THROWS_WITH(static_cast<void>(expr), e)
#define REQUIRE_NOTHROW(expr) DOCTEST_REQUIRE_NOTHROW(static_cast<void>(expr))

// included here because for some tests in the json repository private is defined as
// public and if no STL header is included before that then in the json include when STL
// stuff is included the MSVC STL complains (errors) that C++ keywords are being redefined
#include <iosfwd>

// Catch does this by default
using doctest::Approx;

#endif
