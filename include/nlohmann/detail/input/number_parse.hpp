//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cfloat> // FLT_EVAL_METHOD
#include <clocale> // LC_NUMERIC, LC_NUMERIC_MASK, newlocale, _create_locale
#include <cstddef> // size_t
#include <cstdint> // int64_t, uint64_t
#include <cstdlib> // strtof, strtod, strtold, strtof_l, strtod_l, strtold_l, _strtof_l, _strtod_l, _strtold_l
#include <limits> // numeric_limits
#include <string> // string
#include <utility> // move

#include <nlohmann/detail/macro_scope.hpp>

// std::from_chars lives in <charconv>, but being in C++17 mode does not
// guarantee the header exists: GCC 7 sets __cplusplus to C++17 yet ships no
// <charconv> (added in GCC 8; floating-point support in GCC 11). Guard the
// include with __has_include so such toolchains fall back to the scalar path.
#if defined(JSON_HAS_CPP_17) && defined(__has_include)
    #if __has_include(<charconv>)
        #include <charconv> // from_chars
        #include <system_error> // errc

        // std::from_chars is used for floating-point numbers
        // - for float, double, and long double if __cpp_lib_to_chars announces
        //   complete support (only checked in C++17 or later: some standard
        //   libraries, e.g. libstdc++ 15, define it even in C++14 mode, where
        //   <charconv> is not included);
        // - for float and double with libc++ 20 or later, which does not define
        //   __cpp_lib_to_chars because long double is missing. On Apple
        //   platforms, the implementation is part of the system's libc++ and
        //   only available when deploying to macOS/iOS 26 or later; for older
        //   deployment targets, _LIBCPP_AVAILABILITY_HAS_FROM_CHARS_FLOATING_POINT
        //   is 0, and the fallbacks below are used.
        #if defined(__cpp_lib_to_chars)
            #define JSON_HAS_FLOAT_FROM_CHARS 1
            #define JSON_HAS_LONG_DOUBLE_FROM_CHARS 1
        #elif defined(_LIBCPP_VERSION) && defined(_LIBCPP_AVAILABILITY_HAS_FROM_CHARS_FLOATING_POINT)
            #if _LIBCPP_VERSION >= 200000 && _LIBCPP_AVAILABILITY_HAS_FROM_CHARS_FLOATING_POINT
                #define JSON_HAS_FLOAT_FROM_CHARS 1
            #endif
        #endif
    #endif
#endif

#ifndef JSON_HAS_FLOAT_FROM_CHARS
    #define JSON_HAS_FLOAT_FROM_CHARS 0
#endif

#ifndef JSON_HAS_LONG_DOUBLE_FROM_CHARS
    #define JSON_HAS_LONG_DOUBLE_FROM_CHARS 0
#endif

// strtof_l/strtod_l/strtold_l convert with a given locale object instead of the
// global C locale. They are not part of ISO C or C++, so they are only used where
// the C library is known to declare them: Microsoft's UCRT (as _strtod_l etc.),
// Apple's libc (in <xlocale.h>, which must follow <cstdlib>), and glibc (as GNU
// extensions, visible because g++ and clang++ define _GNU_SOURCE for C++).
// Everything else, e.g. MinGW (whose runtime lacks them), musl (which declares
// only some of them), Android, or uClibc, uses parse_float_locale_aware().
#if defined(_MSC_VER) && !defined(__MINGW32__) && _MSC_VER >= 1900
    #define JSON_HAS_C_LOCALE_STRTOD 1
#elif defined(__APPLE__)
    #include <xlocale.h> // newlocale, strtof_l, strtod_l, strtold_l
    #define JSON_HAS_C_LOCALE_STRTOD 1
#elif defined(__GLIBC__) && defined(__USE_GNU) && !defined(__UCLIBC__)
    #define JSON_HAS_C_LOCALE_STRTOD 1
#else
    #define JSON_HAS_C_LOCALE_STRTOD 0
#endif

// This file contains the value-conversion helpers used by the lexer to turn an
// already-validated number token into a value, where possible without the
// locale/errno overhead of std::strtoull/std::strtod. They are free functions so
// the lexer stays focused on scanning; see lexer::convert_number().

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief fast integer parser for an already-validated unsigned integer

The number scanner has already checked that [first, last) is a valid JSON
integer, so this only needs to accumulate the digits and detect overflow. This
avoids the locale/errno machinery of std::strtoull, which dominates
integer-heavy inputs.

@param[in]  first   pointer to the first character (a digit)
@param[in]  last    pointer past the last character
@param[out] value   the parsed value on success
@return true if the value fit into @a NumberUnsignedType; false on overflow, in
        which case the caller falls back to floating-point parsing (matching the
        previous std::strtoull behavior)
*/
template<typename NumberUnsignedType>
bool parse_integer_unsigned(const char* first, const char* last, NumberUnsignedType& value) noexcept
{
    // accumulate in the widest unsigned type used by the previous strtoull
    // path so the overflow behavior is unchanged for custom number types
    std::uint64_t x = 0;
    constexpr std::uint64_t cutoff = (std::numeric_limits<std::uint64_t>::max)() / 10u;
    constexpr std::uint64_t cutlim = (std::numeric_limits<std::uint64_t>::max)() % 10u;
    for (const char* p = first; p != last; ++p)
    {
        const auto digit = static_cast<std::uint64_t>(static_cast<unsigned char>(*p) - static_cast<unsigned char>('0'));
        if (JSON_HEDLEY_UNLIKELY(x > cutoff || (x == cutoff && digit > cutlim)))
        {
            return false;
        }
        x = (x * 10u) + digit;
    }
    value = static_cast<NumberUnsignedType>(x);
    // reject values that do not round-trip into a narrower NumberUnsignedType
    return static_cast<std::uint64_t>(value) == x;
}

/*!
@brief fast integer parser for an already-validated negative integer

@param[in]  first   pointer to the leading '-'
@param[in]  last    pointer past the last character
@param[out] value   the parsed (negative) value on success
@return true on success; false on overflow (caller falls back to float)
*/
template<typename NumberIntegerType>
bool parse_integer_signed(const char* first, const char* last, NumberIntegerType& value) noexcept
{
    // the state machine only reaches the signed path via a leading '-'
    JSON_ASSERT(first != last && *first == '-');
    std::uint64_t magnitude = 0;
    // |INT64_MIN| == INT64_MAX + 1; this is the largest admissible magnitude
    constexpr std::uint64_t limit = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1u;
    for (const char* p = first + 1; p != last; ++p)
    {
        const auto digit = static_cast<std::uint64_t>(static_cast<unsigned char>(*p) - static_cast<unsigned char>('0'));
        if (JSON_HEDLEY_UNLIKELY(magnitude > (limit - digit) / 10u))
        {
            return false;
        }
        magnitude = (magnitude * 10u) + digit;
    }
    const std::int64_t x = (magnitude == limit)
                           ? (std::numeric_limits<std::int64_t>::min)()
                           : -static_cast<std::int64_t>(magnitude);
    value = static_cast<NumberIntegerType>(x);
    // reject values that do not round-trip into a narrower NumberIntegerType
    return static_cast<std::int64_t>(value) == x;
}

/*!
@brief exact fast path for parsing a `double` (Clinger's algorithm)

For the common case - at most 19 significant digits, a decimal exponent in
[-22, 22], and a significand below 2^53 - the value equals significand *
10^exp computed in IEEE-754 double arithmetic, which is exact under
round-to-nearest because both operands are exactly representable. This is the
same fast path used by fast_float/simdjson; the general cases are left to
std::strtod. The parser only activates for number_float_t == double; float and
long double keep the std::strtof/std::strtold paths (see the templated overload
below).

@param[in]  first  pointer to the first character of the number
@param[in]  last   pointer past the last character
@param[out] out    the parsed value on success
@return true if the value was parsed exactly; false to fall back to strtod
*/
inline bool parse_float_fast(const char* first, const char* last, double& out) noexcept
{
#if defined(FLT_EVAL_METHOD) && FLT_EVAL_METHOD != 0
    // Clinger's fast path is only exact when double operations are evaluated in
    // true double precision. On platforms that keep intermediates in extended
    // precision (e.g. the x87 FPU on 32-bit x86, where FLT_EVAL_METHOD == 2) the
    // single significand * 10^scale step is double-rounded and can be 1 ULP off,
    // so decline and let the caller fall back to the correctly-rounded
    // std::from_chars / std::strtod path.
    static_cast<void>(first);
    static_cast<void>(last);
    static_cast<void>(out);
    return false;
#else
    static const std::array<double, 23> powers_of_ten =
    {
        {
            1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11,
            1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22
        }
    };

    const char* p = first;
    bool negative = false;
    if (p != last && (*p == '-' || *p == '+'))
    {
        negative = (*p == '-');
        ++p;
    }

    std::uint64_t significand = 0;
    int num_digits = 0;
    int fractional_digits = 0;
    bool seen_dot = false;
    bool any_digit = false;
    for (; p != last; ++p)
    {
        const char c = *p;
        if (c >= '0' && c <= '9')
        {
            any_digit = true;
            if (JSON_HEDLEY_UNLIKELY(num_digits >= 19))
            {
                return false; // significand may not fit into uint64_t
            }
            significand = (significand * 10u) + static_cast<std::uint64_t>(c - '0');
            ++num_digits;
            fractional_digits += static_cast<int>(seen_dot);
        }
        else if (c == '.')
        {
            if (JSON_HEDLEY_UNLIKELY(seen_dot))
            {
                return false;
            }
            seen_dot = true;
        }
        else if (c == 'e' || c == 'E')
        {
            ++p;
            break;
        }
        else
        {
            return false;
        }
    }
    if (JSON_HEDLEY_UNLIKELY(!any_digit))
    {
        return false;
    }

    int exponent = 0;
    if (p != last) // an exponent part remains
    {
        bool exp_negative = false;
        if (p != last && (*p == '-' || *p == '+'))
        {
            exp_negative = (*p == '-');
            ++p;
        }
        bool any_exp_digit = false;
        for (; p != last; ++p)
        {
            if (JSON_HEDLEY_UNLIKELY(*p < '0' || *p > '9'))
            {
                return false;
            }
            exponent = (exponent * 10) + (*p - '0');
            any_exp_digit = true;
            if (JSON_HEDLEY_UNLIKELY(exponent > 9999))
            {
                return false;
            }
        }
        if (JSON_HEDLEY_UNLIKELY(!any_exp_digit))
        {
            return false;
        }
        if (exp_negative)
        {
            exponent = -exponent;
        }
    }

    const int scale = exponent - fractional_digits;
    if (JSON_HEDLEY_UNLIKELY(significand >= (static_cast<std::uint64_t>(1) << 53)))
    {
        return false; // significand not exactly representable as double
    }

    auto result = static_cast<double>(significand);
    if (scale >= 0)
    {
        if (JSON_HEDLEY_UNLIKELY(scale > 22))
        {
            return false;
        }
        result *= powers_of_ten[static_cast<std::size_t>(scale)];
    }
    else
    {
        if (JSON_HEDLEY_UNLIKELY(-scale > 22))
        {
            return false;
        }
        result /= powers_of_ten[static_cast<std::size_t>(-scale)];
    }
    out = negative ? -result : result;
    return true;
#endif
}

/// fast float path is only exact for `double`; decline for float/long double
template<typename FloatType>
bool parse_float_fast(const char* /*first*/, const char* /*last*/, FloatType& /*out*/) noexcept
{
    return false;
}

/*!
@brief derive the value of a number token that is out of range

The token [first, last) is a valid JSON number whose value cannot be
represented by @a FloatType. The result follows from the token alone: a value
of at least 1 can only overflow and becomes ±infinity (which the parser reports
as out_of_range.406), a smaller one can only underflow and becomes ±0. The sign
is taken from a leading '-', and the magnitude from the decimal exponent of the
first nonzero digit.

A value slightly below the smallest normal number may still be representable
as a subnormal number, which some implementations also report as out of range
(libstdc++'s std::from_chars before GCC 13, which relies on the ERANGE of
strtod for long double, and in GCC 11 for all types). Therefore ±0 is only
returned if the value is below half the smallest subnormal number whatever its
digits are.

@param[in]  first  pointer to the first character of the token
@param[in]  last   pointer past the last character
@param[out] out    ±infinity or ±0 on success
@return true if @a out was set; false if the value may be a subnormal number,
        in which case the caller converts the token another way
*/
template<typename FloatType>
bool parse_float_out_of_range(const char* first, const char* last, FloatType& out) noexcept
{
    const bool negative = first != last && *first == '-';
    const char* p = negative ? first + 1 : first;

    // the decimal exponent of the first nonzero digit, from its position
    // relative to the decimal point
    std::int64_t exponent = 0;
    bool nonzero = false;
    for (; p != last && *p >= '0' && *p <= '9'; ++p)
    {
        if (nonzero)
        {
            ++exponent;
        }
        else
        {
            nonzero = *p != '0';
        }
    }
    if (p != last && *p == '.')
    {
        for (++p; p != last && *p >= '0' && *p <= '9'; ++p)
        {
            if (!nonzero)
            {
                --exponent;
                nonzero = *p != '0';
            }
        }
    }

    if (nonzero && p != last && (*p == 'e' || *p == 'E'))
    {
        ++p;
        const bool negative_exponent = p != last && *p == '-';
        if (p != last && (*p == '-' || *p == '+'))
        {
            ++p;
        }
        // saturate: a larger exponent is far out of range for every type
        constexpr std::int64_t saturation = 100000000000000000; // 10^17
        std::int64_t explicit_exponent = 0;
        for (; p != last && *p >= '0' && *p <= '9'; ++p)
        {
            if (explicit_exponent < saturation)
            {
                explicit_exponent = (explicit_exponent * 10) + (*p - '0');
            }
        }
        exponent += negative_exponent ? -explicit_exponent : explicit_exponent;
    }

    if (nonzero && exponent >= 0)
    {
        out = negative ? -std::numeric_limits<FloatType>::infinity() : std::numeric_limits<FloatType>::infinity();
        return true;
    }

    // The value is below 10^(exponent + 1). It rounds to zero if that is at most
    // half the smallest subnormal number, 2^(min_exponent - digits - 1). The
    // bound rounds log10(2) up to 0.30103 and the product toward zero, and the
    // margin of 2 keeps it on the safe side.
    constexpr std::int64_t zero_exponent = (static_cast<std::int64_t>(std::numeric_limits<FloatType>::min_exponent - std::numeric_limits<FloatType>::digits - 1) * 30103 / 100000) - 2;
    if (!nonzero || exponent <= zero_exponent)
    {
        out = negative ? -FloatType(0) : FloatType(0);
        return true;
    }
    return false;
}

/*!
@brief parse a float with std::from_chars (Eisel-Lemire) when available

std::from_chars is locale-independent, correctly rounded, and - via the
Eisel-Lemire algorithm in modern standard libraries - much faster than strtod
over the whole value range (not just the Clinger subset). It is used only where
the standard library implements it for @a FloatType (see
JSON_HAS_FLOAT_FROM_CHARS) and only when it consumes the entire token
([first, last)).

For an under- or overflow (std::errc::result_out_of_range), implementations
disagree on the value they store: libstdc++ leaves it unchanged, whereas libc++
and the MSVC STL store ±0 or ±infinity (P4168). The result is therefore derived
from the token, see parse_float_out_of_range().

@return true if the value was parsed exactly and fully; false to fall back
*/
template<typename FloatType>
bool parse_float_from_chars(const char* first, const char* last, FloatType& out) noexcept
{
#if JSON_HAS_FLOAT_FROM_CHARS
    const auto result = std::from_chars(first, last, out);
    if (JSON_HEDLEY_UNLIKELY(result.ec == std::errc::result_out_of_range && result.ptr == last))
    {
        return parse_float_out_of_range(first, last, out);
    }
    return result.ec == std::errc() && result.ptr == last;
#else
    static_cast<void>(first);
    static_cast<void>(last);
    static_cast<void>(out);
    return false;
#endif
}

#if JSON_HAS_FLOAT_FROM_CHARS && !JSON_HAS_LONG_DOUBLE_FROM_CHARS
/// libc++ implements std::from_chars for float and double, but not for long double
inline bool parse_float_from_chars(const char* /*first*/, const char* /*last*/, long double& /*out*/) noexcept
{
    return false;
}
#endif

#if JSON_HAS_C_LOCALE_STRTOD
#if defined(_MSC_VER)
using c_locale_t = _locale_t;

/// the "C" locale for the numeric category, created on first use and never freed
inline c_locale_t c_numeric_locale() noexcept
{
    static const c_locale_t c_locale = _create_locale(LC_NUMERIC, "C");
    return c_locale;
}

inline void strtof_c_locale(float& f, const char* str, char** endptr, c_locale_t loc) noexcept
{
    f = _strtof_l(str, endptr, loc);
}

inline void strtof_c_locale(double& f, const char* str, char** endptr, c_locale_t loc) noexcept
{
    f = _strtod_l(str, endptr, loc);
}

inline void strtof_c_locale(long double& f, const char* str, char** endptr, c_locale_t loc) noexcept
{
    f = _strtold_l(str, endptr, loc);
}
#else
using c_locale_t = locale_t;

/// the "C" locale for the numeric category, created on first use and never freed
inline c_locale_t c_numeric_locale() noexcept
{
    static const c_locale_t c_locale = newlocale(LC_NUMERIC_MASK, "C", nullptr);
    return c_locale;
}

inline void strtof_c_locale(float& f, const char* str, char** endptr, c_locale_t loc) noexcept
{
    f = strtof_l(str, endptr, loc);
}

inline void strtof_c_locale(double& f, const char* str, char** endptr, c_locale_t loc) noexcept
{
    f = strtod_l(str, endptr, loc);
}

inline void strtof_c_locale(long double& f, const char* str, char** endptr, c_locale_t loc) noexcept
{
    f = strtold_l(str, endptr, loc);
}
#endif
#endif

/*!
@brief parse a float with strtof_l/strtod_l/strtold_l in the "C" locale

These functions round correctly like strtod, but take the "C" locale as an
argument instead of using the global one, so the decimal point is always '.'.
The locale object is created on first use and never freed, so it remains valid
for parsers that run during static destruction.

@param[in]  first  pointer to the first character of the token, which must be
                   followed by a NUL character
@param[in]  last   pointer past the last character
@param[out] out    the parsed value (±infinity or ±0 if out of range)
@return true if the value was parsed from the entire token; false if the C
        library offers no such functions (see JSON_HAS_C_LOCALE_STRTOD) or the
        locale could not be created, in which case the caller falls back to
        parse_float_locale_aware()
*/
template<typename FloatType>
bool parse_float_c_locale(const char* first, const char* last, FloatType& out) noexcept
{
#if JSON_HAS_C_LOCALE_STRTOD
    const c_locale_t loc = c_numeric_locale();
    if (JSON_HEDLEY_UNLIKELY(loc == nullptr))
    {
        return false;
    }
    char* endptr = nullptr; // NOLINT(misc-const-correctness)
    strtof_c_locale(out, first, &endptr, loc);
    return endptr == last;
#else
    static_cast<void>(first);
    static_cast<void>(last);
    static_cast<void>(out);
    return false;
#endif
}

JSON_HEDLEY_NON_NULL(2)
inline void strtof_global_locale(float& f, const char* str, char** endptr) noexcept
{
    f = std::strtof(str, endptr);
}

JSON_HEDLEY_NON_NULL(2)
inline void strtof_global_locale(double& f, const char* str, char** endptr) noexcept
{
    f = std::strtod(str, endptr);
}

JSON_HEDLEY_NON_NULL(2)
inline void strtof_global_locale(long double& f, const char* str, char** endptr) noexcept
{
    f = std::strtold(str, endptr);
}

/// return the decimal point of the current locale
inline std::string locale_decimal_point()
{
    const auto* loc = localeconv();
    JSON_ASSERT(loc != nullptr);
    return (loc->decimal_point == nullptr || *loc->decimal_point == '\0') ? "." : loc->decimal_point;
}

/*!
@brief parse a float with strtof/strtod/strtold in the current locale

This is the last resort for platforms without std::from_chars for @a FloatType
and without parse_float_c_locale(). These functions expect the decimal point
of the *current* locale, so the '.' in the token is replaced by it. It is
looked up right before the conversion instead of once when the lexer is
constructed: a locale change in between (by a parser callback, a SAX handler,
or another thread) must not truncate the value (#5198). A single-byte decimal
point is substituted in place and restored afterwards, because the token is
also handed to the SAX interface. A longer one (e.g., the two-byte U+066B of
fa_IR.UTF-8 or ar_EG.UTF-8) is put into a copy of the token instead.

The token has been validated before, so if the conversion stops early and the
decimal point changed in the meantime, the locale changed between the lookup
and the call, and the conversion is repeated with the new decimal point. If it
did not change, the value strtod parsed up to that point is kept.

Note that changing the locale in another thread *while* strtod runs is
undefined behavior of the C library, which this function cannot prevent.

@param[in,out] token                   the token, with '.' as decimal point
@param[in]     decimal_point_position  the position of the '.' in @a token,
                                       or std::string::npos if it has none
@param[out]    out                     the parsed value
*/
template<typename StringType, typename FloatType>
void parse_float_locale_aware(StringType& token, std::size_t decimal_point_position, FloatType& out)
{
    const bool has_dot = decimal_point_position != std::string::npos;
    std::string decimal_point = locale_decimal_point();
    for (;;)
    {
        char* endptr = nullptr; // NOLINT(misc-const-correctness)
        bool complete = false;
        if (!has_dot || decimal_point.size() == 1)
        {
            const bool substitute = has_dot && decimal_point[0] != '.';
            if (substitute)
            {
                token[decimal_point_position] = static_cast<typename StringType::value_type>(decimal_point[0]);
            }
            strtof_global_locale(out, token.data(), &endptr);
            if (substitute)
            {
                token[decimal_point_position] = '.';
            }
            complete = endptr == token.data() + token.size();
        }
        else
        {
            std::string copy(token.data(), token.size());
            copy.replace(decimal_point_position, 1, decimal_point);
            strtof_global_locale(out, copy.c_str(), &endptr);
            complete = endptr == copy.c_str() + copy.size();
        }

        if (JSON_HEDLEY_LIKELY(complete))
        {
            return;
        }

        // retry only if the locale changed; otherwise, this would loop forever
        std::string current_decimal_point = locale_decimal_point();
        if (current_decimal_point == decimal_point)
        {
            return;
        }
        decimal_point = std::move(current_decimal_point);
    }
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
