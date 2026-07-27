//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <nlohmann/detail/macro_scope.hpp>

#if JSON_HAS_FROM_CHARS
    #include <algorithm> // find, find_if
    #include <charconv> // from_chars, from_chars_result
    #include <cmath> // isnan
#else
    #include <cctype> // isspace
    #include <cerrno> // ERANGE
    #include <clocale> // localeconv, newlocale, freelocale
    #include <cstdlib> // strto*
    #include <memory> // unique_ptr
    #include <type_traits> // enable_if, is_unsigned, remove_pointer
    #include <utility> // declval

    #ifdef __has_include
        #if __has_include(<xlocale.h>)
            #include <xlocale.h> // strto*_l, isspace_l
        #endif
    #endif
#endif
#include <limits> // numeric_limits<T>::[has_]infinity, quiet_NaN
#include <system_error> // errc

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

constexpr char get_locale_independent_decimal_point() noexcept
{
    return '.';
}

#if JSON_HAS_FROM_CHARS

//////////////////////////////////////////////
// Delegate to std::from_chars if supported //
//////////////////////////////////////////////

/*!
@brief Number parsing implementation details

A traits class template that allows users of nlohmann::detail::from_chars to
query details of the used implementation.

@tparam T numeric type to parse, matching the `value` argument of from_chars
*/
template <typename T>
struct from_chars_traits
{
    /// whether the from_chars in unaffected by the current global C locale
    static constexpr bool is_locale_independent = true;

    /// getter for the character used as decimal point by from_chars
    static constexpr char(*get_decimal_point)() = &get_locale_independent_decimal_point;
};

using std::from_chars_result;

/*!
@brief Parse integer/floating-point numbers

Parses the string [first, last) into the numeric type T.

This implementation merely delegates to `std::from_chars` with one noteworthy
difference: Different C++ standard library implementations do not agree on
whether `value` should be set in the out-of-range case for floating-point
numbers. Presently, libstdc++ leaves `value` unchanged whereas libc++ and MS STL
set `value` to +/-0 or +/-inf which allows its users to distinguish between the
various cases of over- and underflow. The C++ proposal [P4168][1] details this
discrepancy and advocates to standardize the latter behavior.

Since we need to be able to distinguish absolute underflow (+/-0) from absolute
overflow (+/-inf), this implementation "corrects" the out-of-range behavior
accordingly by estimating the effective exponent through manual string parsing.

[1]: https://isocpp.org/files/papers/P4168R0.html

@tparam T numeric type to parse
@param[in] first points to the beginning of the parsed string (inclusive)
@param[in] end points to the end of the parsed string (exclusive)
@param[out] value references the variable to set the parsed number
@return structure consisting of `ptr` and `ec` such that:
        - If the string starting at `first` matches a number, `ptr` points to
          the address immediately after the last character that matches.
          * If the matched number can be represented by `T`, `value` is set and
            `ec` is value-initialized.
          * If the matched number cannot be represented by `T`, `ec` is set to
            `std::errc::result_out_of_range` and depending on the type of `T`:
            + `value` is left unchanged for integral `T`,
            + `value` is set to +/-0 or +/-inf for floating-point `T`.
        - If the string starting at `first` doesn't match a number, `ptr`
          points to `first`, `ec` is `std::errc::invalid_argument`, and `value`
          is left unchanged.
*/
template <typename T>
JSON_HEDLEY_NON_NULL(1, 2)
inline from_chars_result from_chars(const char* first, const char* last, T& value)
{
    // No implementation of std::from_chars will set its value argument to NaN,
    // so by using NaN as the initial value, we can tell if it changed.
    T inner_value = std::numeric_limits<T>::quiet_NaN();
    auto res = std::from_chars(first, last, inner_value);

    if constexpr (std::numeric_limits<T>::has_infinity)
    {
        if (res.ec == std::errc::result_out_of_range)
        {
            if (std::isnan(inner_value)) // inner_value was not set
            {
                // [first, res.ptr) matches a valid floating-point number that's
                // out-of-range and our std::from_chars did not set `value`, so we
                // need to distinguish the type of under-/overflow ourselves.
                const char* mantissa_begin = *first == '-' ? first + 1 : first;
                const char* mantissa_end = std::find_if(mantissa_begin, res.ptr, [](char c)
                {
                    return c == 'e' || c == 'E';
                });
                const char* decimal_point = std::find(mantissa_begin, mantissa_end, '.');
                const char* significant_digit = std::find_if(mantissa_begin, mantissa_end, [](char d)
                {
                    return d >= '1' && d <= '9';
                });

                // Position of the significant digit relative to the decimal gives
                // the order of magnitude of the mantissa.
                auto effective_exponent = static_cast<int>(decimal_point - significant_digit);

                // If the number includes an explicit exponent, add that to the the
                // total exponent.
                if (mantissa_end != res.ptr)
                {
                    const char* exponent_begin = *(mantissa_end + 1) == '+'
                                                 ? mantissa_end + 2 // skip the exponent's + sign
                                                 : mantissa_end + 1;
                    int exponent = 0;
                    auto exp_res = std::from_chars(exponent_begin, res.ptr, exponent);
                    JSON_ASSERT(exp_res.ptr == res.ptr);

                    if (exp_res.ec == std::errc::result_out_of_range)
                    {
                        // NOTE: Parentheses around function names mitigate min/max macro collision on Windows
                        effective_exponent = *exponent_begin == '-'
                                             ? (std::numeric_limits<int>::min)()
                                             : (std::numeric_limits<int>::max)();
                    }
                    else
                    {
                        JSON_ASSERT(exp_res.ec == std::errc{});
                        effective_exponent += exponent;
                    }
                }

                // Set `value` to the sign-correct non-finite value based on the
                // effective exponent.
                value = (*first == '-' ? -1 : 1) * (effective_exponent < 0
                                                    ? T{}
                                                    : std::numeric_limits<T>::infinity());
            }
            else
            {
                value = inner_value;
            }
        }
    }

    if (res.ec == std::errc{})
    {
        value = inner_value;
    }

    return res;
}

#else

//////////////////////////////////////////////
// Fallback implementation using strto*[_l] //
//////////////////////////////////////////////

#if defined(_WIN32)

/*!
@brief Extended locale functions on Windows

A trait object which provides wrappers for isspace and the strto* family of
functions, based on the platform's support for extended locale APIs.

This is the Windows implementation. The primary class template definition
falls back to the standard locale-dependent functions, which is used on
MinGW, whose C runtime only provides an incomplete subset of the
`_<funcname>_l` family (e.g., missing `_strtof_l`/`_strtold_l` depending on
the toolchain version). A specialization for genuine MSVC (including
clang-cl, which mimics the MSVC ABI and CRT) is used instead, as the full
`_<funcname>_l` family has reliably been available there since at least
Visual Studio 2005.
*/
template <typename = const char*, typename = float>
struct extended_locale_traits
{
    static constexpr bool is_locale_independent = false;

    JSON_HEDLEY_PURE
    static char get_decimal_point() noexcept
    {
        const auto* loc = localeconv();
        JSON_ASSERT(loc != nullptr);
        return (loc->decimal_point == nullptr) ? '.' : *(loc->decimal_point);
    }

    static int isspace(int c) noexcept
    {
        return std::isspace(c);
    }

    // NOLINTNEXTLINE(runtime/int)
    static long long strtoll(const char* str, char** endptr) noexcept
    {
        return std::strtoll(str, endptr, 10);
    }

    // NOLINTNEXTLINE(runtime/int)
    static unsigned long long strtoull(const char* str, char** endptr) noexcept
    {
        return std::strtoull(str, endptr, 10);
    }

    static constexpr float(&strtof)(const char*, char**) = std::strtof;
    static constexpr double(&strtod)(const char*, char**) = std::strtod;
    static constexpr long double(&strtold)(const char*, char**) = std::strtold;
};

#if defined(_MSC_VER)

/*!
@brief Get a pointer to a globally shared instance of the "C" locale on Windows

This function uses _create_locale/_free_locale to allocate a "C" locale instance
which can be passed to extended locale APIs. This instance is created on first
use and has static storage duration, such that it can be used for the duration
of the program.
*/
inline _locale_t get_c_locale_t() noexcept
{
    struct LocaleTDeleter
    {
        void operator()(_locale_t loc) noexcept
        {
            ::_free_locale(loc);
        }
    };
    using LocaleUPtr = std::unique_ptr<std::remove_pointer<_locale_t>::type, LocaleTDeleter>;
    static const LocaleUPtr c_locale = LocaleUPtr{::_create_locale(LC_ALL, "C"), LocaleTDeleter{}};
    return c_locale.get();
}

template <typename T>
struct extended_locale_traits<T, float>
{
    static constexpr bool is_locale_independent = true;
    static constexpr char(&get_decimal_point)() = get_locale_independent_decimal_point;

    static int isspace(int c) noexcept
    {
        return _isspace_l(c, get_c_locale_t());
    }

    // NOLINTNEXTLINE(runtime/int)
    static long long strtoll(const char* str, char** endptr) noexcept
    {
        return _strtoll_l(str, endptr, 10, get_c_locale_t());
    }

    // NOLINTNEXTLINE(runtime/int)
    static unsigned long long strtoull(const char* str, char** endptr) noexcept
    {
        return _strtoull_l(str, endptr, 10, get_c_locale_t());
    }

    static float strtof(T str, char** str_end)
    {
        return _strtof_l(str, str_end, get_c_locale_t());
    }

    static double strtod(T str, char** str_end)
    {
        return _strtod_l(str, str_end, get_c_locale_t());
    }

    static long double strtold(T str, char** str_end)
    {
        return _strtold_l(str, str_end, get_c_locale_t());
    }
};

#endif

#else

/*!
@brief Get a pointer to a globally shared instance of the "C" locale on POSIX

This function uses newlocale/freelocale to allocate a "C" locale instance
which can be passed to extended locale APIs. This instance is created on first
use and has static storage duration, such that it can be used for the duration
of the program.

newlocale/freelocale themselves are in POSIX and are available independent of
the platform's support for extended locale APIs.
*/
inline locale_t get_c_locale_t() noexcept
{
    struct LocaleTDeleter
    {
        void operator()(locale_t loc) noexcept
        {
            ::freelocale(loc);
        }
    };
    using LocaleUPtr = std::unique_ptr<std::remove_pointer<locale_t>::type, LocaleTDeleter>;

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wexit-time-destructors"
#endif
    static const LocaleUPtr c_locale = LocaleUPtr {::newlocale(LC_ALL_MASK, "C", nullptr), LocaleTDeleter{}};
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

    return c_locale.get();
}

/*!
@brief Extended locale functions on POSIX

A trait object which provides wrappers for isspace and the strto* family of
functions, based on the platform's support for extended locale APIs.

This is the POSIX implementation where extended locale support might not be
available. The primary class template definition falls back to the standard
locale-dependent functions. A partial specialization uses SFINAE to detect the
availability of `strtof_l` (as a proxy for the whole `<funcname>_l` family) and
provides access to locale-independent functions.
*/
template <typename = const char*, typename = float>
struct extended_locale_traits
{
    static constexpr bool is_locale_independent = false;

    /*!
    @brief Query the decimal point used by the current C locale

    Note that calling this function while switching the global C locale from
    another thread is undefined behavior.
    */
    JSON_HEDLEY_PURE
    static char get_decimal_point() noexcept
    {
        const auto* loc = localeconv();
        JSON_ASSERT(loc != nullptr);
        return (loc->decimal_point == nullptr) ? '.' : *(loc->decimal_point);
    }

    static int isspace(int c) noexcept
    {
        return std::isspace(c);
    }

    // NOLINTNEXTLINE(runtime/int)
    static long long strtoll(const char* str, char** endptr) noexcept
    {
        return std::strtoll(str, endptr, 10);
    }

    // NOLINTNEXTLINE(runtime/int)
    static unsigned long long strtoull(const char* str, char** endptr) noexcept
    {
        return std::strtoull(str, endptr, 10);
    }

    static constexpr float(&strtof)(const char*, char**) = std::strtof;
    static constexpr double(&strtod)(const char*, char**) = std::strtod;
    static constexpr long double(&strtold)(const char*, char**) = std::strtold;
};

template <typename T>
struct extended_locale_traits<T, decltype(strtof_l(
            std::declval<T>(),
            std::declval<char**>(),
            std::declval<locale_t>()))>
{
    static constexpr bool is_locale_independent = true;
    static constexpr char(&get_decimal_point)() = get_locale_independent_decimal_point;

    static int isspace(int c) noexcept
    {
        return isspace_l(c, get_c_locale_t());
    }

    // NOLINTNEXTLINE(runtime/int)
    static long long strtoll(const char* str, char** endptr) noexcept
    {
        return ::strtoll_l(str, endptr, 10, get_c_locale_t());
    }

    // NOLINTNEXTLINE(runtime/int)
    static unsigned long long strtoull(const char* str, char** endptr) noexcept
    {
        return ::strtoull_l(str, endptr, 10, get_c_locale_t());
    }

    static float strtof(T str, char** str_end)
    {
        return ::strtof_l(str, str_end, get_c_locale_t());
    }

    static double strtod(T str, char** str_end)
    {
        return ::strtod_l(str, str_end, get_c_locale_t());
    }

    static long double strtold(T str, char** str_end)
    {
        return ::strtold_l(str, str_end, get_c_locale_t());
    }
};

#endif

/*!
@brief Number parsing implementation details

A traits class template that allows users of nlohmann::detail::from_chars to
query details of the used implementation.

Each specialization provides the following static members:
- is_locale_independent: whether the from_chars in unaffected by the current
                         global C locale
- get_decimal_point: getter for the character used as decimal point by from_chars
- strto: dispatches to the C standard library strto* function for type T, or to
         the corresponding extended locale function, if available.

@tparam T numeric type to parse, matching the `value` argument of from_chars
*/
template <typename T>
struct from_chars_traits;

template <>
struct from_chars_traits<long long> // NOLINT(runtime/int)
{
    static constexpr bool is_locale_independent = extended_locale_traits<>::is_locale_independent;

    static char get_decimal_point()
    {
        return extended_locale_traits<>::get_decimal_point();
    }

    // NOLINTNEXTLINE(runtime/int)
    static constexpr long long(*strto)(const char*, char**) = &extended_locale_traits<>::strtoll;
};

template <>
struct from_chars_traits<unsigned long long> // NOLINT(runtime/int)
{
    static constexpr bool is_locale_independent = extended_locale_traits<>::is_locale_independent;

    static char get_decimal_point()
    {
        return extended_locale_traits<>::get_decimal_point();
    }

    // NOLINTNEXTLINE(runtime/int)
    static constexpr unsigned long long(*strto)(const char*, char**) = &extended_locale_traits<>::strtoull;
};

template <>
struct from_chars_traits<float>
{
    static constexpr bool is_locale_independent = extended_locale_traits<>::is_locale_independent;

    static char get_decimal_point()
    {
        return extended_locale_traits<>::get_decimal_point();
    }

    static constexpr float(*strto)(const char*, char**) = &extended_locale_traits<>::strtof;
};

template <>
struct from_chars_traits<double>
{
    static constexpr bool is_locale_independent = extended_locale_traits<>::is_locale_independent;

    static char get_decimal_point()
    {
        return extended_locale_traits<>::get_decimal_point();
    }

    static constexpr double(*strto)(const char*, char**) = &extended_locale_traits<>::strtod;
};

template <>
struct from_chars_traits<long double>
{
    static constexpr bool is_locale_independent = extended_locale_traits<>::is_locale_independent;

    static char get_decimal_point()
    {
        return extended_locale_traits<>::get_decimal_point();
    }

    static constexpr long double(*strto)(const char*, char**) = &extended_locale_traits<>::strtold;
};

template <typename T>
constexpr typename std::enable_if<std::numeric_limits<T>::has_infinity, bool>::type is_out_of_range_value(T value) noexcept
{
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
#endif
    return value == T {} || value == std::numeric_limits<T>::infinity() || value == -std::numeric_limits<T>::infinity();
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
}

template <typename T>
constexpr typename std::enable_if < !std::numeric_limits<T>::has_infinity, bool >::type is_out_of_range_value(T value) noexcept
{
    // NOTE: Parentheses around function names mitigate min/max macro collision on Windows
    return value == (std::numeric_limits<T>::max)() || value == (std::numeric_limits<T>::min)();
}

struct from_chars_result
{
    const char* ptr;
    std::errc ec;
};

/*!
@brief Parse integer/floating-point numbers

Parses the string [first, last) into the numeric type T.

This implementation uses the C standard library functions strto*, or their
extended locale counterparts strto*_l, to emulate the behavior of
`std::from_chars` on platforms where it is not (fully) supported.

Regarding the under-/overflow behavior, this implementation adopts the behavior
proposed by [P4168][1] and implemented by libc++ and MS STL of setting `value`
to the corresponding non-finite floating-point value in case of an out-of-range
result.

[1]: https://isocpp.org/files/papers/P4168R0.html

@pre Unlike std::from_chars, this implementation requires the string to be
     null-terminated, such that `last` dereferences into a NUL byte.

@tparam T numeric type to parse
@param[in] first points to the beginning of the parsed string (inclusive)
@param[in] end points to the end of the parsed string (exclusive)
@param[out] value references the variable to set the parsed number
@return structure consisting of `ptr` and `ec` such that:
        - If the string starting at `first` matches a number, `ptr` points to
          the address immediately after the last character that matches.
          * If the matched number can be represented by `T`, `value` is set and
            `ec` is value-initialized.
          * If the matched number cannot be represented by `T`, `ec` is set to
            `std::errc::result_out_of_range` and depending on the type of `T`:
            + `value` is left unchanged for integral `T`,
            + `value` is set to +/-0 or +/-inf for floating-point `T`.
        - If the string starting at `first` doesn't match a number, `ptr`
          points to `first`, `ec` is `std::errc::invalid_argument`, and `value`
          is left unchanged.
*/
template <typename T>
JSON_HEDLEY_NON_NULL(1, 2)
inline from_chars_result from_chars(const char* first, const char* last, T& value)
{
    JSON_ASSERT(*last == '\0');

    // Unlike strto*, from_chars does not accept leading whitespace or + signs
    if (first == last || *first == '+'
            || (std::is_unsigned<T>::value && *first == '-')
            || extended_locale_traits<>::isspace(*first) != 0)
    {
        return {first, std::errc::invalid_argument};
    }

    errno = 0;
    char* ptr = nullptr; // NOLINT(misc-const-correctness)
    T result = from_chars_traits<T>::strto(first, &ptr);

    if (ptr == first)
    {
        return {ptr, std::errc::invalid_argument};
    }

    // Upon under-/overflow, strto* returns a marginal value and sets errno.
    // Note that it is NOT sufficient to just check errno: strto* only clears
    // errno if the parsed string actually parses into 0/[U]LLONG_MIN/-_MAX
    // and this result was returned without indicating an under-/overflow.
    // Otherwise, errno may not be relied upon to indicate the *absence* of
    // an out-of-range error.
    if (is_out_of_range_value(result) && errno == ERANGE)
    {
        if (std::numeric_limits<T>::has_infinity)
        {
            // ONLY for floating-point types, set `value` to the same non-finite
            // result returned by strto* to allow users to distinguish between
            // different types of under-/overflow.
            value = result;
        }
        return {ptr, std::errc::result_out_of_range};
    }

    value = result;
    return {ptr, std::errc{}};
}

#endif

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
