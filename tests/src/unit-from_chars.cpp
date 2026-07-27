//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <limits>
#include <string>
#include <system_error>

// nlohmann::details::from_chars is a wrapper around std::from_chars when it is
// available (__cpp_lib_to_chars is defined), otherwise our fallback
// implementation kicks in.
//
// Due to the incomplete implementation of this C++17 standard library feature
// (for example, lack of support for long double even in current libc++),
// JSON_HAS_CPP_17 does not guarantee that std::from_chars is available.
// However, the reverse holds: If the test is compiled in C++11 mode, the
// fallback implementation will be used for sure.
// By mentioning the JSON_HAS_CPP_17 macro in this here comment, the test will
// be compiled both using our fallback and, at least on some platforms,
// the C++17 standard library version, as a way of ensuring that the
// expectations formulated in this test align with `std::from_chars`.

namespace
{
struct init_val_t {};
constexpr init_val_t init_val{};

template <typename T>
void check_result(std::string& str, T& value, std::ptrdiff_t expected_ptr_offset, std::errc expected_ec)
{
    // On platforms where neither `std::from_chars`, nor extended locale support (`strtof_l`) are
    // available, the `strtof`-based implementation is in fact locale-dependent and might use a
    // different decimal separator, so we need to adapt the test expectations accordingly.
    std::replace(str.begin(), str.end(), '.', nlohmann::detail::from_chars_traits<T>::get_decimal_point());

    auto res = nlohmann::detail::from_chars(str.data(), str.data() + str.size(), value);
    CHECK_MESSAGE(res.ec == expected_ec, "Error code mismatch while parsing: \"", str,
                  "\": Actual: ", make_error_code(res.ec).message(),
                  "; expected: ", make_error_code(expected_ec).message());
    CHECK_MESSAGE(res.ptr - str.data() == expected_ptr_offset, "Ptr offset mismatch while parsing: \"", str, "\"");
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, void>::type
check(std::string str, T expected_value, std::ptrdiff_t expected_ptr_offset, std::errc expected_ec)
{
    T value = 42;
    check_result(str, value, expected_ptr_offset, expected_ec);
    CHECK_MESSAGE(value == expected_value, "while parsing: \"", str, "\"");
}

template <typename T>
typename std::enable_if<std::is_floating_point<T>::value, void>::type
check(std::string str, T expected_value, std::ptrdiff_t expected_ptr_offset, std::errc expected_ec)
{
    {
        T value = 42;
        check_result(str, value, expected_ptr_offset, expected_ec);
        CHECK_MESSAGE(value == expected_value, "while parsing: \"", str, "\"");
        CHECK_MESSAGE(std::signbit(value) == std::signbit(expected_value), "while parsing: \"", str, "\"");
    }
    {
        T value = std::numeric_limits<T>::quiet_NaN();
        check_result(str, value, expected_ptr_offset, expected_ec);
        CHECK_MESSAGE(value == expected_value, "while parsing: \"", str, "\"");
    }
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, void>::type
check(std::string str, init_val_t /*unused*/, std::ptrdiff_t expected_ptr_offset, std::errc expected_ec)
{
    T const init_value = 42;
    T value = init_value;
    check_result(str, value, expected_ptr_offset, expected_ec);
    CHECK_MESSAGE(value == init_value, "while parsing: \"", str, "\"");
}

template <typename T>
typename std::enable_if<std::is_floating_point<T>::value, void>::type
check(std::string str, init_val_t /*unused*/, std::ptrdiff_t expected_ptr_offset, std::errc expected_ec)
{
    {
        T const init_value = 42;
        T value = init_value;
        check_result(str, value, expected_ptr_offset, expected_ec);
        CHECK_MESSAGE(value == init_value, "while parsing: \"", str, "\"");
    }
    {
        T value = std::numeric_limits<T>::quiet_NaN();
        check_result(str, value, expected_ptr_offset, expected_ec);
        CHECK_MESSAGE(doctest::IsNaN<T>(value), "while parsing: \"", str, "\"");
    }
}

}  // namespace

TEST_CASE("integral results consistent with std::from_chars")
{
    SECTION("unsigned long long")
    {
        check<unsigned long long>("", init_val, 0, std::errc::invalid_argument);
        check<unsigned long long>("0", 0ULL, 1, std::errc{});
        check<unsigned long long>(" 123", init_val, 0, std::errc::invalid_argument);
        check<unsigned long long>("123 ", 123ULL, 3, std::errc{});
        check<unsigned long long>("+123", init_val, 0, std::errc::invalid_argument);
        check<unsigned long long>("-123", init_val, 0, std::errc::invalid_argument);
        check<unsigned long long>("123", 123ULL, 3, std::errc{});
        check<unsigned long long>("123e10", 123ULL, 3, std::errc{});
        check<unsigned long long>("18446744073709551615", 18446744073709551615ULL, 20, std::errc{});
        check<unsigned long long>("18446744073709551616", init_val, 20, std::errc::result_out_of_range);
    }

    SECTION("long long")
    {
        check<long long>("", init_val, 0, std::errc::invalid_argument);
        check<long long>("0", 0LL, 1, std::errc{});
        check<long long>(" 123", init_val, 0, std::errc::invalid_argument);
        check<long long>("123 ", 123LL, 3, std::errc{});
        check<long long>("+123", init_val, 0, std::errc::invalid_argument);
        check<long long>("-123", -123LL, 4, std::errc{});
        check<long long>("123", 123LL, 3, std::errc{});
        check<long long>("123e10", 123LL, 3, std::errc{});
        check<long long>("9223372036854775807", 9223372036854775807LL, 19, std::errc{});
        check<long long>("9223372036854775808", init_val, 19, std::errc::result_out_of_range);
        check<long long>("-9223372036854775808", -9223372036854775807LL - 1, 20, std::errc{});
        check<long long>("-9223372036854775809", init_val, 20, std::errc::result_out_of_range);
    }
}

TEST_CASE("floating point results consistent with std::from_chars")
{
    INFO("Using decimal point '",
         std::string{1, nlohmann::detail::from_chars_traits<float>::get_decimal_point()},
         "' to match our possibly-locale-dependent from_chars fallback implementation");

    SECTION("single precision")
    {
        check<float>("", init_val, 0, std::errc::invalid_argument);
        check<float>(" 123", init_val, 0, std::errc::invalid_argument);
        check<float>("123 ", 123.0f, 3, std::errc{});
        check<float>("+123", init_val, 0, std::errc::invalid_argument);
        check<float>("-123", -123.0f, 4, std::errc{});
        check<float>("123", 123.0f, 3, std::errc{});
        check<float>("123e10", 123e10f, 6, std::errc{});
        check<float>("123e+10", 123e10f, 7, std::errc{});
        check<float>("123e-10", 123e-10f, 7, std::errc{});
        check<float>("123.456", 123.456f, 7, std::errc{});
        check<float>("123;456", 123.0f, 3, std::errc{});
        check<float>("123.456 ", 123.456f, 7, std::errc{});
        check<float>("123;456 ", 123.0f, 3, std::errc{});
        check<float>("123456789.123456789", 123456789.123456789f, 19, std::errc{});
        check<float>("1e40", std::numeric_limits<float>::infinity(), 4, std::errc::result_out_of_range);
        check<float>("-1e40", -std::numeric_limits<float>::infinity(), 5, std::errc::result_out_of_range);
        check<float>("2e308", std::numeric_limits<float>::infinity(), 5, std::errc::result_out_of_range);
        check<float>("-2e308", -std::numeric_limits<float>::infinity(), 6, std::errc::result_out_of_range);
        check<float>("123.456e-789", 0.0f, 12, std::errc::result_out_of_range);
        check<float>("-123.456e-789", -0.0f, 13, std::errc::result_out_of_range);
        check<float>("1e-45", 1e-45f, 5, std::errc{});
        check<float>("1e-46", 0.0f, 5, std::errc::result_out_of_range);
        check<float>("1E-45", 1e-45f, 5, std::errc{});
        check<float>("1E-46", 0.0f, 5, std::errc::result_out_of_range);
        check<float>("10e-46", 1e-45f, 6, std::errc{});
        check<float>("0.1e-45", 0.0f, 7, std::errc::result_out_of_range);
        check<float>("100000000000000000000000000000000000000", 1e38f, 39, std::errc{});
        check<float>("100000000000000000000000000000000000000.0", 1e38f, 41, std::errc{});
        check<float>("1000000000000000000000000000000000000000e-1", 1e38f, 43, std::errc{});
        check<float>("0.0000000000000000000000000000000000000000000001e84", 1e38f, 51, std::errc{});
        check<float>("0.000000000000000000000000000000000000000000001", 1e-45f, 47, std::errc{});
        check<float>("00.000000000000000000000000000000000000000000001", 1e-45f, 48, std::errc{});
        check<float>("0.0000000000000000000000000000000000000000000001e1", 1e-45f, 50, std::errc{});
        check<float>("1000000000000000000000000000000000000000e-84", 1e-45f, 44, std::errc{});
        check<float>("1000000000000000000000000000000000000000", std::numeric_limits<float>::infinity(), 40, std::errc::result_out_of_range);
        check<float>("1000000000000000000000000000000000000000.0", std::numeric_limits<float>::infinity(), 42, std::errc::result_out_of_range);
        check<float>("100000000000000000000000000000000000000e1", std::numeric_limits<float>::infinity(), 41, std::errc::result_out_of_range);
        check<float>("0.0000000000000000000000000000000000000000000001e85", std::numeric_limits<float>::infinity(), 51, std::errc::result_out_of_range);
        check<float>("1000000000000000000000000000000000000000e-85", 0.0f, 44, std::errc::result_out_of_range);
        check<float>("0.0000000000000000000000000000000000000000000001", 0.0f, 48, std::errc::result_out_of_range);
        check<float>("0.000000000000000000000000000000000000000000001e-1", 0.0f, 50, std::errc::result_out_of_range);
        check<float>("1e-99999999999999999999", 0.0f, 23, std::errc::result_out_of_range);
        check<float>("1e+99999999999999999999", std::numeric_limits<float>::infinity(), 23, std::errc::result_out_of_range);
        check<float>("-1e-99999999999999999999", -0.0f, 24, std::errc::result_out_of_range);
        check<float>("-1e+99999999999999999999", -std::numeric_limits<float>::infinity(), 24, std::errc::result_out_of_range);
    }

    SECTION("double precision")
    {
        check<double>("", init_val, 0, std::errc::invalid_argument);
        check<double>(" 123", init_val, 0, std::errc::invalid_argument);
        check<double>("123 ", 123.0, 3, std::errc{});
        check<double>("+123", init_val, 0, std::errc::invalid_argument);
        check<double>("-123", -123.0, 4, std::errc{});
        check<double>("123", 123.0, 3, std::errc{});
        check<double>("123e10", 123e10, 6, std::errc{});
        check<double>("123e+10", 123e10, 7, std::errc{});
        check<double>("123e-10", 123e-10, 7, std::errc{});
        check<double>("123.456", 123.456, 7, std::errc{});
        check<double>("123;456", 123.0, 3, std::errc{});
        check<double>("123.456 ", 123.456, 7, std::errc{});
        check<double>("123;456 ", 123.0, 3, std::errc{});
        check<double>("123456789.123456789", 123456789.123456789, 19, std::errc{});
        check<double>("1e40", 1e40, 4, std::errc{});
        check<double>("-1e40", -1e40, 5, std::errc{});
        check<double>("2e308", std::numeric_limits<double>::infinity(), 5, std::errc::result_out_of_range);
        check<double>("-2e308", -std::numeric_limits<double>::infinity(), 6, std::errc::result_out_of_range);
        check<double>("2e-324", 0.0, 6, std::errc::result_out_of_range);
        check<double>("-2e-324", -0.0, 7, std::errc::result_out_of_range);
        check<double>("123.456e-789", 0.0, 12, std::errc::result_out_of_range);
        check<double>("-123.456e-789", -0.0, 13, std::errc::result_out_of_range);
        check<double>("1e-99999999999999999999", 0.0, 23, std::errc::result_out_of_range);
        check<double>("1e+99999999999999999999", std::numeric_limits<double>::infinity(), 23, std::errc::result_out_of_range);
        check<double>("-1e-99999999999999999999", -0.0, 24, std::errc::result_out_of_range);
        check<double>("-1e+99999999999999999999", -std::numeric_limits<double>::infinity(), 24, std::errc::result_out_of_range);
    }

    SECTION("long double precision")
    {
        check<long double>("", init_val, 0, std::errc::invalid_argument);
        check<long double>(" 123", init_val, 0, std::errc::invalid_argument);
        check<long double>("123 ", 123.0L, 3, std::errc{});
        check<long double>("+123", init_val, 0, std::errc::invalid_argument);
        check<long double>("-123", -123.0L, 4, std::errc{});
        check<long double>("123", 123.0L, 3, std::errc{});
        check<long double>("123e10", 123e10L, 6, std::errc{});
        check<long double>("123e+10", 123e10L, 7, std::errc{});
        check<long double>("123e-10", 123e-10L, 7, std::errc{});
        check<long double>("123.456", 123.456L, 7, std::errc{});
        check<long double>("123;456", 123.0L, 3, std::errc{});
        check<long double>("123.456 ", 123.456L, 7, std::errc{});
        check<long double>("123;456 ", 123.0L, 3, std::errc{});
        check<long double>("123456789.123456789", 123456789.123456789L, 19, std::errc{});
        check<long double>("1e40", 1e40L, 4, std::errc{});
        check<long double>("-1e40", -1e40L, 5, std::errc{});
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4127)
#endif
        if (sizeof(long double) > 8)
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
        {
            // Right-hand-side is calculated to avoid warning about literal
            // exceeding range on platforms where this branch is NOT taken.
            check<long double>("2e308", 1e308L * 2, 5, std::errc{});
            check<long double>("-2e308", -1e308L * 2, 6, std::errc{});
            check<long double>("2e-324", 8e-324L / 4, 6, std::errc{});
            check<long double>("-2e-324", -8e-324L / 4, 7, std::errc{});
        }
        else
        {
            check<long double>("2e308", std::numeric_limits<long double>::infinity(), 5, std::errc::result_out_of_range);
            check<long double>("-2e308", -std::numeric_limits<long double>::infinity(), 6, std::errc::result_out_of_range);
            check<long double>("2e-324", 0.0L, 6, std::errc::result_out_of_range);
            check<long double>("-2e-324", -0.0L, 7, std::errc::result_out_of_range);
        }
        check<long double>("1e5000", std::numeric_limits<long double>::infinity(), 6, std::errc::result_out_of_range);
        check<long double>("-1e5000", -std::numeric_limits<long double>::infinity(), 7, std::errc::result_out_of_range);
        check<long double>("123.456e-7890", 0.0L, 13, std::errc::result_out_of_range);
        check<long double>("-123.456e-7890", -0.0L, 14, std::errc::result_out_of_range);
        check<long double>("1e-99999999999999999999", 0.0L, 23, std::errc::result_out_of_range);
        check<long double>("1e+99999999999999999999", std::numeric_limits<long double>::infinity(), 23, std::errc::result_out_of_range);
        check<long double>("-1e-99999999999999999999", -0.0L, 24, std::errc::result_out_of_range);
        check<long double>("-1e+99999999999999999999", -std::numeric_limits<long double>::infinity(), 24, std::errc::result_out_of_range);
    }
}

