//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-conversions2.cpp (conversions of
// std::filesystem::path, std::u8string and std::optional). It is kept in a separate
// translation unit so the (much larger) unit-conversions2.cpp is built for C++11 only and
// not rebuilt for every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

// workaround for MSVC, which does not set __cplusplus to the language version (#464)
#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_HAS_CXX17) && _HAS_CXX17 == 1) // fix for issue #464
    #define JSON_HAS_CPP_17
#endif

// NLOHMANN_JSON_SERIALIZE_ENUM uses a static std::pair
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

#ifdef JSON_HAS_CPP_17
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#if __has_include(<optional>)
    #include <optional>
#elif __has_include(<experimental/optional>)
    #include <experimental/optional>
#endif

#if JSON_HAS_FILESYSTEM || JSON_HAS_EXPERIMENTAL_FILESYSTEM
TEST_CASE("std::filesystem::path")
{
    SECTION("ascii")
    {
        json const j_string = "Path";
        auto p = j_string.template get<nlohmann::detail::std_fs::path>();
        json const j_path = p;

        CHECK(j_path.template get<std::string>() ==
              j_string.template get<std::string>());
    }

    SECTION("utf-8")
    {
        json const j_string = "P\xc4\x9b\xc5\xa1ina";
        auto p = j_string.template get<nlohmann::detail::std_fs::path>();
        json const j_path = p;

        CHECK(j_path.template get<std::string>() ==
              j_string.template get<std::string>());
    }
}

#endif

// the ADL to_json overload for std::u8string only exists under the same guard
// as std::filesystem::path support (it is otherwise only reached indirectly,
// via std::filesystem::path::u8string()) -- mirror both #if conditions from
// include/nlohmann/detail/conversions/to_json.hpp exactly
#if JSON_HAS_FILESYSTEM || JSON_HAS_EXPERIMENTAL_FILESYSTEM
#if defined(__cpp_lib_char8_t)
TEST_CASE("std::u8string")
{
    SECTION("ascii")
    {
        const std::u8string s = u8"Path";
        json const j = s;

        CHECK(j.template get<std::string>() == "Path");
    }

    SECTION("utf-8")
    {
        // use \u universal-character-names (rather than raw \x byte escapes
        // or literal non-ASCII source bytes) to compose the multi-byte UTF-8
        // encoding -- MSVC treats \x escapes used that way inside a u8
        // literal as a nonstandard extension (warning C5321), which some of
        // our CI configs promote to an error; \u is portable and produces
        // the exact same encoded bytes without depending on the source
        // file's encoding
        const std::u8string s = u8"P\u011B\u0161ina";
        json const j = s;

        CHECK(j.template get<std::string>() == "P\xc4\x9b\xc5\xa1ina");
    }
}

#endif
#endif

#if !defined(JSON_NOEXCEPTION)
namespace
{
// a type whose to_json reports an error by throwing, used below to check that
// converting a std::optional<T> to JSON propagates an exception thrown while
// converting its contained value instead of calling std::terminate (#5642)
struct throwing_to_json_type {};

[[noreturn]] void to_json(json& /*unused*/, const throwing_to_json_type& /*unused*/)
{
    throw std::runtime_error("cannot serialize throwing_to_json_type");
}
}  // namespace
#endif

TEST_CASE("std::optional")
{
    SECTION("null")
    {
        const json j_null;
        const std::optional<std::string> opt_null;

        CHECK(json(opt_null) == j_null);
        CHECK(j_null.get<std::optional<std::string>>() == std::nullopt);

        // Constructing std::optional<T> directly from JSON null throws because
        // std::optional's own converting constructor is chosen over basic_json's
        // operator T(). This is a language-level limitation (std::optional<T> is
        // constructible from T, and T is constructible from basic_json via the
        // operator); there is no SFINAE path that distinguishes "call from inside
        // std::optional's constructor" from "direct call". Use get<std::optional<T>>()
        // or get_to() instead for correct null handling. See #4864 and #5246.
        CHECK_THROWS_WITH_AS(std::optional<std::string>(j_null),
                             "[json.exception.type_error.302] type must be string, but is null", json::type_error&);
        CHECK_THROWS_WITH_AS(std::optional<int>(j_null),
                             "[json.exception.type_error.302] type must be number, but is null", json::type_error&);

        // Assignment goes through the same overload resolution as direct
        // construction, so it throws for the same reason. This relies on
        // basic_json's implicit conversion operator, so it only applies
        // when JSON_USE_IMPLICIT_CONVERSIONS is enabled (the default).
#if JSON_USE_IMPLICIT_CONVERSIONS
        std::optional<std::string> opt_assign;
        CHECK_THROWS_WITH_AS(opt_assign = j_null,
                             "[json.exception.type_error.302] type must be string, but is null", json::type_error&);
#endif

        // get_to() is the correct way to obtain std::nullopt from a JSON null.
        std::optional<std::string> opt_get_to = "placeholder";
        j_null.get_to(opt_get_to);
        CHECK(opt_get_to == std::nullopt);
    }

    SECTION("string")
    {
        json j_string = "string";
        std::optional<std::string> opt_string = "string";

        CHECK(json(opt_string) == j_string);
        CHECK(std::optional<std::string>(j_string) == opt_string);
        // false positive: Infer attributes the destruction of the temporaries above to opt_string
        // @infer-ignore USE_AFTER_DELETE
    }

    SECTION("bool")
    {
        json j_bool = true;
        std::optional<bool> opt_bool = true;

        CHECK(json(opt_bool) == j_bool);
        CHECK(std::optional<bool>(j_bool) == opt_bool);
    }

    SECTION("number")
    {
        json j_number = 1;
        std::optional<int> opt_int = 1;

        CHECK(json(opt_int) == j_number);
        CHECK(j_number.get<std::optional<int>>() == opt_int);
    }

    SECTION("array")
    {
        json j_array = {1, 2, nullptr};
        std::vector<std::optional<int>> opt_array = {{1, 2, std::nullopt}};

        CHECK(json(opt_array) == j_array);
        CHECK(j_array.get<std::vector<std::optional<int>>>() == opt_array);
    }

    SECTION("object")
    {
        json j_object = {{"one", 1}, {"two", 2}, {"zero", nullptr}};
        std::map<std::string, std::optional<int>> opt_object {{"one", 1}, {"two", 2}, {"zero", std::nullopt}};

        CHECK(json(opt_object) == j_object);
        CHECK(std::map<std::string, std::optional<int>>(j_object) == opt_object);
    }

#if !defined(JSON_NOEXCEPTION)
    SECTION("exception from contained value's to_json propagates (#5642)")
    {
        // to_json(BasicJsonType&, const std::optional<T>&) must not be
        // noexcept: it calls T's to_json, which may throw (a user-defined
        // to_json that reports an error, or std::bad_alloc for T =
        // std::string/vector/json). Before the fix, this called
        // std::terminate() instead of letting the exception propagate.
        const std::optional<throwing_to_json_type> opt = throwing_to_json_type{};
        CHECK_THROWS_WITH_AS(json(opt), "cannot serialize throwing_to_json_type", std::runtime_error&);

        // the conversion is noexcept exactly when converting the contained value is
        // (except with MSVC 2017, where it is never noexcept, see to_json.hpp)
#if !defined(_MSC_VER) || defined(__clang__) || _MSC_VER >= 1920
        static_assert(!std::is_nothrow_constructible<json, const std::optional<throwing_to_json_type>&>::value);
        static_assert(std::is_nothrow_constructible<json, const std::optional<int>&>::value);
#endif
    }
#endif
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
#endif
