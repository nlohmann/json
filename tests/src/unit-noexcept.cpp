//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// disable -Wnoexcept due to struct pod_bis
DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Wnoexcept")

// skip tests if JSON_DisableEnumSerialization=ON (#4384)
#if defined(JSON_DISABLE_ENUM_SERIALIZATION) && (JSON_DISABLE_ENUM_SERIALIZATION == 1)
    #define SKIP_TESTS_FOR_ENUM_SERIALIZATION
#endif

#include <nlohmann/json.hpp>

using nlohmann::json;

namespace
{
enum test {}; // NOLINT(cppcoreguidelines-use-enum-class)

struct pod {};
struct pod_bis {};

void to_json(json& /*unused*/, pod /*unused*/) noexcept;
void to_json(json& /*unused*/, pod_bis /*unused*/);
void from_json(const json& /*unused*/, pod /*unused*/) noexcept;
void from_json(const json& /*unused*/, pod_bis /*unused*/);
void to_json(json& /*unused*/, pod /*unused*/) noexcept {}
void to_json(json& /*unused*/, pod_bis /*unused*/) {}
void from_json(const json& /*unused*/, pod /*unused*/) noexcept {}
void from_json(const json& /*unused*/, pod_bis /*unused*/) {}

static_assert(noexcept(json{}), "");
static_assert(noexcept(nlohmann::to_json(std::declval<json&>(), 2)), "");
static_assert(noexcept(nlohmann::to_json(std::declval<json&>(), 2.5)), "");
static_assert(noexcept(nlohmann::to_json(std::declval<json&>(), true)), "");
#ifndef SKIP_TESTS_FOR_ENUM_SERIALIZATION
static_assert(noexcept(nlohmann::to_json(std::declval<json&>(), test {})), "");
#endif
static_assert(noexcept(nlohmann::to_json(std::declval<json&>(), pod {})), "");
static_assert(!noexcept(nlohmann::to_json(std::declval<json&>(), pod_bis{})), "");
static_assert(noexcept(json(2)), "");
#ifndef SKIP_TESTS_FOR_ENUM_SERIALIZATION
static_assert(noexcept(json(test {})), "");
#endif
static_assert(noexcept(json(pod {})), "");
static_assert(noexcept(std::declval<json>().get<pod>()), "");
static_assert(!noexcept(std::declval<json>().get<pod_bis>()), "");
static_assert(noexcept(json(pod{})), "");
} // namespace

TEST_CASE("noexcept")
{
    // silence -Wunneeded-internal-declaration errors
    static_cast<void>(static_cast<void(*)(json&, pod)>(&to_json));
    static_cast<void>(static_cast<void(*)(json&, pod_bis)>(&to_json));
    static_cast<void>(static_cast<void(*)(const json&, pod)>(&from_json));
    static_cast<void>(static_cast<void(*)(const json&, pod_bis)>(&from_json));

    SECTION("nothrow-copy-constructible exceptions")
    {
        // for ERR60-CPP (https://github.com/nlohmann/json/issues/531):
        // Exceptions should be nothrow-copy-constructible. However, compilers
        // treat std::runtime_exception differently in this regard. Therefore,
        // we can only demand nothrow-copy-constructibility for our exceptions
        // if std::runtime_exception is.
        CHECK(std::is_nothrow_copy_constructible<json::exception>::value == std::is_nothrow_copy_constructible<std::runtime_error>::value);
        CHECK(std::is_nothrow_copy_constructible<json::parse_error>::value == std::is_nothrow_copy_constructible<std::runtime_error>::value);
        CHECK(std::is_nothrow_copy_constructible<json::invalid_iterator>::value == std::is_nothrow_copy_constructible<std::runtime_error>::value);
        CHECK(std::is_nothrow_copy_constructible<json::type_error>::value == std::is_nothrow_copy_constructible<std::runtime_error>::value);
        CHECK(std::is_nothrow_copy_constructible<json::out_of_range>::value == std::is_nothrow_copy_constructible<std::runtime_error>::value);
        CHECK(std::is_nothrow_copy_constructible<json::other_error>::value == std::is_nothrow_copy_constructible<std::runtime_error>::value);
    }
}

DOCTEST_GCC_SUPPRESS_WARNING_POP
