//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This translation unit checks JSON_NO_AUTOMATIC_UDLS, which keeps
// <nlohmann/json.hpp> from including <nlohmann/json_literals.hpp> and thereby
// leaves out the user-defined string literals operator""_json and
// operator""_json_pointer (see #5294), and that including
// <nlohmann/json_literals.hpp> afterwards brings them back.
#define JSON_NO_AUTOMATIC_UDLS 1

#include "doctest_compatibility.h"

#include <cstddef>
#include <utility>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

// An argument type whose associated namespace is the library namespace, so
// argument-dependent lookup of a literal operator called by its function name
// also searches the inline namespaces nlohmann::literals::json_literals.
NLOHMANN_JSON_NAMESPACE_BEGIN
struct no_automatic_udls_probe
{
    operator const char* () const // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)
    {
        return "";
    }
};
NLOHMANN_JSON_NAMESPACE_END

namespace
{
// The calls below use a dependent argument, so a literal operator that is not
// declared at all is a substitution failure rather than a hard error: lookup is
// deferred to the point of instantiation, where it considers the declarations
// visible from here (the global using-declarations of JSON_USE_GLOBAL_UDLS) plus
// argument-dependent lookup (the literals in the library namespace).
#if !defined(__GNUC__) || defined(__clang__) || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
    template<typename T>
    using json_udl_t = decltype(operator""_json(std::declval<T>(), std::size_t()));

    template<typename T>
    using json_pointer_udl_t = decltype(operator""_json_pointer(std::declval<T>(), std::size_t()));
#else
    // GCC 4.8 requires a space between "" and suffix
    template<typename T>
    using json_udl_t = decltype(operator"" _json(std::declval<T>(), std::size_t()));

    template<typename T>
    using json_pointer_udl_t = decltype(operator"" _json_pointer(std::declval<T>(), std::size_t()));
#endif

template<typename T>
using has_json_udl = nlohmann::detail::is_detected<json_udl_t, T>;

template<typename T>
using has_json_pointer_udl = nlohmann::detail::is_detected<json_pointer_udl_t, T>;
} // namespace

TEST_CASE("JSON_NO_AUTOMATIC_UDLS")
{
    SECTION("literals are not declared")
    {
        // global namespace (JSON_USE_GLOBAL_UDLS defaults to 1)
        CHECK_FALSE(has_json_udl<const char*>::value);
        CHECK_FALSE(has_json_pointer_udl<const char*>::value);

        // nlohmann::literals::json_literals
        CHECK_FALSE(has_json_udl<nlohmann::no_automatic_udls_probe>::value);
        CHECK_FALSE(has_json_pointer_udl<nlohmann::no_automatic_udls_probe>::value);
    }

    SECTION("the rest of the library keeps working")
    {
        const json j = json::parse(R"({"foo": {"bar": 42}})");
        CHECK(j.dump() == R"({"foo":{"bar":42}})");

        const json::json_pointer ptr("/foo/bar");
        CHECK(j.at(ptr) == 42);
        CHECK(j.contains(ptr));
    }
}

// the literals can still be added where they are needed
#include <nlohmann/json_literals.hpp>

TEST_CASE("JSON_NO_AUTOMATIC_UDLS with <nlohmann/json_literals.hpp>")
{
#if !defined(JSON_USE_GLOBAL_UDLS) || JSON_USE_GLOBAL_UDLS
    SECTION("global namespace")
    {
        CHECK("[1,2]"_json == json({1, 2}));
        CHECK("/a/0"_json_pointer == json::json_pointer("/a/0"));
    }
#endif

    SECTION("nlohmann::literals::json_literals")
    {
        using namespace nlohmann::literals::json_literals; // NOLINT(google-build-using-namespace)
        CHECK(R"({"a":[42]})"_json.at("/a/0"_json_pointer) == 42);
    }
}
