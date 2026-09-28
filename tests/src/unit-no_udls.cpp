//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This translation unit checks JSON_NO_UDLS, which leaves out the user-defined
// string literals operator""_json and operator""_json_pointer entirely (see
// #5294), while the rest of the library keeps working.
#define JSON_NO_UDLS 1

#include "doctest_compatibility.h"

#include <cstddef>
#include <utility>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

// An argument type whose associated namespace is the library namespace, so
// argument-dependent lookup of a literal operator called by its function name
// also searches the inline namespaces nlohmann::literals::json_literals.
NLOHMANN_JSON_NAMESPACE_BEGIN
struct no_udls_probe
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
template<typename T>
using json_udl_t = decltype(operator""_json(std::declval<T>(), std::size_t()));

template<typename T>
using json_pointer_udl_t = decltype(operator""_json_pointer(std::declval<T>(), std::size_t()));

template<typename T>
using has_json_udl = nlohmann::detail::is_detected<json_udl_t, T>;

template<typename T>
using has_json_pointer_udl = nlohmann::detail::is_detected<json_pointer_udl_t, T>;
} // namespace

TEST_CASE("JSON_NO_UDLS")
{
    SECTION("literals are not declared")
    {
        // global namespace (JSON_USE_GLOBAL_UDLS defaults to 1)
        CHECK_FALSE(has_json_udl<const char*>::value);
        CHECK_FALSE(has_json_pointer_udl<const char*>::value);

        // nlohmann::literals::json_literals
        CHECK_FALSE(has_json_udl<nlohmann::no_udls_probe>::value);
        CHECK_FALSE(has_json_pointer_udl<nlohmann::no_udls_probe>::value);
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
