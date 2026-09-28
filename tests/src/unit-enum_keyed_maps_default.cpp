//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// This file tests maps with enum keys with the default setting of
// JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS (or whatever a -D flag sets it to).
// unit-enum_keyed_maps.cpp tests JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS=1.
// These tests are not part of unit-conversions.cpp, because that object file
// is already too big for the MinGW linker of some compilers.

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>

// NLOHMANN_JSON_SERIALIZE_ENUM uses a static std::pair
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

enum class cards {kreuz, pik, herz, karo};

// NOLINTNEXTLINE(misc-use-internal-linkage,misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM(cards,
{
    {cards::kreuz, "kreuz"},
    {cards::pik, "pik"},
    {cards::herz, "herz"},
    {cards::karo, "karo"}
})

enum TaskState // NOLINT(cert-int09-c,readability-enum-initial-value,cppcoreguidelines-use-enum-class)
{
    TS_STOPPED,
    TS_RUNNING,
    TS_COMPLETED,
    TS_INVALID = -1,
};

// NOLINTNEXTLINE(misc-const-correctness,misc-use-internal-linkage,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM(TaskState,
{
    {TS_INVALID, nullptr},
    {TS_STOPPED, "stopped"},
    {TS_RUNNING, "running"},
    {TS_COMPLETED, "completed"},
})

enum class strict_cards {kreuz, pik, herz, karo, andere}; // andere not included in mapping

// NOLINTNEXTLINE(misc-use-internal-linkage,misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(strict_cards,
{
    {strict_cards::kreuz, "kreuz"},
    {strict_cards::pik, "pik"},
    {strict_cards::herz, "herz"},
    {strict_cards::karo, "karo"}
})

namespace
{
// std::hash is only required for enums since C++14
struct enum_hash
{
    template<typename T>
    std::size_t operator()(T t) const noexcept
    {
        return static_cast<std::size_t>(t);
    }
};
} // namespace

// see unit-enum_keyed_maps.cpp for JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS=1
TEST_CASE("maps with enum keys")
{
    using task_map = std::map<TaskState, std::string>;
    using task_umap = std::unordered_map<TaskState, std::string, enum_hash>;
    using task_gmap = std::map<TaskState, std::string, std::greater<TaskState>>;
    using nested_map = std::map<cards, std::map<TaskState, int>>;
    using strict_map = std::map<strict_cards, int>;
    using int_map = std::map<int, int>;
    using int_umap = std::unordered_map<int, int>;

    const task_map m = {{TS_STOPPED, "aa"}, {TS_COMPLETED, "bb"}};

#if !JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS
    SECTION("stored as array of pairs")
    {
        CHECK(json(m) == json::parse(R"([["stopped","aa"],["completed","bb"]])"));
        CHECK(json(task_umap {{TS_RUNNING, "cc"}}) == json::parse(R"([["running","cc"]])"));
    }
#endif

    SECTION("read from array of pairs")
    {
        CHECK(json::parse(R"([["stopped","aa"],["completed","bb"]])").get<task_map>() == m);
    }

    SECTION("read from object (#4378)")
    {
        const json j = json::parse(R"({"stopped":"aa","completed":"bb"})");
        CHECK(j.get<task_map>() == m);
        CHECK(j.get<task_umap>() == task_umap(m.begin(), m.end()));
        CHECK(j.get<task_gmap>() == task_gmap(m.begin(), m.end()));
        CHECK(json::parse(R"({"kreuz":{"stopped":1}})").get<nested_map>() == nested_map {{cards::kreuz, {{TS_STOPPED, 1}}}});
        CHECK(nlohmann::ordered_json::parse(R"({"stopped":"aa","completed":"bb"})").get<task_map>() == m);

        // object keys go through the enum's from_json
        strict_map sm;
        CHECK_THROWS_WITH_AS(json::parse(R"({"what?":1})").get_to(sm),
                             "[json.exception.out_of_range.410] enum value out of range for strict_cards: \"what?\"", json::out_of_range&);
    }

    SECTION("objects are only read for enum keys")
    {
        // built rather than parsed, so that the messages do not gain a byte
        // range with JSON_DIAGNOSTIC_POSITIONS
        const json j = {{"1", 2}};
        int_map im;
        int_umap ium;
        CHECK_THROWS_WITH_AS(j.get_to(im),
                             "[json.exception.type_error.302] type must be array, but is object", json::type_error&);
        CHECK_THROWS_WITH_AS(j.get_to(ium),
                             "[json.exception.type_error.302] type must be array, but is object", json::type_error&);
    }

    SECTION("other types are rejected")
    {
        task_map tm;
        CHECK_THROWS_WITH_AS(json("stopped").get_to(tm),
                             "[json.exception.type_error.302] type must be array, but is string", json::type_error&);
    }
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
