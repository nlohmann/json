//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// skip tests if JSON_DisableEnumSerialization=ON (#4384)
#if defined(JSON_DISABLE_ENUM_SERIALIZATION) && (JSON_DISABLE_ENUM_SERIALIZATION == 1)
    #define SKIP_TESTS_FOR_ENUM_SERIALIZATION
#endif

// This file tests the opt-in JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS, so it defines
// the macro itself rather than relying on a -D flag, and runs in every build.
// The default behavior is tested in unit-enum_keyed_maps_default.cpp.
#ifdef JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS
    #undef JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS
#endif

#define JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS 1

#include <nlohmann/json.hpp>
using nlohmann::json;
using nlohmann::ordered_json;

#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#define STRINGIZE_EX(x) #x
#define STRINGIZE(x) STRINGIZE_EX(x)

// NLOHMANN_JSON_SERIALIZE_ENUM uses a static std::pair
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

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

// the example from #4378
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

enum class color {red, green, blue}; // blue is not mapped and falls back to "red"

// NOLINTNEXTLINE(misc-const-correctness,misc-use-internal-linkage,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM(color,
{
    {color::red, "red"},
    {color::green, "green"},
})

enum class strict_color {red, green, blue}; // blue is not mapped

// NOLINTNEXTLINE(misc-const-correctness,misc-use-internal-linkage,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(strict_color,
{
    {strict_color::red, "red"},
    {strict_color::green, "green"},
})

enum class digit {zero, one};

// NOLINTNEXTLINE(misc-const-correctness,misc-use-internal-linkage,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM(digit,
{
    {digit::zero, 0},
    {digit::one, 1},
})

#ifndef SKIP_TESTS_FOR_ENUM_SERIALIZATION
enum class plain {zero, one}; // serialized as integer
#endif

TEST_CASE("JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS")
{
    SECTION("the macro is part of the ABI tag")
    {
        const std::string ns = STRINGIZE(NLOHMANN_JSON_NAMESPACE);
        CHECK(ns.find("_ekmo") != std::string::npos);
    }

    SECTION("std::map (#4378)")
    {
        using task_map = std::map<TaskState, std::string>;
        const task_map m = {{TS_STOPPED, "aa"}, {TS_COMPLETED, "bb"}};
        const json j = m;
        CHECK(j == json::parse(R"({"stopped":"aa","completed":"bb"})"));
        CHECK(j.get<task_map>() == m);

        json j2;
        j2["x"] = m;
        CHECK(j2.dump() == R"({"x":{"completed":"bb","stopped":"aa"}})");
    }

    SECTION("std::map with custom comparator")
    {
        using task_map = std::map<TaskState, int, std::greater<TaskState>>;
        const task_map m = {{TS_STOPPED, 1}, {TS_RUNNING, 2}};
        const json j = m;
        CHECK(j == json::parse(R"({"stopped":1,"running":2})"));
        CHECK(j.get<task_map>() == m);
    }

    SECTION("std::unordered_map")
    {
        using task_map = std::unordered_map<TaskState, int, enum_hash>;
        const task_map m = {{TS_STOPPED, 1}, {TS_RUNNING, 2}};
        const json j = m;
        CHECK(j == json::parse(R"({"stopped":1,"running":2})"));
        CHECK(j.get<task_map>() == m);
    }

    SECTION("nested maps")
    {
        using nested_map = std::map<color, std::map<TaskState, int>>;
        const nested_map m = {{color::green, {{TS_RUNNING, 1}}}, {color::red, {}}};
        const json j = m;
        CHECK(j == json::parse(R"({"green":{"running":1},"red":{}})"));
        CHECK(j.get<nested_map>() == m);
    }

    SECTION("ordered_json keeps the order of the map")
    {
        using task_map = std::map<TaskState, int>;
        const task_map m = {{TS_STOPPED, 1}, {TS_RUNNING, 2}, {TS_COMPLETED, 3}};
        const ordered_json j = m;
        CHECK(j.dump() == R"({"stopped":1,"running":2,"completed":3})");
        CHECK(j.get<task_map>() == m);
    }

    SECTION("empty map")
    {
        const json j = std::map<TaskState, int>();
        CHECK(j.is_object());
        CHECK(j.empty());
    }

    SECTION("NLOHMANN_JSON_SERIALIZE_ENUM_STRICT")
    {
        using color_map = std::map<strict_color, int>;
        const color_map m = {{strict_color::red, 1}, {strict_color::green, 2}};
        const json j = m;
        CHECK(j == json::parse(R"({"red":1,"green":2})"));
        CHECK(j.get<color_map>() == m);

        const color_map unmapped = {{strict_color::blue, 1}};
        json _;
        CHECK_THROWS_WITH_AS(_ = unmapped,
                             "[json.exception.out_of_range.410] enum value out of range for strict_color", json::out_of_range&);
    }

    SECTION("arrays of [key, value] pairs are still read")
    {
        using task_map = std::map<TaskState, int>;
        const task_map m = {{TS_STOPPED, 1}};
        CHECK(json::parse(R"([["stopped",1]])").get<task_map>() == m);
    }

    SECTION("other containers are not affected")
    {
        const std::vector<std::pair<TaskState, int>> pairs = {{TS_STOPPED, 1}};
        const std::map<std::string, TaskState> string_keys = {{"a", TS_STOPPED}};
        const std::map<int, int> int_keys = {{1, 2}};
        CHECK(json(pairs) == json::parse(R"([["stopped",1]])"));
        CHECK(json(string_keys) == json::parse(R"({"a":"stopped"})"));
        CHECK(json(int_keys) == json::parse("[[1,2]]"));
    }

    SECTION("maps with non-unique keys are still stored as arrays of pairs")
    {
        const std::multimap<TaskState, int> mm = {{TS_STOPPED, 1}, {TS_STOPPED, 2}};
        const std::unordered_multimap<TaskState, int, enum_hash> umm = {{TS_RUNNING, 3}, {TS_RUNNING, 3}};
        CHECK(json(mm) == json::parse(R"([["stopped",1],["stopped",2]])"));
        CHECK(json(umm) == json::parse(R"([["running",3],["running",3]])"));
    }

    SECTION("keys that do not serialize to strings")
    {
        const std::map<TaskState, int> null_key = {{TS_INVALID, 1}};
        const std::map<digit, int> number_key = {{digit::zero, 1}};
        json j = "unchanged";

        // mapped to null
        CHECK_THROWS_WITH_AS(j = null_key,
                             "[json.exception.type_error.302] type must be string, but is null", json::type_error&);

        // mapped to a number
        CHECK_THROWS_WITH_AS(j = number_key,
                             "[json.exception.type_error.302] type must be string, but is number", json::type_error&);

#ifndef SKIP_TESTS_FOR_ENUM_SERIALIZATION
        // enum without NLOHMANN_JSON_SERIALIZE_ENUM
        const std::map<plain, int> plain_key = {{plain::zero, 1}};
        CHECK_THROWS_WITH_AS(j = plain_key,
                             "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
#endif

        CHECK(j == "unchanged");
    }

    SECTION("keys that serialize to the same string")
    {
        const std::map<color, int> m = {{color::red, 1}, {color::blue, 2}};
        json j = "unchanged";

        // color::blue is not mapped and falls back to "red"
        CHECK_THROWS_WITH_AS(j = m,
                             "[json.exception.type_error.318] duplicate object key 'red'", json::type_error&);

        CHECK(j == "unchanged");
    }
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
