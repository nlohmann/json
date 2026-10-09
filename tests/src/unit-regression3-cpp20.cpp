//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++20-only part of unit-regression3.cpp (C++20 regression tests
// (operator<=> related aggregates, ranges)). It is kept in a separate translation unit so
// the (much larger) unit-regression3.cpp is built for C++11 only and not rebuilt for every
// C++ standard.

#include "doctest_compatibility.h"

// skip tests if JSON_DisableEnumSerialization=ON (#4384): std::byte is a
// scoped enum, so get<std::byte>() (needed below to get<std::vector<std::byte>>()
// from a plain JSON array, not just from an already-binary value) relies on
// enum serialization being enabled
#if defined(JSON_DISABLE_ENUM_SERIALIZATION) && (JSON_DISABLE_ENUM_SERIALIZATION == 1)
    #define SKIP_TESTS_FOR_ENUM_SERIALIZATION
#endif

#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#ifdef JSON_HAS_CPP_20
#include <string>

#if __has_include(<span>)
    #include <span>
#endif

/////////////////////////////////////////////////////////////////////
// for #4440
/////////////////////////////////////////////////////////////////////
#if JSON_HAS_RANGES == 1
    #include <ranges>
#endif

/////////////////////////////////////////////////////////////////////
// for #3312
/////////////////////////////////////////////////////////////////////

struct for_3312
{
    std::string name;
};

inline void from_json(const json& j, for_3312& obj) // NOLINT(misc-use-internal-linkage)
{
    j.at("name").get_to(obj.name);
}

TEST_CASE("regression tests 3 (C++20)")
{
    SECTION("issue #3312 - Parse to custom class from unordered_json breaks on G++11.2.0 with C++20")
    {
        // see test for #3171
        const ordered_json j = {{"name", "class"}};
        for_3312 obj{};

        j.get_to(obj);

        CHECK(obj.name == "class");
    }

#if JSON_HAS_RANGES == 1
    SECTION("issue #4440 - assert when using std::views::filter and GCC 10")
    {
        auto noOpFilter = std::views::filter([](auto&&) noexcept
        {
            return true;
        });
        json j = {1, 2, 3};
        auto filtered = j | noOpFilter;
        CHECK(*filtered.begin() == 1);
    }
#endif

#if JSON_HAS_RANGE_VIEW_CONVERSION
    SECTION("issue #4916 - constructing array from C++20 ranges view does not work")
    {
        std::vector<int> nums{1, 2, 37, 42, 21};
        auto filteredNums = nums | std::views::filter([](int i)
        {
            return i > 10;
        });
        json const j(filteredNums);
        CHECK(j.type() == json::value_t::array);
        CHECK(j == json({37, 42, 21}));
    }
#endif

    // owning_view is not available in libstdc++ < 12
#if JSON_HAS_RANGE_VIEW_CONVERSION && !(defined(__GLIBCXX__) && _GLIBCXX_RELEASE < 12)
    SECTION("issue #4916 - constructing array from prvalue C++20 ranges view (owning_view)")
    {
        json const j(std::vector<int> {1, 2, 37, 42, 21} | std::views::filter([](int i)
        {
            return i > 10;
        }));
        CHECK(j.type() == json::value_t::array);
        CHECK(j == json({37, 42, 21}));
    }
#endif

#if JSON_HAS_RANGE_VIEW_CONVERSION
    SECTION("issue #4916 - constructing array from C++20 transform view (prvalue elements)")
    {
        std::vector<int> nums{1, 2, 3};
        auto t = nums | std::views::transform([](int i) noexcept
        {
            return i * 2;
        });
        json const j(t);
        CHECK(j.type() == json::value_t::array);
        CHECK(j == json({2, 4, 6}));
    }
#endif
}

#endif
