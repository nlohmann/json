//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-regression3.cpp (std::any, std::optional,
// std::variant and std::filesystem regression tests). It is kept in a separate translation
// unit so the (much larger) unit-regression3.cpp is built for C++11 only and not rebuilt
// for every C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#ifdef JSON_HAS_CPP_17
#include <cstdint>
#include <string>
#include <typeinfo>
#include <vector>

#include <any>
#include <variant>

#if __has_include(<optional>)
    #include <optional>
#elif __has_include(<experimental/optional>)
#endif

/////////////////////////////////////////////////////////////////////
// for #4740
/////////////////////////////////////////////////////////////////////

struct Example_4740
{
    std::optional<std::string> host = std::nullopt;
    std::optional<int> port = std::nullopt;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Example_4740, host, port)
};

TEST_CASE("regression tests 3 (C++17)")
{
#if JSON_HAS_FILESYSTEM || JSON_HAS_EXPERIMENTAL_FILESYSTEM
    SECTION("issue #3070 - Version 3.10.3 breaks backward-compatibility with 3.10.2 ")
    {
        nlohmann::detail::std_fs::path text_path("/tmp/text.txt");
        const json j(text_path);

        const auto j_path = j.get<nlohmann::detail::std_fs::path>();
        CHECK(j_path == text_path);

#if DOCTEST_CLANG || DOCTEST_GCC >= DOCTEST_COMPILER(8, 4, 0)
        // only known to work on Clang and GCC >=8.4
        CHECK_THROWS_WITH_AS(nlohmann::detail::std_fs::path(json(1)), "[json.exception.type_error.302] type must be string, but is number", json::type_error);
#endif
    }
#endif

#if JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("issue #3428 - Error occurred when converting nlohmann::json to std::any")
    {
        const json j;
        const std::any a1 = j;
        std::any&& a2 = j;

        CHECK(a1.type() == typeid(j));
        CHECK(a2.type() == typeid(j));
    }
#endif

    SECTION("issue #4740 - build issue with std::optional")
    {
        const auto t1 = Example_4740();
        const auto j1 = nlohmann::json(t1);
        CHECK(j1.dump() == "{\"host\":null,\"port\":null}");
        const auto t2 = j1.get<Example_4740>();
        CHECK(!t2.host.has_value());
        CHECK(!t2.port.has_value());

        // improve coverage
        auto t3 = Example_4740();
        t3.port = 80;
        t3.host = "example.com";
        const auto j2 = nlohmann::json(t3);
        CHECK(j2.dump() == "{\"host\":\"example.com\",\"port\":80}");
        const auto t4 = j2.get<Example_4740>();
        CHECK(t4.host.has_value());
        CHECK(t4.port.has_value());
    }

    SECTION("issue #5046 - implicit conversion of return json to std::optional no longer implicit")
    {
        const json jval{};
        auto GetValue = [](const json & valRoot) -> std::optional<json>
        {
            if (valRoot.contains("default"))
            {
                return valRoot.at("default");
            }
            return std::nullopt;
        };
        auto result = GetValue(jval);
        CHECK(!result.has_value());
    }

}

#endif
