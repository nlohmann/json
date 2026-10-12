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
// for #4804
/////////////////////////////////////////////////////////////////////
using json_4804 = nlohmann::json::with_binary_t<std::vector<std::byte>>;

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

    SECTION("issue #4804: from_cbor incompatible with std::vector<std::byte> as binary_t")
    {
        const std::vector<std::uint8_t> data = {0x80};
        const auto decoded = json_4804::from_cbor(data);
        CHECK((decoded == json_4804::array()));
    }

#ifndef SKIP_TESTS_FOR_ENUM_SERIALIZATION
    SECTION("discussion #4209 - custom BinaryType direct assignment and round-tripping")
    {
        // Test that assigning a custom BinaryType directly creates a binary value, not an array
        const std::vector<std::byte> original{std::byte{1}, std::byte{2}, std::byte{3}};
        const json_4804 j = original;
        CHECK(j.is_binary());
        CHECK(!j.is_array());

        // Test round-tripping: extracting the binary value back as the custom container type
        const auto extracted = j.get<std::vector<std::byte>>();
        CHECK(extracted == original);

        // Test that the default json alias behavior is unchanged: std::vector<uint8_t> -> array
        const json default_json = std::vector<std::uint8_t> {1, 2, 3};
        CHECK(default_json.is_array());
        CHECK(!default_json.is_binary());
    }

    SECTION("discussion #4209 - custom BinaryType extraction from parsed array")
    {
        // Test that extracting a custom BinaryType from a parsed JSON array still works
        // (not just from a binary-typed node)
        const auto j = json_4804::parse("[1,2,3]");
        CHECK(j.is_array());
        CHECK(!j.is_binary());

        // Extracting as custom BinaryType should work from arrays
        const auto extracted = j.get<std::vector<std::byte>>();
        CHECK(extracted.size() == 3);
        CHECK(extracted[0] == std::byte{1});
        CHECK(extracted[1] == std::byte{2});
        CHECK(extracted[2] == std::byte{3});
    }
#endif

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
