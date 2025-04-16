//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

TEST_CASE("user-defined string literals")
{
    auto j_expected = nlohmann::json::parse(R"({"foo": "bar", "baz": 42})");
    auto ptr_expected = nlohmann::json::json_pointer("/foo/bar");

    SECTION("using namespace nlohmann::literals::json_literals")
    {
        using namespace nlohmann::literals::json_literals; // NOLINT(google-build-using-namespace)

        CHECK(R"({"foo": "bar", "baz": 42})"_json == j_expected);
        CHECK("/foo/bar"_json_pointer == ptr_expected);
    }

    SECTION("using namespace nlohmann::json_literals")
    {
        using namespace nlohmann::json_literals; // NOLINT(google-build-using-namespace)

        CHECK(R"({"foo": "bar", "baz": 42})"_json == j_expected);
        CHECK("/foo/bar"_json_pointer == ptr_expected);
    }

    SECTION("using namespace nlohmann::literals")
    {
        using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)

        CHECK(R"({"foo": "bar", "baz": 42})"_json == j_expected);
        CHECK("/foo/bar"_json_pointer == ptr_expected);
    }

    SECTION("using namespace nlohmann")
    {
        using namespace nlohmann; // NOLINT(google-build-using-namespace)

        CHECK(R"({"foo": "bar", "baz": 42})"_json == j_expected);
        CHECK("/foo/bar"_json_pointer == ptr_expected);
    }

#ifndef JSON_TEST_NO_GLOBAL_UDLS
    SECTION("global namespace")
    {
        CHECK(R"({"foo": "bar", "baz": 42})"_json == j_expected);
        CHECK("/foo/bar"_json_pointer == ptr_expected);
    }
#endif
}
