//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("other constructors and destructor")
{
    SECTION("copy constructor")
    {
        SECTION("object")
        {
            const json j {{"foo", 1}, {"bar", false}};
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("array")
        {
            const json j {"foo", 1, 42.23, false};
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("null")
        {
            const json j(nullptr);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            const json j(true);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("string")
        {
            const json j("Hello world");
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            const json j(42);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("number (unsigned)")
        {
            const  json j(42u);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            const json j(42.23);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("binary")
        {
            const json j = json::binary({1, 2, 3});
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }
    }

    SECTION("move constructor")
    {
        json j {{"foo", "bar"}, {"baz", {1, 2, 3, 4}}, {"a", 42u}, {"b", 42.23}, {"c", nullptr}};
        CHECK(j.type() == json::value_t::object);
        const json k(std::move(j));
        CHECK(k.type() == json::value_t::object);
        CHECK(j.type() == json::value_t::null); // NOLINT: access after move is OK here
    }

    SECTION("copy assignment")
    {
        SECTION("object")
        {
            const json j {{"foo", 1}, {"bar", false}};
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("array")
        {
            const json j {"foo", 1, 42.23, false};
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("null")
        {
            const json j(nullptr);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            const json j(true);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("string")
        {
            const json j("Hello world");
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            const json j(42);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (unsigned)")
        {
            const json j(42u);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            const json j(42.23);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("binary")
        {
            const json j = json::binary({1, 2, 3});
            json k;
            k = j;
            CHECK(j == k);
        }
    }

    SECTION("destructor")
    {
        SECTION("object")
        {
            auto* j = new json {{"foo", 1}, {"bar", false}}; // NOLINT(cppcoreguidelines-owning-memory)
            delete j; // NOLINT(cppcoreguidelines-owning-memory)
        }

        SECTION("array")
        {
            auto* j = new json {"foo", 1, 1u, false, 23.42}; // NOLINT(cppcoreguidelines-owning-memory)
            delete j; // NOLINT(cppcoreguidelines-owning-memory)
        }

        SECTION("string")
        {
            auto* j = new json("Hello world"); // NOLINT(cppcoreguidelines-owning-memory)
            delete j; // NOLINT(cppcoreguidelines-owning-memory)
        }
    }
}
