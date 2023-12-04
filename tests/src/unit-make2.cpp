//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2023 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"
#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_SUITE("nlohmann/json test suite")
{
    TEST_CASE("Basic JSON Operations")
    {
        SECTION("Construction and Type Checks")
        {
            json number = 42;
            json text = "Hello, JSON!";
            json array = {1, 2, 3};
            json object = {{"key", "value"}};

            CHECK(number.is_number());
            CHECK(text.is_string());
            CHECK(array.is_array());
            CHECK(object.is_object());
        }

        SECTION("Serialization and Deserialization")
        {
            json original = {{"name", "John"}, {"age", 30}};
            std::string serialized = original.dump();
            json parsed = json::parse(serialized);

            CHECK(parsed == original);
        }

        SECTION("Array and Object Operations")
        {
            json array = {1, 2, 3};
            array.push_back(4);
            array.insert(array.begin() + 1, 10);

            CHECK(array.size() == 5);
            CHECK(array[1] == 10);

            json object = {{"name", "Alice"}, {"age", 25}};
            object["city"] = "Wonderland";

            CHECK(object["city"] == "Wonderland");
        }
    }

    // Add more test cases and sections as needed to cover other functionalities.
}