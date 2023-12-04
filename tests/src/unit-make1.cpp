// test_json_suite_extended.cpp
#include "doctest_compatibility.h"
#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_SUITE("nlohmann/json test suite - Extended")
{
    TEST_CASE("Nested Structures")
    {
        SECTION("Nested Objects")
        {
            json nested_object = {
                {"person", {
                    {"name", "Bob"},
                    {"age", 40},
                    {"address", {
                        {"city", "Example City"},
                        {"zip", "12345"}
                    }}
                }}
            };

            CHECK(nested_object["person"]["name"] == "Bob");
            CHECK(nested_object["person"]["address"]["city"] == "Example City");
        }

        SECTION("Nested Arrays")
        {
            json nested_array = {
                {"numbers", {1, 2, {3, 4}, 5}}
            };

            CHECK(nested_array["numbers"][2][1] == 4);
        }
    }

    TEST_CASE("Exception Handling")
    {
        SECTION("Parsing Invalid JSON")
        {
            // Expecting a parse error for invalid JSON
            CHECK_THROWS_AS(json::parse("invalid_json_string"), json::parse_error);
        }

        SECTION("Accessing Nonexistent Key")
        {
            json object = {{"name", "Alice"}, {"age", 25}};

            // Expecting an exception when accessing a nonexistent key
            CHECK_THROWS_AS(object.at("nonexistent_key"), json::out_of_range);
        }
    }

    TEST_CASE("Additional Serialization and Deserialization")
    {
        SECTION("Serialize and Deserialize with Custom Format")
        {
            json data = {{"key1", 42}, {"key2", "value"}};

            // Serialize with indentation for human-readable format
            std::string serialized = data.dump(2);

            // Deserialize the serialized string
            json parsed = json::parse(serialized);

            CHECK(parsed == data);
        }

        SECTION("Deserialize from Stream")
        {
            std::istringstream stream(R"({"name": "Charlie", "age": 35})");

            // Deserialize from the input stream
            json parsed;
            stream >> parsed;

            CHECK(parsed["name"] == "Charlie");
            CHECK(parsed["age"] == 35);
        }
    }

    // Add more test cases and sections as needed to cover other functionalities.
}