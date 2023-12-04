// test_json_suite_more.cpp
#include "doctest_compatibility.h"
#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_SUITE("nlohmann/json test suite - More")
{
    TEST_CASE("Comparing JSON Objects")
    {
        SECTION("Ordering of Object Keys Matters")
        {
            json object1 = {
                {"name", "Alice"},
                {"age", 25},
                {"city", "Wonderland"}
            };

            json object2 = {
                {"name", "Alice"},
                {"city", "Wonderland"},
                {"age", 25}
            };

            // Expecting the objects to be different due to key order
            CHECK(object1 != object2);
        }

        SECTION("Ordering of Object Keys Doesn't Matter")
        {
            json object1 = {
                {"name", "Bob"},
                {"age", 30},
                {"city", "Example City"}
            };

            json object2 = {
                {"age", 30},
                {"name", "Bob"},
                {"city", "Example City"}
            };

            // Expecting the objects to be considered equal
            CHECK(object1 == object2);
        }
    }

    // Add more test cases and sections as needed to cover other functionalities.
}