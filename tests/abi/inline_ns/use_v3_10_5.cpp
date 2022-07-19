#include "doctest_compatibility.h"

#include <nlohmann/json_v3_10_5.hpp>
using nlohmann::json;
using nlohmann::ordered_json;

TEST_CASE("use library v3.10.5 without inline namespace")
{
    json j;
    j[ordered_json::json_pointer("/root")] = json::object();
    // In v3.10.5 mixing json_pointers of different basic_json types
    // results in implicit string conversion
    CHECK(j.dump() == "{\"/root\":{}}");
}
