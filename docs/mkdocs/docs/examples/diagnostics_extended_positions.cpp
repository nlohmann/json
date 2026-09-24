#include <iostream>

#define JSON_DIAGNOSTICS 1
#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/* Demonstration of type error exception with diagnostic positions support enabled */
int main()
{
    //Invalid json string - housenumber type must be int instead of string
    const std::string json_invalid_string = R"(
    {
        "address": {
            "street": "Fake Street",
            "housenumber": "1"
        }
    }
    )";
    json j = json::parse(json_invalid_string);
    try
    {
        int housenumber = j["address"]["housenumber"];
        std::cout << housenumber;
    }
    catch (const json::exception& e)
    {
        std::cout << e.what() << '\n';
    }
}
